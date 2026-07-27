// TextConvo webhook signature verification and receiver — Go
//
// Docs: https://textconvo.ai/docs#webhooks
// Requires: Go 1.21+ (standard library only)
//
// Signature:     X-TextConvo-Signature: sha256=<hex>
// Signed string: timestamp + "." + rawBody
//
// Run:
//   export TEXTCONVO_WEBHOOK_SECRET=your_webhook_secret
//   go run verify.go

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Reject anything older than this even when the signature is valid.
// This is what makes a captured request useless later.
const toleranceSeconds = 300

// Keep the body small enough that a bad actor cannot exhaust memory.
const maxBodyBytes = 1 << 20 // 1 MiB

var (
	hex64 = regexp.MustCompile("^[0-9a-f]{64}$")

	ErrNoSecret          = errors.New("no secret configured")
	ErrMissingSignature  = errors.New("missing signature header")
	ErrMissingTimestamp  = errors.New("missing timestamp header")
	ErrMalformedTime     = errors.New("malformed timestamp")
	ErrStaleTimestamp    = errors.New("timestamp outside tolerance")
	ErrMalformedSig      = errors.New("malformed signature")
	ErrSignatureMismatch = errors.New("signature mismatch")
)

// VerifyWebhook checks the signature and the timestamp. rawBody must be the
// exact bytes received — never a re-serialised struct.
func VerifyWebhook(rawBody []byte, signatureHeader, timestampHeader, secret string) error {
	if secret == "" {
		return ErrNoSecret
	}
	if signatureHeader == "" {
		return ErrMissingSignature
	}
	if timestampHeader == "" {
		return ErrMissingTimestamp
	}

	// 1. Replay protection first: cheap, and it fails fast.
	timestamp, err := strconv.ParseInt(timestampHeader, 10, 64)
	if err != nil {
		return ErrMalformedTime
	}

	skew := time.Now().Unix() - timestamp
	if skew < 0 {
		skew = -skew
	}
	if skew > toleranceSeconds {
		return ErrStaleTimestamp
	}

	// 2. Recompute over timestamp + "." + rawBody.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestampHeader + "."))
	mac.Write(rawBody)
	expected := mac.Sum(nil)

	// 3. Strip the sha256= prefix. Hex comparison is case-insensitive.
	received := strings.ToLower(strings.TrimPrefix(signatureHeader, "sha256="))
	if !hex64.MatchString(received) {
		return ErrMalformedSig
	}

	receivedBytes, err := hex.DecodeString(received)
	if err != nil {
		return ErrMalformedSig
	}

	// 4. Constant-time comparison. Never use == on the hex here.
	if !hmac.Equal(expected, receivedBytes) {
		return ErrSignatureMismatch
	}

	return nil
}

// --- Receiver --------------------------------------------------------------

type event struct {
	Event     string `json:"event"`
	LeadID    string `json:"lead_id"`
	ContactID string `json:"contact_id"`
	MessageID string `json:"message_id"`
	Phone     string `json:"phone"`
}

func handler(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Read the raw bytes. Verify these, not a parsed struct.
		rawBody, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}

		if err := VerifyWebhook(
			rawBody,
			r.Header.Get("X-TextConvo-Signature"),
			r.Header.Get("X-TextConvo-Timestamp"),
			secret,
		); err != nil {
			log.Printf("rejected webhook: %v", err)
			http.Error(w, "invalid signature", http.StatusUnauthorized)
			return
		}

		var e event
		if err := json.Unmarshal(rawBody, &e); err != nil {
			// Signature was valid, so accept and investigate offline rather than
			// forcing a retry we know will fail the same way.
			log.Printf("valid signature but unparseable body: %v", err)
			w.WriteHeader(http.StatusOK)
			return
		}

		// Answer fast, work later: enqueue, then return 200 immediately.
		// Unknown events must not error — new ones are added over time.
		switch e.Event {
		case "lead.accepted":
			log.Printf("lead accepted: %s (contact %s)", e.LeadID, e.ContactID)
		case "lead.delivered", "lead.failed", "lead.sent":
			log.Printf("message %s: %s", e.Event, e.MessageID)
		case "lead.reply":
			log.Printf("reply from %s", e.ContactID)
		case "lead.opt_out":
			log.Printf("opt-out: %s — suppress locally too", e.ContactID)
		default:
			log.Printf("unhandled event %q — ignoring", e.Event)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{\"received\":true}"))
	}
}

func main() {
	secret := os.Getenv("TEXTCONVO_WEBHOOK_SECRET")
	if secret == "" {
		fmt.Fprintln(os.Stderr, "Set TEXTCONVO_WEBHOOK_SECRET before starting the receiver.")
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/webhooks/textconvo", handler(secret))

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("listening on http://localhost:%s/webhooks/textconvo", port)
	log.Fatal(server.ListenAndServe())
}
