<h1 align="center">TextConvo Webhooks</h1>

<p align="center"><strong>Payload examples, signature verification, and sample receivers.</strong></p>

<p align="center">
  <a href="https://textconvo.ai">Website</a> &nbsp;&middot;&nbsp;
  <a href="https://textconvo.ai/docs">Developer Docs</a> &nbsp;&middot;&nbsp;
  <a href="https://textconvo.ai/docs#webhooks">Webhook Reference</a> &nbsp;&middot;&nbsp;
  <a href="https://textconvo.ai/contact-us">Support</a>
</p>

<p align="center">
  <a href="https://textconvo.ai/docs#webhooks"><img alt="Docs" src="https://img.shields.io/badge/docs-webhooks-1f6feb?style=flat-square"></a>
  <img alt="Signature" src="https://img.shields.io/badge/signature-HMAC--SHA256-8957e5?style=flat-square">
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-2ea043?style=flat-square"></a>
  <a href="https://github.com/textconvo/textconvo-webhooks/issues"><img alt="Issues" src="https://img.shields.io/github/issues/textconvo/textconvo-webhooks?style=flat-square"></a>
</p>

---

Webhooks are how TextConvo tells you what happened: a lead was accepted, a message was delivered, someone replied, someone opted out, a journey pushed its result to your CRM.

This repository gives you the payload shapes, four verification implementations, and two runnable receivers. No platform code — just what you need on your side of the connection.

> The event catalogue and header reference are maintained at [textconvo.ai/docs#webhooks](https://textconvo.ai/docs#webhooks). This repository shows you what to *do* with them.

## Contents

| Path | What it is |
| --- | --- |
| [payloads/](payloads) | One JSON file per event, exactly as delivered |
| [verification/](verification) | Signature verification in Node.js, Python, PHP, and Go |
| [receivers/](receivers) | Runnable receivers: Express and Flask |
| [docs/RETRIES.md](docs/RETRIES.md) | Retry behaviour, idempotency, and how to build a receiver that survives them |

## The three headers on every delivery

| Header | Purpose |
| --- | --- |
| `X-TextConvo-Signature` | Signature in the form `sha256=<hex>` |
| `X-TextConvo-Timestamp` | Unix timestamp used in the signed string |
| `X-TextConvo-Source-Key` | Which source the webhook belongs to |

Recompute HMAC-SHA256 over `timestamp + "." + rawBody` using your webhook secret, hex-encode it, and compare against the header value with the `sha256=` prefix stripped.

## Five rules for a receiver you will not have to debug at 2am

**1. Verify before you parse.** Read the raw body as bytes, verify the signature against those exact bytes, and only then deserialise. Most frameworks parse and discard the raw body by default — every receiver here shows how to keep it.

**2. Compare in constant time.** Use `crypto.timingSafeEqual`, `hmac.compare_digest`, `hash_equals`, or `hmac.Equal`. A plain string comparison leaks timing information.

**3. Reject stale timestamps.** Anything outside a few minutes should be refused, even with a valid signature. That is what stops a captured request being replayed later.

**4. Answer fast, work later.** Return 2xx as soon as the signature checks out, then process asynchronously. Slow receivers cause retries, and retries cause duplicates.

**5. Deduplicate.** The same event can arrive more than once. Key your processing on the identifiers in the payload and make handlers idempotent. See [docs/RETRIES.md](docs/RETRIES.md).

## Events

| Event | Meaning |
| --- | --- |
| `lead.accepted` | Lead accepted, matched or created as a contact |
| `lead.rejected` | Lead rejected by validation or deduplication |
| `lead.delivered` | Message delivered to the carrier |
| `lead.failed` | Message failed to deliver |
| `lead.reply` | Contact replied |
| `lead.click` | Contact clicked a tracked link |
| `lead.opt_out` | Contact opted out; suppression applies automatically |
| `lead.sent` | Email message sent |
| `lead.crm_updated` | Inbound CRM change reflected into TextConvo |
| `journey.crm_pushed` | Journey outcome pushed to your CRM |
| `scheduled_call.confirmed` | A scheduled call was confirmed |
| `scheduled_call.cancelled` | A scheduled call was cancelled |
| `support.call_me_now` | Contact asked for an immediate callback |
| `support.call_back_later` | Contact asked for a callback later |

Every body includes an `event` field naming the event. Switch on it, and ignore events you do not handle rather than erroring on them — new events can be added at any time.

## Quick start

```bash
# Node.js / Express
cd receivers
npm install express
export TEXTCONVO_WEBHOOK_SECRET=your_webhook_secret
node express-receiver.js

# Python / Flask
pip install flask
export TEXTCONVO_WEBHOOK_SECRET=your_webhook_secret
python flask_receiver.py
```

Expose it with a tunnel, configure the URL in TextConvo, then send yourself a test lead using [textconvo-api-examples](https://github.com/textconvo/textconvo-api-examples).

## Signing a test payload locally

```bash
SECRET=your_webhook_secret
TS=$(date +%s)
BODY=$(tr -d '\n ' < payloads/lead.accepted.json)
SIG=$(printf '%s' "$TS.$BODY" | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.* //')

curl -X POST http://localhost:3000/webhooks/textconvo \
  -H "Content-Type: application/json" \
  -H "X-TextConvo-Timestamp: $TS" \
  -H "X-TextConvo-Signature: sha256=$SIG" \
  -H "X-TextConvo-Source-Key: test-source" \
  -d "$BODY"
```

A receiver that accepts this and rejects the same request with a tampered body is working correctly.

## Related repositories

| Repository | Purpose |
| --- | --- |
| [textconvo-api-examples](https://github.com/textconvo/textconvo-api-examples) | Sending leads in nine languages |
| [textconvo-openapi](https://github.com/textconvo/textconvo-openapi) | Webhook payloads as OpenAPI 3.1 schemas |
| [textconvo-sample-apps](https://github.com/textconvo/textconvo-sample-apps) | Receivers inside complete demo apps |

## See it live

Submit the [contact form](https://textconvo.ai/contact-us) and you get a direct line to **Ria**, the TextConvo AI orchestrator &mdash; call her for a live voice demo, or text her and watch the SMS AI reply in real time. A human follows up within one business day, and the same form is how API credentials, a source key, and a webhook secret are issued.

Handed a TextConvo QR code at an event or in a demo? Scanning it opens the same conversation. The form is simply the path that works for everyone.

## Contributing

A receiver for your framework would be genuinely useful — FastAPI, Rails, Laravel, Spring, ASP.NET, Cloudflare Workers. See [CONTRIBUTING.md](https://github.com/textconvo/.github/blob/main/CONTRIBUTING.md).

## Security

If you find a flaw in a verification example, report it privately — [SECURITY.md](https://github.com/textconvo/.github/blob/main/SECURITY.md). Never paste a real webhook secret in an issue.

## License

[MIT](LICENSE) &copy; TextConvo
