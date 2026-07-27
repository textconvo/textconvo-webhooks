<?php

declare(strict_types=1);

/**
 * TextConvo webhook signature verification — PHP
 *
 * Docs: https://textconvo.ai/docs#webhooks
 * Requires: PHP 8.1+ with the hash extension
 *
 * Signature:     X-TextConvo-Signature: sha256=<hex>
 * Signed string: timestamp . "." . rawBody
 *
 * Read the raw body with file_get_contents('php://input') — never rebuild it
 * from a parsed array, or the signature will not match.
 */

// Reject anything older than this even when the signature is valid.
const TEXTCONVO_TOLERANCE_SECONDS = 300;

/**
 * @return array{valid: bool, reason?: string}
 */
function textconvo_verify_webhook(
    string $rawBody,
    ?string $signatureHeader,
    ?string $timestampHeader,
    ?string $secret,
    int $toleranceSeconds = TEXTCONVO_TOLERANCE_SECONDS
): array {
    if ($secret === null || $secret === '') {
        return ['valid' => false, 'reason' => 'no_secret_configured'];
    }
    if ($signatureHeader === null || $signatureHeader === '') {
        return ['valid' => false, 'reason' => 'missing_signature_header'];
    }
    if ($timestampHeader === null || $timestampHeader === '') {
        return ['valid' => false, 'reason' => 'missing_timestamp_header'];
    }

    // 1. Replay protection first: cheap, and it fails fast.
    if (!ctype_digit($timestampHeader)) {
        return ['valid' => false, 'reason' => 'malformed_timestamp'];
    }

    if (abs(time() - (int) $timestampHeader) > $toleranceSeconds) {
        return ['valid' => false, 'reason' => 'timestamp_outside_tolerance'];
    }

    // 2. Recompute over timestamp . "." . rawBody.
    $expected = hash_hmac('sha256', $timestampHeader . '.' . $rawBody, $secret);

    // 3. Strip the sha256= prefix. Hex comparison is case-insensitive.
    $received = strtolower(preg_replace('/^sha256=/', '', $signatureHeader));
    if (preg_match('/^[0-9a-f]{64}$/', $received) !== 1) {
        return ['valid' => false, 'reason' => 'malformed_signature'];
    }

    // 4. Constant-time comparison. Never use === on the hex here.
    if (!hash_equals($expected, $received)) {
        return ['valid' => false, 'reason' => 'signature_mismatch'];
    }

    return ['valid' => true];
}

// --- Receiver sketch -------------------------------------------------------
// Drop this into any front controller. Verify, respond, then queue the work.

if (PHP_SAPI !== 'cli' && ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $rawBody = file_get_contents('php://input') ?: '';

    $result = textconvo_verify_webhook(
        $rawBody,
        $_SERVER['HTTP_X_TEXTCONVO_SIGNATURE'] ?? null,
        $_SERVER['HTTP_X_TEXTCONVO_TIMESTAMP'] ?? null,
        getenv('TEXTCONVO_WEBHOOK_SECRET') ?: null,
    );

    if (!$result['valid']) {
        http_response_code(401);
        error_log('TextConvo webhook rejected: ' . ($result['reason'] ?? 'unknown'));
        echo json_encode(['error' => 'invalid signature']);
        exit;
    }

    $payload = json_decode($rawBody, true) ?: [];

    // Answer fast, work later. Enqueue and return 200 immediately.
    // Unknown events must not error — new ones are added over time.
    error_log('TextConvo event received: ' . ($payload['event'] ?? 'unknown'));

    http_response_code(200);
    echo json_encode(['received' => true]);
    exit;
}

// --- Self-test -------------------------------------------------------------
//   php verify.php

if (PHP_SAPI === 'cli') {
    $secret = getenv('TEXTCONVO_WEBHOOK_SECRET') ?: 'test_secret_do_not_use_in_production';
    $body = json_encode(['event' => 'lead.accepted', 'lead_id' => 'lead_abc123']);
    $now = (string) time();
    $signature = 'sha256=' . hash_hmac('sha256', $now . '.' . $body, $secret);

    $cases = [
        ['valid signature', $body, $signature, $now, $secret],
        ['tampered body', $body . ' ', $signature, $now, $secret],
        ['stale timestamp', $body, $signature, (string) (time() - 4000), $secret],
        ['missing signature', $body, null, $now, $secret],
        ['wrong secret', $body, $signature, $now, 'not_the_secret'],
    ];

    foreach ($cases as [$name, $b, $sig, $ts, $key]) {
        $outcome = textconvo_verify_webhook($b, $sig, $ts, $key);
        printf(
            "%-7s%s%s\n",
            $outcome['valid'] ? 'ACCEPT' : 'REJECT',
            $name,
            isset($outcome['reason']) ? ' (' . $outcome['reason'] . ')' : ''
        );
    }
}
