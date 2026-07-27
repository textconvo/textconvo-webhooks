/**
 * TextConvo webhook signature verification — Node.js
 *
 * Docs: https://textconvo.ai/docs#webhooks
 * Requires: Node 18+ (no dependencies)
 *
 * Signature: X-TextConvo-Signature: sha256=<hex>
 * Signed string: timestamp + "." + rawBody
 *
 * The rawBody argument must be the EXACT bytes received. If your framework has
 * already parsed and re-serialised the JSON, the signature will not match — see
 * ../receivers/express-receiver.js for how to keep the raw body.
 */

'use strict';

const crypto = require('node:crypto');

// Reject anything older than this even when the signature is valid.
// This is what makes a captured request useless later.
const DEFAULT_TOLERANCE_SECONDS = 300;

/**
 * Verify a TextConvo webhook.
 *
 * @param {string|Buffer} rawBody   exact request body
 * @param {string} signatureHeader  value of X-TextConvo-Signature
 * @param {string} timestampHeader  value of X-TextConvo-Timestamp
 * @param {string} secret           your webhook secret
 * @param {number} toleranceSeconds maximum accepted clock skew
 * @returns {{valid: boolean, reason?: string}}
 */
function verifyWebhook(rawBody, signatureHeader, timestampHeader, secret, toleranceSeconds = DEFAULT_TOLERANCE_SECONDS) {
  if (!secret) return { valid: false, reason: 'no_secret_configured' };
  if (!signatureHeader) return { valid: false, reason: 'missing_signature_header' };
  if (!timestampHeader) return { valid: false, reason: 'missing_timestamp_header' };

  // 1. Replay protection first: cheap, and it fails fast.
  const timestamp = Number(timestampHeader);
  if (!Number.isFinite(timestamp)) return { valid: false, reason: 'malformed_timestamp' };

  const skew = Math.abs(Math.floor(Date.now() / 1000) - timestamp);
  if (skew > toleranceSeconds) return { valid: false, reason: 'timestamp_outside_tolerance' };

  // 2. Recompute the signature over timestamp + "." + rawBody.
  const body = Buffer.isBuffer(rawBody) ? rawBody.toString('utf8') : rawBody;
  const expected = crypto
    .createHmac('sha256', secret)
    .update(timestampHeader + '.' + body, 'utf8')
    .digest('hex');

  // 3. Strip the sha256= prefix. Comparison is case-insensitive on the hex.
  const received = signatureHeader.replace(/^sha256=/, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(received)) return { valid: false, reason: 'malformed_signature' };

  // 4. Constant-time comparison. Never use === here.
  const valid = crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(received, 'hex'));

  return valid ? { valid: true } : { valid: false, reason: 'signature_mismatch' };
}

module.exports = { verifyWebhook, DEFAULT_TOLERANCE_SECONDS };

// --- Self-test -------------------------------------------------------------
// Run directly to prove the implementation both accepts and rejects.
//   node verify.js

if (require.main === module) {
  const secret = process.env.TEXTCONVO_WEBHOOK_SECRET || 'test_secret_do_not_use_in_production';
  const rawBody = JSON.stringify({
    event: 'lead.accepted',
    lead_id: 'lead_abc123',
    contact_id: 'cnt_xyz789',
    phone: '+15035551234'
  });

  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = 'sha256=' + crypto.createHmac('sha256', secret).update(timestamp + '.' + rawBody).digest('hex');

  const cases = [
    ['valid signature', () => verifyWebhook(rawBody, signature, timestamp, secret)],
    ['tampered body', () => verifyWebhook(rawBody.replace('Jane', 'Mallory') + ' ', signature, timestamp, secret)],
    ['stale timestamp', () => verifyWebhook(rawBody, signature, String(Number(timestamp) - 4000), secret)],
    ['missing signature', () => verifyWebhook(rawBody, '', timestamp, secret)],
    ['wrong secret', () => verifyWebhook(rawBody, signature, timestamp, 'not_the_secret')]
  ];

  for (const [name, run] of cases) {
    const result = run();
    console.log((result.valid ? 'ACCEPT' : 'REJECT').padEnd(7), name, result.reason ? '(' + result.reason + ')' : '');
  }
}
