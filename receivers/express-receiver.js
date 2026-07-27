/**
 * TextConvo webhook receiver — Node.js + Express
 *
 * Docs: https://textconvo.ai/docs#webhooks
 * Retries and idempotency: ../docs/RETRIES.md
 *
 * Install and run:
 *   npm install express
 *   export TEXTCONVO_WEBHOOK_SECRET=your_webhook_secret
 *   node express-receiver.js
 *
 * The important detail is express.raw(). Verification must run against the
 * exact bytes TextConvo sent — express.json() would parse and discard them,
 * and any re-serialisation changes the signature.
 */

'use strict';

const express = require('express');
const { verifyWebhook } = require('../verification/verify');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.TEXTCONVO_WEBHOOK_SECRET;

if (!SECRET) {
  console.error('Set TEXTCONVO_WEBHOOK_SECRET before starting the receiver.');
  process.exit(1);
}

const app = express();

// In-memory deduplication, good enough to demonstrate the idea. In production
// use a table with a unique constraint, or a queue with deduplication built in.
// See ../docs/RETRIES.md
const seen = new Set();

function dedupeKey(payload) {
  return [
    payload.event,
    payload.lead_id,
    payload.message_id,
    payload.contact_id,
    payload.received_at || payload.delivered_at || payload.failed_at || payload.opted_out_at || payload.pushed_at
  ].filter(Boolean).join(':');
}

app.post(
  '/webhooks/textconvo',
  express.raw({ type: 'application/json', limit: '1mb' }),
  (req, res) => {
    const rawBody = req.body; // Buffer, exactly as received

    const result = verifyWebhook(
      rawBody,
      req.get('X-TextConvo-Signature'),
      req.get('X-TextConvo-Timestamp'),
      SECRET
    );

    if (!result.valid) {
      // Log the reason, tell the caller nothing useful.
      console.warn('Rejected webhook:', result.reason);
      return res.status(401).json({ error: 'invalid signature' });
    }

    let payload;
    try {
      payload = JSON.parse(rawBody.toString('utf8'));
    } catch (error) {
      // Signature was valid, so a retry would fail identically. Accept and
      // investigate offline rather than triggering a retry storm.
      console.error('Valid signature but unparseable body:', error.message);
      return res.status(200).json({ received: true });
    }

    const key = dedupeKey(payload);
    if (seen.has(key)) {
      console.log('Duplicate delivery ignored:', key);
      return res.status(200).json({ received: true, duplicate: true });
    }
    seen.add(key);

    // Answer fast, work later. In production the line below is a queue push.
    res.status(200).json({ received: true });
    setImmediate(() => handleEvent(payload));
  }
);

/**
 * Switch on payload.event. Ignore what you do not handle — returning an error
 * for an unfamiliar event means your receiver breaks the day a new one ships.
 */
function handleEvent(payload) {
  switch (payload.event) {
    case 'lead.accepted':
      console.log('Lead accepted:', payload.lead_id, 'contact', payload.contact_id);
      break;
    case 'lead.rejected':
      console.log('Lead rejected:', payload.lead_id);
      break;
    case 'lead.delivered':
    case 'lead.sent':
      console.log('Message', payload.event, payload.message_id);
      break;
    case 'lead.failed':
      console.warn('Message failed:', payload.message_id, payload.error_code);
      break;
    case 'lead.reply':
      console.log('Reply from', payload.contact_id + ':', payload.message_text);
      break;
    case 'lead.click':
      console.log('Link clicked by', payload.contact_id);
      break;
    case 'lead.opt_out':
      // TextConvo applies suppression already; stop contacting them from your
      // own systems too.
      console.log('Opt-out:', payload.contact_id, 'on', payload.channel);
      break;
    case 'journey.crm_pushed':
      console.log('Journey outcome pushed to', payload.crm_key + ':', payload.outcome);
      break;
    case 'scheduled_call.confirmed':
    case 'scheduled_call.cancelled':
      console.log('Scheduled call', payload.event, 'for', payload.contact_id);
      break;
    case 'support.call_me_now':
    case 'support.call_back_later':
      console.log('Callback requested:', payload.event, payload.contact_id);
      break;
    default:
      console.log('Unhandled event', payload.event, '— ignoring');
  }
}

// A health endpoint is useful, and it must not require a signature.
app.get('/healthz', (_req, res) => res.status(200).send('ok'));

app.listen(PORT, () => {
  console.log('Listening on http://localhost:' + PORT + '/webhooks/textconvo');
  console.log('Expose it with a tunnel, then set the URL in TextConvo.');
});
