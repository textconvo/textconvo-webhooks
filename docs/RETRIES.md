# Retries, duplicates, and idempotent receivers

Webhook delivery is at-least-once. Assume every event can arrive twice, out of order, and occasionally later than you expect. A receiver built on that assumption is boring to operate; one built on optimism is not.

For delivery guarantees and the retry window specific to your account, see [textconvo.ai/docs#webhooks](https://textconvo.ai/docs#webhooks) or ask [support](https://textconvo.ai/contact-us).

## What counts as success

Return a 2xx status as soon as you have verified the signature and safely stored the event. Anything else is treated as a failure and will be retried.

| Your response | Interpreted as |
| --- | --- |
| 200, 201, 202, 204 | Delivered. No retry. |
| 3xx | Failure. Do not redirect webhook endpoints. |
| 400, 401, 403, 422 | Failure. Usually a verification bug on your side. |
| 5xx | Failure. Retried. |
| Timeout or connection reset | Failure. Retried. |

A 2xx does not mean you finished the work. It means you accepted responsibility for it.

## Answer fast, work later

The pattern that survives contact with production:

1. Read the raw body.
2. Verify the signature and the timestamp.
3. Write the event to a queue or table, keyed for deduplication.
4. Return 200.
5. Process from the queue, with your own retries and alerting.

If steps 4 and 5 are the other way round, a slow database becomes a retry storm, and a retry storm becomes duplicate messages to your customers.

## Deduplicating

Key on the identifiers each event carries:

| Event | Suggested key |
| --- | --- |
| `lead.accepted`, `lead.rejected` | `event` + `lead_id` |
| `lead.delivered`, `lead.failed`, `lead.sent` | `event` + `message_id` |
| `lead.reply`, `lead.click` | `event` + `message_id` + timestamp field |
| `lead.opt_out` | `event` + `contact_id` + `channel` |
| `journey.crm_pushed` | `event` + `contact_id` + `pushed_at` |
| `scheduled_call.*` | `event` + `contact_id` + scheduled time |

Store that key with a unique constraint and let the database reject the second arrival. It is less code than checking first, and it is race-free.

```sql
CREATE TABLE textconvo_events (
  dedupe_key   TEXT PRIMARY KEY,
  event        TEXT NOT NULL,
  payload      JSONB NOT NULL,
  received_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  processed_at TIMESTAMPTZ
);
```

Insert with `ON CONFLICT DO NOTHING`. If nothing was inserted, you have seen this event and can return 200 immediately.

## Out-of-order delivery

A reply can land before the delivery confirmation for the message it answers. Never derive state from arrival order. Use the timestamp inside the payload, and treat an older timestamp as a no-op when it arrives after a newer one.

## Timestamp and replay protection

Reject deliveries whose `X-TextConvo-Timestamp` is far from your clock. A few minutes is sensible, and the outbound API uses 300 seconds for signed requests. This is what makes a captured request useless later.

Two practical notes: keep your clocks on NTP, and log the timestamp you rejected. Most "webhooks stopped working" incidents are clock drift.

## When your receiver had a bug

Fix the receiver first, then reconcile:

- Contacts and journey outcomes can be re-synced through your [CRM integration](https://textconvo.ai/docs#crm-integrations).
- For a gap you cannot close yourself, [contact support](https://textconvo.ai/contact-us) with the time window and your source key.

## Local testing checklist

- A valid signature is accepted.
- A tampered body with the original signature is rejected.
- A valid signature with an old timestamp is rejected.
- A missing signature header is rejected.
- The same event delivered twice is processed once.
- An unknown `event` value returns 200 and is ignored, not 500.

The last one matters more than it looks: new events are added over time, and a receiver that throws on anything unfamiliar will fail the day the platform grows.
