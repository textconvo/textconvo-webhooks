"""TextConvo webhook receiver — Python + Flask.

Docs: https://textconvo.ai/docs#webhooks
Retries and idempotency: ../docs/RETRIES.md

Install and run:
    pip install flask
    export TEXTCONVO_WEBHOOK_SECRET=your_webhook_secret
    python flask_receiver.py

The important detail is request.get_data(). Verification must run against the
exact bytes TextConvo sent — request.get_json() parses them, and any
re-serialisation changes the signature.
"""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, Set

from flask import Flask, jsonify, request

sys.path.append(str(Path(__file__).resolve().parent.parent / "verification"))
from verify import verify_webhook  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("textconvo")

SECRET = os.environ.get("TEXTCONVO_WEBHOOK_SECRET")
if not SECRET:
    raise SystemExit("Set TEXTCONVO_WEBHOOK_SECRET before starting the receiver.")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024  # 1 MiB is plenty

# In-memory deduplication, good enough to demonstrate the idea. In production
# use a table with a unique constraint, or a queue with deduplication built in.
_seen: Set[str] = set()


def dedupe_key(payload: Dict[str, Any]) -> str:
    """Build a stable key from whichever identifiers this event carries."""
    parts = [
        payload.get("event"),
        payload.get("lead_id"),
        payload.get("message_id"),
        payload.get("contact_id"),
        payload.get("received_at")
        or payload.get("delivered_at")
        or payload.get("failed_at")
        or payload.get("opted_out_at")
        or payload.get("pushed_at"),
    ]
    return ":".join(str(part) for part in parts if part)


@app.post("/webhooks/textconvo")
def receive() -> Any:
    raw_body = request.get_data()  # exact bytes, before any parsing

    result = verify_webhook(
        raw_body,
        request.headers.get("X-TextConvo-Signature"),
        request.headers.get("X-TextConvo-Timestamp"),
        SECRET,
    )

    if not result.valid:
        # Log the reason, tell the caller nothing useful.
        logger.warning("Rejected webhook: %s", result.reason)
        return jsonify(error="invalid signature"), 401

    payload = request.get_json(silent=True)
    if payload is None:
        # Signature was valid, so a retry would fail identically. Accept and
        # investigate offline rather than triggering a retry storm.
        logger.error("Valid signature but unparseable body")
        return jsonify(received=True), 200

    key = dedupe_key(payload)
    if key in _seen:
        logger.info("Duplicate delivery ignored: %s", key)
        return jsonify(received=True, duplicate=True), 200
    _seen.add(key)

    # Answer fast, work later. In production this is a queue push and the
    # handler below runs in a worker.
    handle_event(payload)

    return jsonify(received=True), 200


def handle_event(payload: Dict[str, Any]) -> None:
    """Switch on the event name, and ignore what you do not handle.

    Returning an error for an unfamiliar event means your receiver breaks the
    day a new one ships.
    """
    event = payload.get("event", "")

    if event == "lead.accepted":
        logger.info("Lead accepted: %s (contact %s)", payload.get("lead_id"), payload.get("contact_id"))
    elif event == "lead.rejected":
        logger.info("Lead rejected: %s", payload.get("lead_id"))
    elif event in {"lead.delivered", "lead.sent"}:
        logger.info("Message %s: %s", event, payload.get("message_id"))
    elif event == "lead.failed":
        logger.warning("Message failed: %s (%s)", payload.get("message_id"), payload.get("error_code"))
    elif event == "lead.reply":
        logger.info("Reply from %s: %s", payload.get("contact_id"), payload.get("message_text"))
    elif event == "lead.click":
        logger.info("Link clicked by %s", payload.get("contact_id"))
    elif event == "lead.opt_out":
        # TextConvo applies suppression already; stop contacting them from your
        # own systems too.
        logger.info("Opt-out: %s on %s", payload.get("contact_id"), payload.get("channel"))
    elif event == "journey.crm_pushed":
        logger.info("Journey outcome pushed to %s: %s", payload.get("crm_key"), payload.get("outcome"))
    elif event in {"scheduled_call.confirmed", "scheduled_call.cancelled"}:
        logger.info("Scheduled call %s for %s", event, payload.get("contact_id"))
    elif event in {"support.call_me_now", "support.call_back_later"}:
        logger.info("Callback requested: %s %s", event, payload.get("contact_id"))
    else:
        logger.info("Unhandled event %s — ignoring", event)


@app.get("/healthz")
def healthz() -> Any:
    """Health checks must not require a signature."""
    return "ok", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "3000"))
    logger.info("Listening on http://localhost:%d/webhooks/textconvo", port)
    logger.info("Expose it with a tunnel, then set the URL in TextConvo.")
    app.run(port=port)
