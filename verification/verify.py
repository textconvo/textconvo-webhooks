"""TextConvo webhook signature verification — Python.

Docs: https://textconvo.ai/docs#webhooks
Requires: Python 3.9+ (standard library only)

Signature:     X-TextConvo-Signature: sha256=<hex>
Signed string: timestamp + "." + raw_body

raw_body must be the EXACT bytes received. If your framework parsed and
re-serialised the JSON, the signature will not match — see
../receivers/flask_receiver.py for how to keep the raw body.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Optional, Union

# Reject anything older than this even when the signature is valid.
# This is what makes a captured request useless later.
DEFAULT_TOLERANCE_SECONDS = 300

_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    reason: Optional[str] = None


def verify_webhook(
    raw_body: Union[str, bytes],
    signature_header: Optional[str],
    timestamp_header: Optional[str],
    secret: Optional[str],
    tolerance_seconds: int = DEFAULT_TOLERANCE_SECONDS,
) -> VerificationResult:
    """Verify a TextConvo webhook signature and timestamp."""
    if not secret:
        return VerificationResult(False, "no_secret_configured")
    if not signature_header:
        return VerificationResult(False, "missing_signature_header")
    if not timestamp_header:
        return VerificationResult(False, "missing_timestamp_header")

    # 1. Replay protection first: cheap, and it fails fast.
    try:
        timestamp = int(timestamp_header)
    except ValueError:
        return VerificationResult(False, "malformed_timestamp")

    if abs(int(time.time()) - timestamp) > tolerance_seconds:
        return VerificationResult(False, "timestamp_outside_tolerance")

    # 2. Recompute over timestamp + "." + raw_body.
    body = raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body
    expected = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp_header}.{body}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    # 3. Strip the sha256= prefix. Hex comparison is case-insensitive.
    received = signature_header.removeprefix("sha256=").lower()
    if not _HEX_64.match(received):
        return VerificationResult(False, "malformed_signature")

    # 4. Constant-time comparison. Never use == here.
    if not hmac.compare_digest(expected, received):
        return VerificationResult(False, "signature_mismatch")

    return VerificationResult(True)


# --- Self-test -------------------------------------------------------------
# Run directly to prove the implementation both accepts and rejects.
#   python verify.py

if __name__ == "__main__":
    secret = os.environ.get("TEXTCONVO_WEBHOOK_SECRET", "test_secret_do_not_use_in_production")
    raw_body = json.dumps(
        {
            "event": "lead.accepted",
            "lead_id": "lead_abc123",
            "contact_id": "cnt_xyz789",
            "phone": "+15035551234",
        },
        separators=(",", ":"),
    )

    now = str(int(time.time()))
    signature = "sha256=" + hmac.new(
        secret.encode(), f"{now}.{raw_body}".encode(), hashlib.sha256
    ).hexdigest()

    cases = [
        ("valid signature", raw_body, signature, now, secret),
        ("tampered body", raw_body + " ", signature, now, secret),
        ("stale timestamp", raw_body, signature, str(int(now) - 4000), secret),
        ("missing signature", raw_body, None, now, secret),
        ("wrong secret", raw_body, signature, now, "not_the_secret"),
    ]

    for name, body, sig, ts, key in cases:
        result = verify_webhook(body, sig, ts, key)
        verdict = "ACCEPT" if result.valid else "REJECT"
        print(f"{verdict:<7}{name}" + (f" ({result.reason})" if result.reason else ""))
