"""Ring webhook signatures and payload parsing.

Ring signs every webhook with HMAC-SHA256 over the raw request body and sends the hex digest in the
``X-Signature`` header as ``sha256=<hex>``. Verify against the bytes exactly as received: parsing and
re-serialising the JSON changes whitespace and key order, and the digest will no longer match.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from typing import Any

SIGNATURE_HEADER = "X-Signature"

MOTION_DETECTED = "motion_detected"
BUTTON_PRESS = "button_press"
DEVICE_ADDED = "device_added"
DEVICE_REMOVED = "device_removed"
DEVICE_ONLINE = "device_online"
DEVICE_OFFLINE = "device_offline"
APP_INTEGRATION_ADDED = "app_integration_added"
APP_INTEGRATION_REMOVED = "app_integration_removed"
SUBSCRIPTION_ACTIVATED = "subscription_activated"
SUBSCRIPTION_DEACTIVATED = "subscription_deactivated"
CONTACT_OPENED = "contact_sensor_faulted"   # Ring's name: "faulted" means the door/window is open
CONTACT_CLOSED = "contact_sensor_cleared"
TAMPER_DETECTED = "tamper_detected"
TAMPER_CLEARED = "tamper_cleared"

EVENT_TYPES = frozenset({
    MOTION_DETECTED, BUTTON_PRESS, DEVICE_ADDED, DEVICE_REMOVED, DEVICE_ONLINE, DEVICE_OFFLINE,
    APP_INTEGRATION_ADDED, APP_INTEGRATION_REMOVED, SUBSCRIPTION_ACTIVATED, SUBSCRIPTION_DEACTIVATED,
    CONTACT_OPENED, CONTACT_CLOSED, TAMPER_DETECTED, TAMPER_CLEARED,
})


class WebhookError(ValueError):
    """The webhook body is not a valid Ring v1.x payload."""


def sign(signing_key: str, raw_body: bytes) -> str:
    """Return the ``X-Signature`` header value Ring would send for ``raw_body``."""
    digest = hmac.new(signing_key.encode(), raw_body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def verify_signature(signing_key: str, raw_body: bytes, received: str | None) -> bool:
    """Constant-time check of an ``X-Signature`` header against the raw body."""
    if not received or not signing_key:
        return False
    expected = sign(signing_key, raw_body).removeprefix("sha256=")
    return hmac.compare_digest(expected, received.strip().removeprefix("sha256="))


@dataclass(frozen=True)
class RingEvent:
    """One webhook delivery, flattened from the JSON:API envelope."""

    request_id: str
    type: str
    device_id: str | None
    timestamp_ms: int | None
    account_id: str | None = None
    event_id: str | None = None
    sub_type: str | None = None
    component_ids: tuple[str, ...] = ()
    sent_at: str | None = None
    version: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    @property
    def is_visitor_event(self) -> bool:
        return self.type in (BUTTON_PRESS, MOTION_DETECTED)


def parse_event(raw_body: bytes | str | dict[str, Any]) -> RingEvent:
    """Parse a webhook body (after its signature has been verified)."""
    if isinstance(raw_body, dict):
        payload = raw_body
    else:
        try:
            payload = json.loads(raw_body)
        except (TypeError, ValueError) as exc:
            raise WebhookError(f"body is not JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise WebhookError("body is not a JSON object")
    meta = payload.get("meta") or {}
    data = payload.get("data") or {}
    attrs = data.get("attributes") or {}
    event_type = data.get("type")
    request_id = meta.get("request_id")
    if not event_type or not request_id:
        raise WebhookError("missing data.type or meta.request_id")
    timestamp = attrs.get("timestamp")
    return RingEvent(
        request_id=str(request_id),
        type=str(event_type),
        device_id=attrs.get("source") if attrs.get("source_type", "devices") == "devices" else None,
        timestamp_ms=int(timestamp) if timestamp is not None else None,
        account_id=meta.get("account_id"),
        event_id=data.get("id"),
        sub_type=attrs.get("sub_type"),
        component_ids=tuple(str(c) for c in attrs.get("component_ids") or ()),
        sent_at=meta.get("time"),
        version=meta.get("version"),
        raw=payload,
    )
