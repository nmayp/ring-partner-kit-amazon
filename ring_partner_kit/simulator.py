"""Build and send correctly signed Ring webhook deliveries for local development and tests.

    python -m ring_partner_kit.simulator --url http://localhost:8000/webhooks/ring \\
        --key "$RING_HMAC_KEY" --type button_press --device sim.front-door

The payloads follow Ring's webhook v1.1 shape, so a handler that accepts them should accept real
deliveries too.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx

from .webhooks import BUTTON_PRESS, EVENT_TYPES, MOTION_DETECTED, SIGNATURE_HEADER, sign


def build_event(event_type: str, device_id: str, *, account_id: str = "ava1.ring.account.SIMULATED",
                timestamp_ms: int | None = None, sub_type: str | None = None,
                component_ids: list[str] | None = None, request_id: str | None = None) -> dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"unknown event type {event_type!r}")
    ts = int(time.time() * 1000) if timestamp_ms is None else int(timestamp_ms)
    attributes: dict[str, Any] = {"source": device_id, "source_type": "devices", "timestamp": ts}
    if event_type == MOTION_DETECTED:
        attributes["sub_type"] = sub_type or "human"
        attributes["timestamp_readable"] = datetime.fromtimestamp(ts / 1000, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S")
    if component_ids:
        attributes["component_ids"] = list(component_ids)
    return {
        "meta": {
            "version": "1.1",
            "time": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "request_id": request_id or str(uuid.uuid4()),
            "account_id": account_id,
        },
        "data": {
            "id": f"{device_id}_{event_type}_{ts}",
            "type": event_type,
            "attributes": attributes,
            "relationships": {"devices": {"links": {"self": f"/v1/devices/{device_id}"}}},
        },
    }


def signed_delivery(signing_key: str, payload: dict[str, Any]) -> tuple[bytes, dict[str, str]]:
    """Serialise ``payload`` once and sign exactly those bytes."""
    body = json.dumps(payload, separators=(",", ":")).encode()
    return body, {"Content-Type": "application/json", SIGNATURE_HEADER: sign(signing_key, body)}


def send(url: str, signing_key: str, payload: dict[str, Any], *, timeout: float = 10) -> httpx.Response:
    body, headers = signed_delivery(signing_key, payload)
    return httpx.post(url, content=body, headers=headers, timeout=timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send a signed Ring webhook to a local handler")
    parser.add_argument("--url", required=True)
    parser.add_argument("--key", required=True, help="HMAC signing key")
    parser.add_argument("--type", default=BUTTON_PRESS, choices=sorted(EVENT_TYPES))
    parser.add_argument("--device", default="sim.front-door")
    parser.add_argument("--account", default="ava1.ring.account.SIMULATED")
    parser.add_argument("--sub-type", default=None, help="motion sub_type, e.g. human")
    args = parser.parse_args(argv)
    payload = build_event(args.type, args.device, account_id=args.account, sub_type=args.sub_type)
    resp = send(args.url, args.key, payload)
    print(resp.status_code, resp.text[:500])
    return 0 if resp.is_success else 1


if __name__ == "__main__":
    sys.exit(main())
