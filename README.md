# ring-partner-kit

A small, typed Python toolkit for building on the **Ring Partner API** (Amazon Vision). Ring publishes no official SDK,
so every partner ends up writing the same pieces: verifying webhook signatures, matching account-linking nonces,
refreshing tokens, following media redirects, and faking events for tests. This package does those, with tests.

Extracted from [Porchlight](https://github.com/dfifth/hackathons/tree/main/porchlight), an accessible doorbell
built for the Amazon Developer Hackathon 2026.

## Install

```bash
pip install ring-partner-kit          # or: pip install git+https://github.com/dfifth/ring-partner-kit
```

## What's inside

| Module | What it does |
|---|---|
| `webhooks` | `verify_signature()` checks `X-Signature: sha256=<hex>` over the **raw** body in constant time; `parse_event()` flattens the v1.1 JSON:API envelope into a `RingEvent`; event-type constants including contact sensors |
| `linking` | one-way (Ring-driven) account linking: `compute_nonce()` (URL-safe base64 HMAC, no padding), `check_freshness()` (10-minute window), `match_nonce()` over your unclaimed tokens, `mask_email()` for `account_identifier` |
| `client` | `RingOAuth` (authorization-code exchange and refresh), `TokenManager` (refresh before expiry, persist rotated refresh tokens), `RingClient` (devices, status, event history, snapshots and clips via the 303 pre-signed download without leaking the bearer token, chime playback, app-integrations, `whep_frame()`, which grabs one live-view frame over WHEP/WebRTC (set up through HTTPS, needs the `webrtc` extra: `pip install ring-partner-kit[webrtc]`), and `live_frame()`, which grabs one keyframe from the RTSPS bridge with FFmpeg; port 322 is blocked on some hosts, so try WHEP first); retries 429/5xx with `Retry-After`, refreshes once on 401 |
| `simulator` | builds v1.1 payloads for any event type and signs them exactly as Ring does, as a library or a CLI |

## Examples

Verify and parse a webhook (FastAPI):

```python
from ring_partner_kit import verify_signature, parse_event

@app.post("/webhooks/ring")
async def ring_webhook(request: Request):
    raw = await request.body()                     # the exact bytes, before any JSON parsing
    if not verify_signature(HMAC_KEY, raw, request.headers.get("X-Signature")):
        return Response(status_code=401)
    event = parse_event(raw)                       # RingEvent(type="button_press", device_id=..., ...)
    queue_for_processing(event)                    # answer within 5 seconds; do the work elsewhere
    return {"ok": True}
```

Download the snapshot for an event:

```python
from ring_partner_kit import RingClient, RingOAuth, TokenManager

client = RingClient(TokenManager(tokens, RingOAuth(CLIENT_ID, CLIENT_SECRET), on_refresh=save_tokens))
image = await client.snapshot_at(event.device_id, event.timestamp_ms)   # Media(content=b"...", content_type="image/jpeg")
```

Send a signed test event to your local handler:

```bash
ring-webhook-sim --url http://localhost:8000/webhooks/ring --key "$RING_HMAC_KEY" --type button_press
ring-webhook-sim --url http://localhost:8000/webhooks/ring --key "$RING_HMAC_KEY" --type contact_sensor_faulted
```

## Tests

```bash
pip install -e ".[test]" && pytest
```

The tests use `httpx.MockTransport`; no network or Ring account is needed. They cover signature checks (including
the classic re-serialised-JSON mistake), the documented payloads, nonce matching, the freshness window, token
refresh on 401, `Retry-After` handling and that pre-signed media URLs never receive the bearer token.

## Not affiliated

This is an independent open-source project. Ring and Amazon are trademarks of their owners.

## License

MIT
