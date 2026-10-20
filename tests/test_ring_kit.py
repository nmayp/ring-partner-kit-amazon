import asyncio
import base64
import hashlib
import hmac
import json
import time

import httpx
import pytest

from ring_partner_kit import (LinkError, RingAPIError, RingClient, RingOAuth, TokenManager, TokenSet, build_event,
                              check_freshness, compute_nonce, mask_email, match_nonce, parse_event, sign,
                              signed_delivery, verify_signature)

KEY = "test-signing-key"

# Payload copied from the Ring webhook documentation (motion_detected, v1.1).
DOC_MOTION = (b'{"meta":{"version":"1.1","time":"2026-02-13T13:39:57.200155525Z",'
              b'"request_id":"2ad45ade-1818-4154-813b-afdd8bcd8085","account_id":"ava1.ring.account.XXXYYY"},'
              b'"data":{"id":"dev_motion_1786715596787","type":"motion_detected","attributes":{"source":"dev",'
              b'"source_type":"devices","timestamp":1786715596787,"timestamp_readable":"2026-08-14 08:53:16",'
              b'"sub_type":"motion","component_ids":["0"]},"relationships":{"devices":{"links":{"self":"/v1/devices/dev"}}}}}')


def test_signature_roundtrip_and_tamper():
    header = sign(KEY, DOC_MOTION)
    assert header.startswith("sha256=")
    assert verify_signature(KEY, DOC_MOTION, header)
    assert verify_signature(KEY, DOC_MOTION, header.removeprefix("sha256="))
    assert not verify_signature(KEY, DOC_MOTION + b" ", header)
    assert not verify_signature("other-key", DOC_MOTION, header)
    assert not verify_signature(KEY, DOC_MOTION, None)


def test_signature_over_reserialised_json_fails():
    # The classic mistake: verifying json.dumps(json.loads(body)) instead of the raw bytes.
    header = sign(KEY, DOC_MOTION)
    assert not verify_signature(KEY, json.dumps(json.loads(DOC_MOTION)).encode(), header)


def test_parse_documented_payload():
    event = parse_event(DOC_MOTION)
    assert event.type == "motion_detected"
    assert event.device_id == "dev"
    assert event.account_id == "ava1.ring.account.XXXYYY"
    assert event.timestamp_ms == 1786715596787
    assert event.sub_type == "motion"
    assert event.component_ids == ("0",)
    assert event.is_visitor_event


def test_parse_rejects_bad_bodies():
    from ring_partner_kit import WebhookError
    for body in (b"not json", b"[]", b'{"meta":{},"data":{}}'):
        with pytest.raises(WebhookError):
            parse_event(body)


def test_simulator_builds_signed_parseable_events():
    payload = build_event("button_press", "sim.door", account_id="acct", timestamp_ms=1000, request_id="r1")
    raw, headers = signed_delivery(KEY, payload)
    assert verify_signature(KEY, raw, headers["X-Signature"])
    event = parse_event(raw)
    assert (event.type, event.device_id, event.account_id, event.request_id) == ("button_press", "sim.door", "acct", "r1")
    assert event.event_id == "sim.door_button_press_1000"
    with pytest.raises(ValueError):
        build_event("doorbell_rang", "x")


def test_nonce_matches_ring_algorithm():
    t, account = "1771130906289", "ava1.ring.account.ABC"
    expected = base64.urlsafe_b64encode(
        hmac.new(KEY.encode(), f"{t}:{account}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    nonce = compute_nonce(t, account, KEY)
    assert nonce == expected and "=" not in nonce and "+" not in nonce and "/" not in nonce
    assert match_nonce(nonce, t, ["ava1.ring.account.OTHER", account], KEY) == account
    assert match_nonce(nonce, t, ["ava1.ring.account.OTHER"], KEY) is None
    assert match_nonce(nonce, "1771130906290", [account], KEY) is None


def test_freshness_window():
    now = 1_800_000_000_000
    check_freshness(now - 599_000, now_ms=now)
    with pytest.raises(LinkError):
        check_freshness(now - 601_000, now_ms=now)
    with pytest.raises(LinkError):
        check_freshness(now + 5_000, now_ms=now)
    with pytest.raises(LinkError):
        check_freshness("abc", now_ms=now)


def test_mask_email():
    assert mask_email("user@partner.example.com") == "u***r@partner.example.com"
    assert mask_email("al@x.io") == "a***@x.io"


# Client -------------------------------------------------------------------------------------------

def _run(coro):
    return asyncio.run(coro)


def test_snapshot_follows_redirect_without_bearer():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.host == "api.test":
            body = json.loads(request.content)
            assert body == {"type": "at_timestamp", "timestamp": 123, "image_options": {"format": "jpeg"},
                            "components": [{"component_id": "1"}]}
            return httpx.Response(303, headers={"Location": "https://download.test/v1/download?security_token=x"})
        return httpx.Response(200, content=b"JPEG", headers={"Content-Type": "image/jpeg",
                                                             "X-Media-Timestamp": "124", "X-Media-Origin": "snapshot"})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client = RingClient("tok", base_url="https://api.test", http=http)
    media = _run(client.snapshot_at("dev1", 123, component_id="1"))
    assert (media.content, media.content_type, media.media_timestamp_ms, media.origin) == (b"JPEG", "image/jpeg", 124, "snapshot")
    assert seen[0].headers["Authorization"] == "Bearer tok"
    assert "Authorization" not in seen[1].headers  # pre-signed URL must not receive the token


def test_401_refreshes_once_and_persists():
    calls = {"api": 0}
    persisted = []

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth.test":
            form = dict(x.split("=") for x in request.content.decode().split("&"))
            assert form["grant_type"] == "refresh_token" and form["refresh_token"] == "r1"
            assert form["client_id"] == "cid" and form["client_secret"] == "secret"
            return httpx.Response(200, json={"access_token": "a2", "refresh_token": "r2", "expires_in": 14400})
        calls["api"] += 1
        if request.headers["Authorization"] == "Bearer a1":
            return httpx.Response(401, json={"errors": [{"detail": "expired"}]})
        return httpx.Response(200, json={"data": {"type": "users", "id": "ava1.ring.account.Z"}})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    oauth = RingOAuth("cid", "secret", token_url="https://oauth.test/oauth/token", http=http)

    async def persist(tokens):
        persisted.append(tokens)

    manager = TokenManager(TokenSet("a1", "r1", time.time() + 3600), oauth, on_refresh=persist)
    client = RingClient(manager, base_url="https://api.test", http=http)
    assert _run(client.account_id()) == "ava1.ring.account.Z"
    assert calls["api"] == 2 and [t.refresh_token for t in persisted] == ["r2"]


def test_429_retries_after_header_then_raises_on_404():
    attempts = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(request.url.path)
        if request.url.path == "/v1/devices" and len(attempts) == 1:
            return httpx.Response(429, headers={"Retry-After": "0"})
        if request.url.path == "/v1/devices":
            return httpx.Response(200, json={"data": [{"type": "devices", "id": "d1", "attributes": {"name": "Door"}}]})
        return httpx.Response(404, json={"errors": [{"detail": "no such device"}]})

    client = RingClient("tok", base_url="https://api.test", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert _run(client.list_devices())[0]["id"] == "d1"
    with pytest.raises(RingAPIError) as err:
        _run(client.device_status("missing"))
    assert err.value.status == 404 and "no such device" in str(err.value)


def test_exchange_code_posts_form():
    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(x.split("=") for x in request.content.decode().split("&"))
        assert form == {"grant_type": "authorization_code", "code": "c0de", "client_id": "cid", "client_secret": "s"}
        return httpx.Response(200, json={"access_token": "a", "refresh_token": "r", "expires_in": 100, "scope": "ava"})

    oauth = RingOAuth("cid", "s", token_url="https://oauth.test/t", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    tokens = _run(oauth.exchange_code("c0de"))
    assert tokens.access_token == "a" and tokens.scope == "ava" and tokens.expiring(now=tokens.expires_at - 10)


# Live view (RTSPS through FFmpeg) ------------------------------------------------------------------

FAKE_FFMPEG = str(__import__("pathlib").Path(__file__).parent / "fakes" / "ffmpeg")


def test_live_frame_passes_token_in_query_and_returns_jpeg(tmp_path, monkeypatch):
    log = tmp_path / "args.log"
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "ok")
    monkeypatch.setenv("FAKE_FFMPEG_LOG", str(log))
    client = RingClient("tok-123", rtsp_base="rtsps://rtsp.test:322", ffmpeg=FAKE_FFMPEG)
    media = _run(client.live_frame("dev1", component_id="2"))
    assert media.content.startswith(b"\xff\xd8") and media.origin == "live" and media.content_type == "image/jpeg"
    args = log.read_text().strip().split("\t")
    assert args[args.index("-i") + 1] == "rtsps://rtsp.test:322/v1/devices/dev1/stream?token=tok-123&component_id=2"
    assert args[args.index("-rtsp_transport") + 1] == "tcp" and args[args.index("-frames:v") + 1] == "1"


def test_live_frame_errors_never_contain_the_token(monkeypatch):
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "401")
    client = RingClient("very-secret-token", rtsp_base="rtsps://rtsp.test:322", ffmpeg=FAKE_FFMPEG)
    with pytest.raises(RingAPIError) as err:
        _run(client.live_frame("dev1"))
    assert err.value.status == 401 and "very-secret-token" not in str(err.value) and "<token>" in str(err.value)


def test_live_frame_refreshes_once_on_401(monkeypatch):
    monkeypatch.setenv("FAKE_FFMPEG_MODE", "401")
    refreshed = []

    class Manager:
        async def access_token(self, force_refresh=False):
            refreshed.append(force_refresh)
            return "t2" if force_refresh else "t1"

    client = RingClient(Manager(), rtsp_base="rtsps://rtsp.test:322", ffmpeg=FAKE_FFMPEG)
    with pytest.raises(RingAPIError):
        _run(client.live_frame("dev1"))
    assert refreshed == [False, True]


def test_live_frame_without_ffmpeg():
    client = RingClient("t", ffmpeg="/nonexistent/ffmpeg")
    with pytest.raises(RingAPIError) as err:
        _run(client.live_frame("dev1"))
    assert "FFmpeg" in str(err.value)
