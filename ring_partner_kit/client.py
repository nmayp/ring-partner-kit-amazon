"""Async client for the Ring Partner (Amazon Vision) API.

Covers OAuth token exchange and refresh, device discovery, event history, snapshot and clip downloads,
chime playback and the App-Integrations calls used during account linking. Every call is
server-to-server: the API blocks browser requests with CORS.
"""
from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

API_BASE = "https://api.amazonvision.com"
OAUTH_TOKEN_URL = "https://oauth.ring.com/oauth/token"
RTSP_BASE = "rtsps://video.rtsp.amazonvision.com:322"

# Refresh this long before the access token expires (tokens live about 4 hours).
REFRESH_MARGIN_SECONDS = 300


class RingAPIError(Exception):
    def __init__(self, status: int, message: str, request_id: str | None = None):
        super().__init__(f"Ring API {status}: {message}")
        self.status = status
        self.request_id = request_id


@dataclass
class TokenSet:
    access_token: str
    refresh_token: str
    expires_at: float
    scope: str | None = None

    @classmethod
    def from_response(cls, body: dict[str, Any], now: float | None = None) -> TokenSet:
        now = time.time() if now is None else now
        return cls(
            access_token=body["access_token"],
            refresh_token=body["refresh_token"],
            expires_at=now + float(body.get("expires_in", 14400)),
            scope=body.get("scope"),
        )

    def expiring(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return now >= self.expires_at - REFRESH_MARGIN_SECONDS


@dataclass
class Media:
    content: bytes
    content_type: str
    media_timestamp_ms: int | None = None
    origin: str | None = None  # "recording" or "snapshot" for images


class RingOAuth:
    """Exchanges authorization codes and refresh tokens at Ring's OAuth server."""

    def __init__(self, client_id: str, client_secret: str, *, token_url: str = OAUTH_TOKEN_URL,
                 http: httpx.AsyncClient | None = None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self._http = http or httpx.AsyncClient(timeout=15)

    async def _token_request(self, form: dict[str, str]) -> TokenSet:
        form = {**form, "client_id": self.client_id, "client_secret": self.client_secret}
        resp = await self._http.post(self.token_url, data=form)
        if resp.status_code != 200:
            raise RingAPIError(resp.status_code, f"token request failed: {resp.text[:300]}")
        return TokenSet.from_response(resp.json())

    async def exchange_code(self, code: str, code_verifier: str | None = None) -> TokenSet:
        """Exchange an authorization code. One-way linking codes are valid for only 60 seconds."""
        form = {"grant_type": "authorization_code", "code": code}
        if code_verifier:
            form["code_verifier"] = code_verifier
        return await self._token_request(form)

    async def refresh(self, refresh_token: str) -> TokenSet:
        return await self._token_request({"grant_type": "refresh_token", "refresh_token": refresh_token})


class TokenManager:
    """Hands out a valid access token for one Ring account, refreshing it when it is about to expire.

    ``on_refresh`` is awaited with the new :class:`TokenSet` so the caller can persist it; Ring rotates
    the refresh token on every exchange, so the old one must not be reused.
    """

    def __init__(self, tokens: TokenSet, oauth: RingOAuth,
                 on_refresh: Callable[[TokenSet], Awaitable[None]] | None = None):
        self.tokens = tokens
        self._oauth = oauth
        self._on_refresh = on_refresh
        self._lock = asyncio.Lock()

    async def access_token(self, force_refresh: bool = False) -> str:
        async with self._lock:
            if force_refresh or self.tokens.expiring():
                self.tokens = await self._oauth.refresh(self.tokens.refresh_token)
                if self._on_refresh:
                    await self._on_refresh(self.tokens)
            return self.tokens.access_token


class RingClient:
    """Thin typed wrapper over the Ring Partner API for one linked Ring account."""

    def __init__(self, token: TokenManager | str, *, base_url: str = API_BASE,
                 http: httpx.AsyncClient | None = None, max_retries: int = 3,
                 rtsp_base: str = RTSP_BASE, ffmpeg: str = "ffmpeg"):
        self._token = token
        self.base_url = base_url.rstrip("/")
        self._http = http or httpx.AsyncClient(timeout=30)
        self.max_retries = max_retries
        self.rtsp_base = rtsp_base.rstrip("/")
        self.ffmpeg = ffmpeg

    async def _bearer(self, force_refresh: bool = False) -> str:
        if isinstance(self._token, str):
            return self._token
        return await self._token.access_token(force_refresh=force_refresh)

    async def _request(self, method: str, path: str, *, json: Any = None, params: dict | None = None,
                       allow_redirect: bool = False) -> httpx.Response:
        refreshed = False
        delay = 1.0
        for attempt in range(self.max_retries + 1):
            headers = {"Authorization": f"Bearer {await self._bearer(force_refresh=refreshed)}"}
            resp = await self._http.request(method, f"{self.base_url}{path}", json=json, params=params,
                                            headers=headers, follow_redirects=False)
            if resp.status_code == 401 and not refreshed and not isinstance(self._token, str):
                refreshed = True
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == self.max_retries:
                    break
                retry_after = resp.headers.get("Retry-After")
                await asyncio.sleep(float(retry_after) if retry_after else delay)
                delay *= 2
                continue
            if allow_redirect and resp.status_code in (301, 302, 303, 307, 308):
                return resp
            if resp.status_code >= 400:
                break
            return resp
        raise RingAPIError(resp.status_code, _error_message(resp), resp.headers.get("X-Request-ID"))

    async def _download(self, path: str, body: dict[str, Any]) -> Media:
        """Media downloads answer 303 with a pre-signed URL; fetch it without the bearer token."""
        resp = await self._request("POST", path, json=body, allow_redirect=True)
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers["Location"]
            resp = await self._http.get(location, follow_redirects=True)
            if resp.status_code != 200:
                raise RingAPIError(resp.status_code, _error_message(resp), resp.headers.get("X-Request-ID"))
        ts = resp.headers.get("X-Media-Timestamp")
        return Media(
            content=resp.content,
            content_type=resp.headers.get("Content-Type", "application/octet-stream").split(";")[0],
            media_timestamp_ms=int(ts) if ts and ts.isdigit() else None,
            origin=resp.headers.get("X-Media-Origin"),
        )

    # Users and integrations -------------------------------------------------------------------------

    async def account_id(self) -> str:
        body = (await self._request("GET", "/v1/users/me")).json()
        data = body.get("data") or {}
        return data.get("id") or (data.get("attributes") or {}).get("account_id")

    async def confirm_integration(self, nonce: str, account_identifier: str) -> dict[str, Any]:
        """POST the nonce back to Ring; the integration moves to ``awaiting``."""
        resp = await self._request("POST", "/v1/accounts/me/app-integrations",
                                   json={"account_identifier": account_identifier, "nonce": nonce})
        return resp.json() if resp.content else {}

    async def set_integration_status(self, status: str = "completed") -> dict[str, Any]:
        """PATCH the integration to ``completed`` (or back to ``awaiting``). Required after confirming."""
        resp = await self._request("PATCH", "/v1/accounts/me/app-integrations", json={"status": status})
        return resp.json() if resp.content else {}

    # Devices ----------------------------------------------------------------------------------------

    async def list_devices(self, include: str | None = "status,capabilities") -> list[dict[str, Any]]:
        params = {"include": include} if include else None
        body = (await self._request("GET", "/v1/devices", params=params)).json()
        return body.get("data") or []

    async def get_device(self, device_id: str, include: str | None = None) -> dict[str, Any]:
        params = {"include": include} if include else None
        return (await self._request("GET", f"/v1/devices/{device_id}", params=params)).json()

    async def device_status(self, device_id: str) -> dict[str, Any]:
        return (await self._request("GET", f"/v1/devices/{device_id}/status")).json()

    async def event_history(self, device_id: str, **params: Any) -> dict[str, Any]:
        return (await self._request("GET", f"/v1/history/devices/{device_id}/events", params=params)).json()

    # Media ------------------------------------------------------------------------------------------

    async def snapshot_at(self, device_id: str, timestamp_ms: int, *, fmt: str = "jpeg",
                          component_id: str | None = None) -> Media:
        body: dict[str, Any] = {"type": "at_timestamp", "timestamp": int(timestamp_ms),
                                "image_options": {"format": fmt}}
        if component_id is not None:
            body["components"] = [{"component_id": str(component_id)}]
        return await self._download(f"/v1/devices/{device_id}/media/image/download", body)

    async def latest_snapshot(self, device_id: str, *, since_ms: int, until_ms: int | None = None,
                              fmt: str = "jpeg", component_id: str | None = None) -> Media:
        body: dict[str, Any] = {"type": "latest_in_range", "start_timestamp": int(since_ms),
                                "image_options": {"format": fmt}}
        if until_ms is not None:
            body["end_timestamp"] = int(until_ms)
        if component_id is not None:
            body["components"] = [{"component_id": str(component_id)}]
        return await self._download(f"/v1/devices/{device_id}/media/image/download", body)

    async def download_clip(self, device_id: str, timestamp_ms: int, duration_ms: int = 15000, *,
                            audio: bool = True, component_id: str | None = None) -> Media:
        body: dict[str, Any] = {"timestamp": int(timestamp_ms), "duration": int(duration_ms),
                                "audio_options": {"audio_enabled": audio}}
        if component_id is not None:
            body["components"] = [{"component_id": str(component_id)}]
        return await self._download(f"/v1/devices/{device_id}/media/video/download", body)

    async def live_frame(self, device_id: str, *, component_id: str | None = None,
                         timeout: float = 25.0) -> Media:
        """Grab one frame of what the camera sees right now, through Ring's RTSPS live-view bridge.

        The media endpoints only serve frames from existing recordings (416 when there are none); live view
        works whenever the camera is online. Needs FFmpeg with TLS support on the PATH. FFmpeg can't send the
        token in a header, so it goes in the ``token`` query parameter, as Ring's docs advise; it is never
        logged and is removed from error messages.
        """
        for attempt in (0, 1):
            token = await self._bearer(force_refresh=attempt == 1)
            query = f"token={token}" + (f"&component_id={component_id}" if component_id is not None else "")
            url = f"{self.rtsp_base}/v1/devices/{device_id}/stream?{query}"
            args = [self.ffmpeg, "-hide_banner", "-nostdin", "-loglevel", "error", "-rtsp_transport", "tcp",
                    "-timeout", str(int(timeout * 1_000_000)), "-skip_frame", "nokey", "-i", url,
                    "-frames:v", "1", "-f", "image2", "-c:v", "mjpeg", "-q:v", "3", "pipe:1"]
            try:
                proc = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE,
                                                            stderr=asyncio.subprocess.PIPE)
            except FileNotFoundError as exc:
                raise RingAPIError(0, f"live view needs FFmpeg ({self.ffmpeg} not found)") from exc
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout + 5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise RingAPIError(504, f"live view gave no frame within {timeout:.0f} s")
            message = err.decode("utf-8", "replace").replace(token, "<token>").strip()
            if proc.returncode == 0 and out:
                return Media(content=out, content_type="image/jpeg",
                             media_timestamp_ms=int(time.time() * 1000), origin="live")
            status = _rtsp_status(message)
            if status == 401 and attempt == 0 and not isinstance(self._token, str):
                continue  # the token may have just expired: refresh once and retry
            raise RingAPIError(status, f"live view failed: {message[-300:] or f'ffmpeg exit {proc.returncode}'}")
        raise RingAPIError(401, "live view failed: token rejected")

    async def whep_frame(self, device_id: str, *, component_id: str | None = None, timeout: float = 15.0,
                         skip: int = 3, ice_servers: tuple[str, ...] = ("stun:stun.l.google.com:19302",)) -> Media:
        """Grab one frame of what the camera sees right now, through Ring's WHEP (WebRTC) live view.

        The session is set up over HTTPS (an SDP offer POSTed to the WHEP endpoint, 201 with the answer and a
        Location to close it); the video then arrives over WebRTC. Use this where the RTSPS bridge's port 322 is
        unreachable. Needs the optional ``aiortc`` package. ``skip`` decoded frames are dropped first, since a
        stream can start on a half-drawn picture. The session is always closed, so it doesn't count against the
        device's session limit (30 s on battery, 60 s on line power).
        """
        try:
            import av
            from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription
        except ImportError as exc:
            raise RingAPIError(0, "WebRTC live view needs the aiortc package") from exc
        pc = RTCPeerConnection(RTCConfiguration([RTCIceServer(url) for url in ice_servers]))
        loop = asyncio.get_running_loop()
        frame_ready: asyncio.Future = loop.create_future()

        @pc.on("track")
        def on_track(track):  # attached before the offer, as Ring's docs require
            if track.kind != "video":
                return

            async def pump():
                seen = 0
                try:
                    while not frame_ready.done():
                        frame = await track.recv()
                        seen += 1
                        if seen > skip:
                            frame_ready.set_result(frame)
                except Exception as exc:  # the track ends when the session closes
                    if not frame_ready.done():
                        frame_ready.set_exception(RingAPIError(0, f"live view stream ended: {exc}"))
            asyncio.ensure_future(pump())

        session_url = None
        try:
            pc.addTransceiver("video", direction="recvonly")
            await pc.setLocalDescription(await pc.createOffer())  # aiortc gathers every ICE candidate here
            path = f"/v1/devices/{device_id}/media/streaming/whep/sessions"
            params = {"component_id": str(component_id)} if component_id is not None else None
            for attempt in (0, 1):
                resp = await self._http.post(f"{self.base_url}{path}", params=params,
                                             content=pc.localDescription.sdp.encode(),
                                             headers={"Authorization": f"Bearer {await self._bearer(force_refresh=attempt == 1)}",
                                                      "Content-Type": "application/sdp"})
                if resp.status_code == 401 and attempt == 0 and not isinstance(self._token, str):
                    continue
                break
            if resp.status_code != 201:
                raise RingAPIError(resp.status_code, f"WHEP session refused: {_error_message(resp)}",
                                   resp.headers.get("x-request-id"))
            session_url = resp.headers.get("location")
            await pc.setRemoteDescription(RTCSessionDescription(sdp=resp.text, type="answer"))
            try:
                frame = await asyncio.wait_for(frame_ready, timeout)
            except asyncio.TimeoutError:
                raise RingAPIError(504, f"WebRTC live view gave no frame within {timeout:.0f} s "
                                        f"(connection {pc.connectionState})")
            encoder = av.CodecContext.create("mjpeg", "w")
            encoder.width, encoder.height, encoder.pix_fmt = frame.width, frame.height, "yuvj420p"
            encoder.options = {"q:v": "3"}
            packets = encoder.encode(frame.reformat(format="yuvj420p")) + encoder.encode(None)
            return Media(content=b"".join(bytes(p) for p in packets), content_type="image/jpeg",
                         media_timestamp_ms=int(time.time() * 1000), origin="live")
        finally:
            if session_url:
                try:
                    await self._http.delete(session_url, headers={"Authorization": f"Bearer {await self._bearer()}"})
                except httpx.HTTPError:
                    pass
            await pc.close()

    async def play_chime(self, device_id: str, audio_ref: str) -> dict[str, Any]:
        """Play one of the app's chime audio slots (needs the Chime Controls scope)."""
        resp = await self._request("POST", f"/v1/devices/{device_id}/media/audio/playback",
                                   json={"audio_ref": audio_ref})
        return resp.json() if resp.content else {}

    async def aclose(self) -> None:
        await self._http.aclose()


def _rtsp_status(ffmpeg_stderr: str) -> int:
    """Pull the RTSP status (401, 403, 404, 461, 503…) out of FFmpeg's error output, 0 if there is none."""
    m = re.search(r"\b(4\d\d|5\d\d)\b", ffmpeg_stderr)
    return int(m.group(1)) if m else 0


def _error_message(resp: httpx.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300] or resp.reason_phrase
    errors = body.get("errors") if isinstance(body, dict) else None
    if errors and isinstance(errors, list):
        first = errors[0]
        return first.get("detail") or first.get("title") or str(first)
    return str(body)[:300]
