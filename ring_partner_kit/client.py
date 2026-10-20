"""Async client for the Ring Partner (Amazon Vision) API.

Covers OAuth token exchange and refresh, device discovery, event history, snapshot and clip downloads,
chime playback and the App-Integrations calls used during account linking. Every call is
server-to-server: the API blocks browser requests with CORS.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

API_BASE = "https://api.amazonvision.com"
OAUTH_TOKEN_URL = "https://oauth.ring.com/oauth/token"

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
                 http: httpx.AsyncClient | None = None, max_retries: int = 3):
        self._token = token
        self.base_url = base_url.rstrip("/")
        self._http = http or httpx.AsyncClient(timeout=30)
        self.max_retries = max_retries

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

    async def play_chime(self, device_id: str, audio_ref: str) -> dict[str, Any]:
        """Play one of the app's chime audio slots (needs the Chime Controls scope)."""
        resp = await self._request("POST", f"/v1/devices/{device_id}/media/audio/playback",
                                   json={"audio_ref": audio_ref})
        return resp.json() if resp.content else {}

    async def aclose(self) -> None:
        await self._http.aclose()


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
