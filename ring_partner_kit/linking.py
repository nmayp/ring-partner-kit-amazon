"""One-way (Ring-driven) account linking helpers.

Ring releases OAuth tokens to the partner's Token Exchange URL before the partner knows which of its
users they belong to. It then redirects the user's browser to the Account Link URL with
``?nonce=...&time=...`` where ``nonce = base64url(HMAC-SHA256(key, f"{time}:{account_id}"))`` without
padding. After the user signs in, the partner recomputes the nonce for each unclaimed token's account ID
and claims the one that matches.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import time
from collections.abc import Iterable
from typing import TypeVar

VALIDATION_WINDOW_SECONDS = 600

T = TypeVar("T")


class LinkError(ValueError):
    """The account-link redirect is expired, malformed or does not match any token."""


def compute_nonce(time_param: str | int, account_id: str, signing_key: str) -> str:
    payload = f"{time_param}:{account_id}".encode()
    mac = hmac.new(signing_key.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).rstrip(b"=").decode()


def check_freshness(time_param: str | int, now_ms: int | None = None,
                    window_seconds: int = VALIDATION_WINDOW_SECONDS) -> None:
    """Raise :class:`LinkError` unless ``time_param`` (epoch ms) is within the validation window."""
    try:
        sent_ms = int(time_param)
    except (TypeError, ValueError) as exc:
        raise LinkError("time parameter is not an integer") from exc
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    delta = (now_ms - sent_ms) / 1000
    if delta < 0:
        raise LinkError("link timestamp is in the future")
    if delta > window_seconds:
        raise LinkError("link request expired")


def match_nonce(nonce: str, time_param: str | int, candidates: Iterable[T], signing_key: str,
                account_id_of=lambda c: c) -> T | None:
    """Return the candidate whose account ID reproduces ``nonce``, or ``None``.

    ``candidates`` are usually unclaimed token records; ``account_id_of`` extracts the Ring account ID.
    """
    for candidate in candidates:
        expected = compute_nonce(time_param, account_id_of(candidate), signing_key)
        if hmac.compare_digest(expected, nonce):
            return candidate
    return None


def mask_email(email: str) -> str:
    """Mask an email the way Ring's examples do (``u***r@example.com``) for ``account_identifier``."""
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    if len(local) <= 2:
        masked = local[:1] + "***"
    else:
        masked = f"{local[0]}***{local[-1]}"
    return f"{masked}@{domain}"
