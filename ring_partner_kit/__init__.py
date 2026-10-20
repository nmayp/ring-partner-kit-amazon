"""ring-partner-kit: a small, typed toolkit for the Ring Partner (Amazon Vision) API."""
from .client import API_BASE, OAUTH_TOKEN_URL, Media, RingAPIError, RingClient, RingOAuth, TokenManager, TokenSet
from .linking import LinkError, check_freshness, compute_nonce, mask_email, match_nonce
from .simulator import build_event, signed_delivery
from .webhooks import RingEvent, WebhookError, parse_event, sign, verify_signature

__all__ = [
    "API_BASE", "OAUTH_TOKEN_URL", "Media", "RingAPIError", "RingClient", "RingOAuth", "TokenManager",
    "TokenSet", "LinkError", "check_freshness", "compute_nonce", "mask_email", "match_nonce",
    "build_event", "signed_delivery", "RingEvent", "WebhookError", "parse_event", "sign",
    "verify_signature",
]
__version__ = "0.1.0"
