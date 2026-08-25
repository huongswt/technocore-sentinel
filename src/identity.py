from __future__ import annotations

import base64
import hashlib
import os
import re
import unicodedata
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

MULTICODEC_ED25519 = b"\xed\x01"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
INVISIBLE_CATEGORIES = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")
NONCE_RE = re.compile(r"^[0-9]{1,19}$")


def sweep(text: str, limit: int = 4096) -> str:
    """Mirror Technocore's canonical single-line sweep before signing."""
    cleaned = "".join(
        " " if unicodedata.category(c) in INVISIBLE_CATEGORIES else c for c in text
    ).strip()
    if not cleaned:
        raise ValueError("nothing visible remains after Technocore single-line sweep")
    if len(cleaned) > limit:
        raise ValueError(f"text exceeds Technocore limit ({len(cleaned)} > {limit})")
    return cleaned


def _base58btc(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    leading_zeroes = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * leading_zeroes + (out or "1")


def load_private_key(seed_value: str | None = None) -> Ed25519PrivateKey:
    """Load key using the same convention as Technocore's official scripts/sign.py.

    * 64 hexadecimal characters -> raw 32-byte Ed25519 seed.
    * any other string -> SHA-256(string) used as the 32-byte seed.

    The function intentionally never logs or returns the original secret.
    """
    given = seed_value if seed_value is not None else os.getenv("SIGN_SEED")
    if not given:
        raise ValueError("SIGN_SEED is not configured")
    if len(given) == 64:
        try:
            return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(given))
        except ValueError:
            pass
    digest = hashlib.sha256(given.encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(digest)


def did_of(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes_raw()
    return "did:key:z" + _base58btc(MULTICODEC_ED25519 + raw)


def sign_message(key: Ed25519PrivateKey, room: str, nonce: str, text: str) -> tuple[str, str]:
    if not NONCE_RE.fullmatch(nonce):
        raise ValueError("nonce must contain 1-19 ASCII digits")
    clean = sweep(text, 4096)
    canonical = f"{room}|{nonce}|{clean}"
    sig = key.sign(canonical.encode("utf-8"))
    return clean, base64.urlsafe_b64encode(sig).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class IdentityCheck:
    configured_did: str
    derived_did: str
    matches: bool


def verify_identity(configured_did: str, seed_value: str | None = None) -> IdentityCheck:
    key = load_private_key(seed_value)
    derived = did_of(key)
    return IdentityCheck(configured_did=configured_did, derived_did=derived, matches=derived == configured_did)
