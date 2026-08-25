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
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")


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


def _key_from_value(given: str) -> Ed25519PrivateKey:
    """Technocore official signer convention for one interpreted secret value."""
    if HEX64_RE.fullmatch(given):
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(given))
    digest = hashlib.sha256(given.encode("utf-8")).digest()
    return Ed25519PrivateKey.from_private_bytes(digest)


def _secret() -> str:
    given = os.getenv("SIGN_SEED")
    if not given:
        raise ValueError("SIGN_SEED is not configured")
    return given


def load_private_key(seed_value: str | None = None) -> Ed25519PrivateKey:
    """Load the secret exactly as configured, using Technocore's official convention."""
    given = seed_value if seed_value is not None else _secret()
    if not given:
        raise ValueError("SIGN_SEED is not configured")
    return _key_from_value(given)


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


def _candidate_values(given: str) -> list[tuple[str, str]]:
    """Try only conservative CMD/GitHub-entry normalizations.

    These cover common copy/paste mistakes without inventing a new cryptographic
    derivation scheme. The secret values themselves are never returned publicly.
    """
    raw: list[tuple[str, str]] = [("official_exact", given)]

    stripped = given.strip()
    if stripped != given and stripped:
        raw.append(("trim_outer_whitespace", stripped))

    for source_name, source in (("exact", given), ("trimmed", stripped)):
        if len(source) >= 2 and source[0] == source[-1] and source[0] in {'"', "'"}:
            inner = source[1:-1]
            if inner:
                raw.append((f"unwrap_quotes_from_{source_name}", inner))

    for source_name, source in (("exact", given), ("trimmed", stripped)):
        if source.lower().startswith("0x") and HEX64_RE.fullmatch(source[2:]):
            raw.append((f"strip_0x_prefix_from_{source_name}", source[2:]))

        compact = "".join(ch for ch in source if not ch.isspace())
        if compact != source and HEX64_RE.fullmatch(compact):
            raw.append((f"compact_hex_whitespace_from_{source_name}", compact))

    # Deduplicate by interpreted secret value while keeping the first/best label.
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for method, value in raw:
        if value not in seen:
            seen.add(value)
            out.append((method, value))
    return out


@dataclass(frozen=True)
class IdentityCandidate:
    method: str
    derived_did: str
    matches: bool


@dataclass(frozen=True)
class IdentityResolution:
    method: str
    derived_did: str
    key: Ed25519PrivateKey


def diagnose_identity(configured_did: str, seed_value: str | None = None) -> list[IdentityCandidate]:
    given = seed_value if seed_value is not None else _secret()
    candidates: list[IdentityCandidate] = []
    for method, value in _candidate_values(given):
        key = _key_from_value(value)
        derived = did_of(key)
        candidates.append(
            IdentityCandidate(method=method, derived_did=derived, matches=derived == configured_did)
        )
    return candidates


def resolve_private_key(configured_did: str, seed_value: str | None = None) -> IdentityResolution:
    """Resolve the configured DID using safe input-normalization candidates only."""
    given = seed_value if seed_value is not None else _secret()
    for method, value in _candidate_values(given):
        key = _key_from_value(value)
        derived = did_of(key)
        if derived == configured_did:
            return IdentityResolution(method=method, derived_did=derived, key=key)
    raise RuntimeError(
        "No safe CMD/GitHub secret normalization matches TECHNOCORE_DID. "
        "The original DID may have been created from a different random seed."
    )
