from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict

from .identity import did_of, load_private_key, sign_message

DEFAULT_BASE_URL = "https://technocore.chat"
USER_AGENT = "technocore-sentinel/1.0 (+github-monitor)"


@dataclass
class ProbeResult:
    name: str
    path: str
    ok: bool
    status_code: int | None
    latency_ms: int
    error: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def _request_text(url: str, timeout: float = 10.0) -> tuple[int, str, int]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(65536).decode("utf-8", errors="replace")
            elapsed = round((time.perf_counter() - started) * 1000)
            return response.status, body, elapsed
    except urllib.error.HTTPError as exc:
        elapsed = round((time.perf_counter() - started) * 1000)
        body = exc.read(65536).decode("utf-8", errors="replace")
        return exc.code, body, elapsed


def probe(base_url: str, name: str, path: str, timeout: float = 10.0) -> ProbeResult:
    url = base_url.rstrip("/") + path
    started = time.perf_counter()
    try:
        status, _body, elapsed = _request_text(url, timeout=timeout)
        return ProbeResult(name=name, path=path, ok=200 <= status < 300, status_code=status, latency_ms=elapsed)
    except Exception as exc:
        elapsed = round((time.perf_counter() - started) * 1000)
        return ProbeResult(name=name, path=path, ok=False, status_code=None, latency_ms=elapsed, error=f"{type(exc).__name__}: {exc}")


def post_signed_message(
    *,
    base_url: str,
    room: str,
    did: str,
    nonce: str,
    text: str,
    timeout: float = 10.0,
) -> dict:
    key = load_private_key()
    derived_did = did_of(key)
    if derived_did != did:
        raise RuntimeError(
            "Configured TECHNOCORE_DID does not match the DID derived from SIGN_SEED. "
            "Refusing to sign or publish."
        )

    clean, signature = sign_message(key, room, nonce, text)
    q = urllib.parse.quote
    path = "/r/{room}/say-signed/{did}/{sig}/{nonce}/{text}".format(
        room=q(room, safe=""),
        did=q(did, safe=""),
        sig=q(signature, safe=""),
        nonce=q(nonce, safe=""),
        text=q(clean, safe=""),
    )
    url = base_url.rstrip("/") + path
    status, body, latency = _request_text(url, timeout=timeout)
    if not (200 <= status < 300):
        raise RuntimeError(f"Technocore signed post failed: HTTP {status}: {body[:500]}")

    parsed: dict | None = None
    try:
        parsed = json.loads(body)
    except Exception:
        pass
    return {
        "ok": True,
        "status_code": status,
        "latency_ms": latency,
        "room": room,
        "did": did,
        "response": parsed if parsed is not None else body[:1000],
    }
