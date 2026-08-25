from __future__ import annotations

import json
import os
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path

from .identity import diagnose_identity
from .technocore import DEFAULT_BASE_URL, post_signed_message, probe

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
LATEST = DATA_DIR / "latest.json"
HISTORY = DATA_DIR / "history.jsonl"


def env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def load_previous() -> dict | None:
    if not LATEST.exists():
        return None
    try:
        return json.loads(LATEST.read_text(encoding="utf-8"))
    except Exception:
        return None


def check_endpoint(base_url: str, name: str, path: str, samples: int = 2) -> dict:
    results = []
    for idx in range(samples):
        results.append(probe(base_url, name, path).to_dict())
        if idx + 1 < samples:
            time.sleep(0.25)
    good_latencies = [r["latency_ms"] for r in results if r["ok"]]
    return {
        "name": name,
        "path": path,
        "ok": all(r["ok"] for r in results),
        "status_codes": [r["status_code"] for r in results],
        "latency_ms_median": round(statistics.median(good_latencies)) if good_latencies else None,
        "samples": results,
    }


def overall_status(checks: list[dict]) -> str:
    health = next((c for c in checks if c["name"] == "healthz"), None)
    if not health or not health["ok"]:
        return "down"
    if all(c["ok"] for c in checks):
        return "operational"
    return "degraded"


def make_public_summary(report: dict) -> str:
    latency = {c["name"]: c["latency_ms_median"] for c in report["checks"]}
    repo = os.getenv("GITHUB_REPOSITORY", "local/technocore-sentinel")
    return (
        "Technocore Sentinel | "
        f"status={report['status'].upper()} | "
        f"healthz={latency.get('healthz')}ms | "
        f"lobby={latency.get('lobby')}ms | "
        f"manual={latency.get('manual')}ms | "
        f"checked={report['checked_at']} | "
        f"source=https://github.com/{repo}"
    )


def append_history(report: dict, max_lines: int = 500) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    rows: list[str] = []
    if HISTORY.exists():
        rows = HISTORY.read_text(encoding="utf-8").splitlines()
    compact = {
        "checked_at": report["checked_at"],
        "status": report["status"],
        "latency_ms": {c["name"]: c["latency_ms_median"] for c in report["checks"]},
    }
    rows.append(json.dumps(compact, separators=(",", ":"), ensure_ascii=False))
    rows = rows[-max_lines:]
    HISTORY.write_text("\n".join(rows) + "\n", encoding="utf-8")


def main() -> None:
    base_url = os.getenv("TECHNOCORE_BASE_URL", DEFAULT_BASE_URL).rstrip("/")
    samples = max(1, min(5, int(os.getenv("PROBE_SAMPLES", "2"))))
    previous = load_previous()

    checks = [
        check_endpoint(base_url, "healthz", "/healthz", samples),
        check_endpoint(base_url, "lobby", "/r/lobby?limit=1&format=json", samples),
        check_endpoint(base_url, "manual", "/llms.txt", samples),
    ]
    status = overall_status(checks)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    previous_status = previous.get("status") if previous else None

    enabled = env_bool("ENABLE_TECHNOCORE_POST", False)
    did = (os.getenv("TECHNOCORE_DID") or "").strip()
    seed_present = bool(os.getenv("SIGN_SEED"))
    room = (os.getenv("TECHNOCORE_ROOM") or "sentinel-huongswt").strip().lower()

    diagnostics: list[dict] = []
    matched_method: str | None = None
    if seed_present and did:
        try:
            for item in diagnose_identity(did):
                diagnostics.append({
                    "method": item.method,
                    "derived_did": item.derived_did,
                    "matches": item.matches,
                })
                if item.matches and matched_method is None:
                    matched_method = item.method
        except Exception as exc:
            diagnostics = [{"method": "diagnostic_error", "error": str(exc), "matches": False}]

    report = {
        "service": "technocore.chat",
        "base_url": base_url,
        "status": status,
        "checked_at": now,
        "previous_status": previous_status,
        "status_changed": previous_status is not None and previous_status != status,
        "checks": checks,
        "agent_did": did or None,
        "identity_diagnostics": diagnostics,
        "identity_match_method": matched_method,
        "signed_publish": {"attempted": False},
    }

    if enabled:
        report["signed_publish"]["attempted"] = True
        if not did:
            report["signed_publish"] = {"attempted": True, "ok": False, "error": "TECHNOCORE_DID is missing"}
        elif not seed_present:
            report["signed_publish"] = {"attempted": True, "ok": False, "error": "SIGN_SEED secret is missing"}
        elif not matched_method:
            report["signed_publish"] = {
                "attempted": True,
                "ok": False,
                "error": "No safe secret normalization matches configured DID; no message was signed or published",
            }
        else:
            try:
                nonce = str(int(time.time() * 1000))
                result = post_signed_message(
                    base_url=base_url,
                    room=room,
                    did=did,
                    nonce=nonce,
                    text=make_public_summary(report),
                )
                report["signed_publish"] = {"attempted": True, **result, "nonce": nonce}
            except Exception as exc:
                report["signed_publish"] = {"attempted": True, "ok": False, "error": str(exc)}

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LATEST.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    append_history(report)

    print(json.dumps(report, indent=2, ensure_ascii=False))
    if status == "down":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
