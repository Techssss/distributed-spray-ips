"""Load and replay labeled synthetic authentication fixtures against SprayDetector."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from detector import SprayDetector

FIXTURES_DIR = Path(__file__).resolve().parent
ALLOWED_RECORD_KEYS = {"event", "timestamp", "ip", "account", "surface"}


def _parse_iso_ms(ts: str) -> int:
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1000)


def load_fixture(name: str) -> list[dict[str, Any]]:
    """Load a .jsonl fixture by scenario name (without extension)."""
    path = FIXTURES_DIR / f"{name}.jsonl"
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        records.append(json.loads(line))
    return records


def load_expected_outcomes() -> dict[str, Any]:
    """Load expected detector outcomes for all scenarios."""
    path = FIXTURES_DIR / "expected_outcomes.json"
    return json.loads(path.read_text(encoding="utf-8"))


def replay_fixture(name: str, *, window: int = 60, threshold: int = 5) -> dict[str, Any]:
    """Replay a labeled fixture through SprayDetector and summarize signals."""
    records = load_fixture(name)
    if not records:
        raise ValueError(f"Fixture '{name}' is empty")

    base_ms = _parse_iso_ms(records[0]["timestamp"])
    current_ms = 0
    detector = SprayDetector(window=window, threshold=threshold, clock=lambda: current_ms / 1000.0)

    first_graph_alert_at: int | None = None
    first_graph_alert_ms: int | None = None
    ip_alert = False
    account_alert = False
    latest_signals: dict[str, Any] = {}

    for idx, rec in enumerate(records, 1):
        current_ms = _parse_iso_ms(rec["timestamp"]) - base_ms
        detector.record_failure(rec["ip"], rec["account"], rec["surface"])
        latest_signals = detector.signals()
        if latest_signals["ip_threshold"]:
            ip_alert = True
        if latest_signals["account_threshold"]:
            account_alert = True
        if latest_signals["campaigns"] and first_graph_alert_at is None:
            first_graph_alert_at = idx
            first_graph_alert_ms = current_ms

    campaigns = [asdict(c) for c in latest_signals.get("campaigns", [])]
    return {
        "scenario": name,
        "events": len(records),
        "ip_alert": ip_alert,
        "account_alert": account_alert,
        "ip_threshold": latest_signals.get("ip_threshold", []),
        "account_threshold": latest_signals.get("account_threshold", []),
        "campaign_count": len(campaigns),
        "campaigns": campaigns,
        "first_graph_alert_at": first_graph_alert_at,
        "simulated_alert_ms": first_graph_alert_ms,
    }


if __name__ == "__main__":
    summary = {
        name: replay_fixture(name)
        for name in ("single_source", "distributed_spray", "control_disjoint")
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
