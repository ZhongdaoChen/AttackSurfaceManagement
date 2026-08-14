from __future__ import annotations

import datetime
from typing import Any

import pandas as pd


def current_kpis(
    rows: list[dict[str, Any]],
    latest_scan_id: str | None,
    resolved_latest_scan: int = 0,
) -> dict[str, int]:
    return {
        "active_findings": len(rows),
        "active_high": sum(1 for row in rows if str(row.get("risk_level") or "").lower() == "high"),
        "new_latest_scan": sum(1 for row in rows if latest_scan_id and row.get("first_seen_scan_id") == latest_scan_id),
        "resolved_latest_scan": int(resolved_latest_scan),
        "sensitive_exposure_80_443": sum(
            1
            for row in rows
            if row.get("check_id") == "llm_sensitive_content" and row.get("port") in (80, 443)
        ),
        "current_non_standard_ports": sum(1 for row in rows if row.get("check_id") == "non_standard_open_port"),
    }


def _as_date(value: Any) -> datetime.date | None:
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        return value.date()
    if isinstance(value, datetime.date):
        return value
    text = str(value)
    try:
        return datetime.datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def trend_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    events: list[dict[str, Any]] = []
    for row in rows:
        first_seen = _as_date(row.get("first_seen_at"))
        resolved = _as_date(row.get("resolved_at"))
        if first_seen is not None:
            events.append({"date": first_seen, "metric": "New", "count": 1})
            if str(row.get("risk_level") or "").lower() == "high":
                events.append({"date": first_seen, "metric": "New High", "count": 1})
            if row.get("check_id") == "non_standard_open_port":
                events.append({"date": first_seen, "metric": "Non-standard Port", "count": 1})
            if row.get("check_id") == "llm_sensitive_content" and row.get("port") in (80, 443):
                events.append({"date": first_seen, "metric": "Sensitive Exposure 80/443", "count": 1})
        if resolved is not None:
            events.append({"date": resolved, "metric": "Resolved", "count": 1})
    if not events:
        return pd.DataFrame(columns=["date", "metric", "count"])
    return pd.DataFrame(events).groupby(["date", "metric"], as_index=False)["count"].sum()


def distribution(rows: list[dict[str, Any]], key: str, limit: int = 10) -> pd.DataFrame:
    counts: dict[Any, int] = {}
    for row in rows:
        value = row.get(key)
        if value in (None, ""):
            continue
        counts[value] = counts.get(value, 0) + 1
    records = [{key: value, "count": count} for value, count in counts.items()]
    records.sort(key=lambda item: (-item["count"], str(item[key])))
    return pd.DataFrame(records[:limit], columns=[key, "count"])


def endpoint_link(endpoint_name: Any) -> str:
    text = str(endpoint_name or "").strip()
    if text.startswith(("http://", "https://")):
        return f"[{text}]({text})"
    return text
