from __future__ import annotations

import datetime
from typing import Any

import pandas as pd


def current_kpis(
    rows: list[dict[str, Any]],
    newly_identified_since: datetime.date,
    resolved_this_quarter: int = 0,
) -> dict[str, int]:
    active_rows = [row for row in rows if not bool(row.get("whitelisted"))]
    return {
        "active_findings": len(active_rows),
        "active_high": sum(1 for row in active_rows if str(row.get("risk_level") or "").lower() == "high"),
        "newly_identified_this_month": sum(
            1
            for row in active_rows
            if (first_seen := _as_date(row.get("first_seen_at"))) is not None and first_seen >= newly_identified_since
        ),
        "resolved_this_quarter": int(resolved_this_quarter),
        "sensitive_exposure_80_443": sum(
            1
            for row in active_rows
            if str(row.get("risk_level") or "").lower() == "high"
            and row.get("check_id") == "llm_sensitive_content"
            and row.get("port") in (80, 443)
        ),
        "current_non_standard_ports": sum(1 for row in active_rows if row.get("check_id") == "non_standard_open_port"),
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
    records: list[dict[str, Any]] = []
    for row in rows:
        scan_date = _as_date(row.get("scan_started_at"))
        if scan_date is None:
            continue
        high_risk_count = int(row.get("high_risk_count") or 0)
        mitigated_count = int(row.get("mitigated_count") or 0)
        records.append(
            {
                "date": scan_date,
                "scan_id": row.get("scan_id"),
                "metric": "High Risk",
                "count": max(0, high_risk_count - mitigated_count),
            }
        )
        records.append(
            {
                "date": scan_date,
                "scan_id": row.get("scan_id"),
                "metric": "Mitigated",
                "count": mitigated_count,
            }
        )
    if not records:
        return pd.DataFrame(columns=["date", "scan_id", "metric", "count"])
    return pd.DataFrame(records, columns=["date", "scan_id", "metric", "count"])


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


def markdown_link(label: Any, url: Any) -> str:
    text = str(label or "").strip()
    href = str(url or "").strip()
    if not text or not href:
        return ""
    escaped = text.replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]").replace("(", "\\(").replace(")", "\\)")
    return f"[{escaped}]({href})"


def endpoint_link(endpoint_name: Any) -> str:
    text = str(endpoint_name or "").strip()
    if text.startswith(("http://", "https://")):
        return markdown_link(text, text)
    return text


def wiz_link(wiz_url: Any) -> str:
    return markdown_link("Wiz Link", wiz_url)
