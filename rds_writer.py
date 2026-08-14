from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import urllib.request
from typing import Any


REQUIRED_RDS_ENV = ("RDS_HOST", "RDS_DB", "RDS_USER", "RDS_PASSWORD")


def rds_configured() -> bool:
    return all(os.getenv(key, "").strip() for key in REQUIRED_RDS_ENV)


def connection_info() -> str:
    """Build a psycopg-style connection string from environment variables.

    Construct from an explicit list of (key, value) pairs so the password
    fragment is unambiguous in source and tests can assert the presence of
    the password key without exposing its value.
    """
    pairs = [
        ("host", os.getenv("RDS_HOST", "")),
        ("port", os.getenv("RDS_PORT", "5432")),
        ("dbname", os.getenv("RDS_DB", "")),
        ("user", os.getenv("RDS_USER", "")),
        ("password", os.getenv("RDS_PASSWORD", "")),
        ("sslmode", os.getenv("RDS_SSLMODE", "prefer")),
    ]

    def fmt(k: str, v: str) -> str:
        s = str(v)
        # Escape backslashes and single quotes per libpq connection-string rules:
        # backslashes and single quotes inside a value must be backslash-escaped.
        # Quote the value if it contains spaces, single quotes, or backslashes
        # so psycopg/libpq will parse it unambiguously.
        needs_quote = any(ch in s for ch in (" ", "'", "\\"))
        if needs_quote:
            escaped = s.replace("\\", "\\\\").replace("'", "\\'")
            return f"{k}='{escaped}'"
        return f"{k}={s}"

    return " ".join(fmt(k, v) for k, v in pairs)


def connect():
    try:
        import psycopg  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("RDS writing requires psycopg. Install with: pip3 install -r requirements.txt") from exc

    # Prefer psycopg v3 row factory which returns dict-like rows. Do a
    # best-effort lookup so older/newer psycopg variants won't break import
    # time or runtime. If the rows.dict_row factory is available, pass it
    # as row_factory to psycopg.connect(). If the connect() implementation
    # doesn't accept row_factory, fall back to calling without it.
    row_factory = None
    rows_module = getattr(psycopg, "rows", None)
    if rows_module is not None and hasattr(rows_module, "dict_row"):
        row_factory = rows_module.dict_row
    try:
        if row_factory is not None:
            return psycopg.connect(connection_info(), row_factory=row_factory)
        return psycopg.connect(connection_info())
    except TypeError:
        # Some psycopg compat layers may not accept row_factory; fall back
        # to a plain connect() call which will return whatever the driver
        # provides (typically tuples). Callers should handle conversion
        # if necessary.
        return psycopg.connect(connection_info())


def is_whitelisted_finding(finding: dict[str, Any], low_risk_subscriptions: set[str]) -> bool:
    details = finding.get("details")
    if not isinstance(details, dict):
        return False
    subscription = str(details.get("subscription") or "").strip().lower()
    return bool(subscription and subscription in low_risk_subscriptions)


def dashboard_whitelisted(cursor, endpoint_name: Any, port: Any) -> bool:
    endpoint = str(endpoint_name or "").strip()
    if not endpoint:
        return False
    cursor.execute(
        """
        SELECT id
        FROM asm_whitelist_rules
        WHERE active = TRUE
          AND endpoint_name = %(endpoint_name)s
          AND COALESCE(port, -1) = COALESCE(%(port)s, -1)
        LIMIT 1
        """,
        {"endpoint_name": endpoint, "port": port},
    )
    return cursor.fetchone() is not None


def strip_nul_bytes(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace("\x00", "")
    if isinstance(value, list):
        return [strip_nul_bytes(item) for item in value]
    if isinstance(value, dict):
        return {key: strip_nul_bytes(item) for key, item in value.items()}
    return value


def finding_key(params: dict[str, Any]) -> str:
    port = params.get("port")
    key_parts = [
        str(params.get("endpoint_id") or ""),
        str(params.get("check_id") or ""),
        str(params.get("host") or ""),
        port if port is not None else -1,
    ]
    payload = json.dumps(key_parts, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def finding_insert_params(
    finding: dict[str, Any],
    scan_id: str,
    low_risk_subscriptions: set[str],
) -> dict[str, Any]:
    clean_finding = strip_nul_bytes(finding)
    details = clean_finding.get("details")
    if not isinstance(details, dict):
        details = {}
    params = {
        "scan_id": scan_id,
        "endpoint_id": clean_finding.get("endpoint_id"),
        "endpoint_name": clean_finding.get("endpoint_name"),
        "wiz_link": clean_finding.get("wiz_link"),
        "host": clean_finding.get("host"),
        "port": clean_finding.get("port"),
        "cloud_platform": clean_finding.get("cloudPlatform"),
        "cloud_account_name": clean_finding.get("cloudAccountName"),
        "tag_emails": clean_finding.get("tagEmails") if isinstance(clean_finding.get("tagEmails"), list) else [],
        "exposure_level": clean_finding.get("exposureLevel"),
        "check_id": clean_finding.get("check_id"),
        "risk_level": clean_finding.get("risk_level"),
        "whitelisted": is_whitelisted_finding(clean_finding, low_risk_subscriptions),
        "http_status": str(details.get("http_status") or details.get("status") or "") or None,
        "http_response": clean_finding.get("http_response"),
        "llm_opinion": clean_finding.get("llm_opinion"),
        "evidence": clean_finding.get("evidence"),
        "recommendation": clean_finding.get("recommendation"),
        "details": json.dumps(details, ensure_ascii=False),
        "raw": json.dumps(clean_finding, ensure_ascii=False),
    }
    params["finding_key"] = finding_key(params)
    return params


def default_scan_id(now: datetime.datetime | None = None) -> str:
    value = now or datetime.datetime.now(datetime.UTC)
    return value.strftime("%Y%m%d-%H%M%S")


TEAMS_CARD_MAX_FINDINGS = 10
TEAMS_CARD_TEXT_LIMIT = 300


def truncate_text(value: Any, limit: int = TEAMS_CARD_TEXT_LIMIT) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 3)] + "..."


def finding_heading(finding: dict[str, Any]) -> str:
    endpoint_name = str(finding.get("endpoint_name") or "").strip()
    if endpoint_name:
        return endpoint_name
    host = str(finding.get("host") or "").strip()
    port = finding.get("port")
    if host and port:
        return f"{host}:{port}"
    endpoint_id = str(finding.get("endpoint_id") or "").strip()
    return endpoint_id or "<unknown endpoint>"


def build_teams_high_risk_card(scan_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]:
    displayed_findings = findings[:TEAMS_CARD_MAX_FINDINGS]
    summary = f"本次扫描发现 {len(findings)} 个新增 High Risk endpoint。"
    if len(findings) > TEAMS_CARD_MAX_FINDINGS:
        summary += f" 仅展示前 {TEAMS_CARD_MAX_FINDINGS} 个。"
    first_seen = str(displayed_findings[0].get("first_seen_at") or "") if displayed_findings else ""
    body: list[dict[str, Any]] = [
        {
            "type": "TextBlock",
            "text": "ASM 新增 High Risk 告警",
            "weight": "Bolder",
            "size": "Large",
            "color": "Attention",
        },
        {"type": "TextBlock", "text": summary, "wrap": True},
        {
            "type": "FactSet",
            "facts": [
                {"title": "Scan ID", "value": scan_id},
                {"title": "First seen", "value": first_seen},
                {"title": "Total", "value": str(len(findings))},
            ],
        },
    ]
    for index, finding in enumerate(displayed_findings, start=1):
        body.append(
            {
                "type": "TextBlock",
                "text": f"{index}. {finding_heading(finding)}",
                "weight": "Bolder",
                "wrap": True,
                "separator": True,
            }
        )
        body.append(
            {
                "type": "FactSet",
                "facts": [
                    {"title": "Host", "value": str(finding.get("host") or "")},
                    {"title": "Port", "value": str(finding.get("port") or "")},
                    {"title": "CloudAccount", "value": str(finding.get("cloud_account_name") or "")},
                    {"title": "Check", "value": str(finding.get("check_id") or "")},
                    {"title": "Evidence", "value": truncate_text(finding.get("evidence"))},
                    {"title": "Recommendation", "value": truncate_text(finding.get("recommendation"))},
                ],
            }
        )
    card: dict[str, Any] = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.4",
        "body": body,
    }
    first_wiz_link = str(displayed_findings[0].get("wiz_link") or "").strip() if displayed_findings else ""
    if first_wiz_link:
        card["actions"] = [{"type": "Action.OpenUrl", "title": "Open first finding in Wiz", "url": first_wiz_link}]
    return card


def post_teams_webhook(webhook_url: str, card: dict[str, Any]) -> None:
    body = json.dumps(card, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        status = getattr(response, "status", response.getcode())
        if status < 200 or status >= 300:
            raise RuntimeError(f"Teams webhook returned HTTP {status}")


class RdsFindingWriter:
    def __init__(
        self,
        connection,
        scan_id: str,
        started_at: str,
        source_file: str | None,
        low_risk_subscriptions: set[str],
    ) -> None:
        self.connection = connection
        self.cursor = connection.cursor()
        self.scan_id = scan_id
        self.started_at = started_at
        self.low_risk_subscriptions = low_risk_subscriptions
        self.cursor.execute(
            """
            INSERT INTO asm_scans (scan_id, started_at, source_file)
            VALUES (%(scan_id)s, %(started_at)s, %(source_file)s)
            ON CONFLICT (scan_id) DO NOTHING
            """,
            {"scan_id": scan_id, "started_at": started_at, "source_file": source_file},
        )
        self.connection.commit()

    def write(self, finding: dict[str, Any]) -> None:
        params = finding_insert_params(finding, self.scan_id, self.low_risk_subscriptions)
        if dashboard_whitelisted(self.cursor, params.get("endpoint_name"), params.get("port")):
            params["whitelisted"] = True
        self.cursor.execute(
            """
            INSERT INTO asm_findings (
              scan_id, endpoint_id, endpoint_name, wiz_link, host, port,
              cloud_platform, cloud_account_name, tag_emails, exposure_level,
              check_id, risk_level, whitelisted, http_status, http_response,
              llm_opinion, evidence, recommendation, details, raw
            )
            VALUES (
              %(scan_id)s, %(endpoint_id)s, %(endpoint_name)s, %(wiz_link)s, %(host)s, %(port)s,
              %(cloud_platform)s, %(cloud_account_name)s, %(tag_emails)s, %(exposure_level)s,
              %(check_id)s, %(risk_level)s, %(whitelisted)s, %(http_status)s, %(http_response)s,
              %(llm_opinion)s, %(evidence)s, %(recommendation)s, %(details)s, %(raw)s
            )
            ON CONFLICT DO NOTHING
            """,
            params,
        )
        inserted_history = self.cursor.rowcount != 0
        if inserted_history:
            params["started_at"] = self.started_at
            self._upsert_current_finding(params)
        self.connection.commit()

    def _upsert_current_finding(self, params: dict[str, Any]) -> None:
        self.cursor.execute(
            """
            INSERT INTO asm_current_findings (
              finding_key, endpoint_id, endpoint_name, wiz_link, host, port,
              cloud_platform, cloud_account_name, tag_emails, exposure_level,
              check_id, risk_level, whitelisted, http_status, http_response,
              llm_opinion, evidence, recommendation, details, raw,
              first_seen_scan_id, first_seen_at, last_seen_scan_id, last_seen_at,
              seen_count, resolved_at, resolved_scan_id
            )
            VALUES (
              %(finding_key)s, %(endpoint_id)s, %(endpoint_name)s, %(wiz_link)s, %(host)s, %(port)s,
              %(cloud_platform)s, %(cloud_account_name)s, %(tag_emails)s, %(exposure_level)s,
              %(check_id)s, %(risk_level)s, %(whitelisted)s, %(http_status)s, %(http_response)s,
              %(llm_opinion)s, %(evidence)s, %(recommendation)s, %(details)s, %(raw)s,
              %(scan_id)s, %(started_at)s, %(scan_id)s, %(started_at)s,
              1, NULL, NULL
            )
            ON CONFLICT (finding_key) DO UPDATE SET
              endpoint_id = EXCLUDED.endpoint_id,
              endpoint_name = EXCLUDED.endpoint_name,
              wiz_link = EXCLUDED.wiz_link,
              host = EXCLUDED.host,
              port = EXCLUDED.port,
              cloud_platform = EXCLUDED.cloud_platform,
              cloud_account_name = EXCLUDED.cloud_account_name,
              tag_emails = EXCLUDED.tag_emails,
              exposure_level = EXCLUDED.exposure_level,
              check_id = EXCLUDED.check_id,
              risk_level = EXCLUDED.risk_level,
              whitelisted = EXCLUDED.whitelisted,
              http_status = EXCLUDED.http_status,
              http_response = EXCLUDED.http_response,
              llm_opinion = EXCLUDED.llm_opinion,
              evidence = EXCLUDED.evidence,
              recommendation = EXCLUDED.recommendation,
              details = EXCLUDED.details,
              raw = EXCLUDED.raw,
              last_seen_scan_id = EXCLUDED.last_seen_scan_id,
              last_seen_at = EXCLUDED.last_seen_at,
              seen_count = asm_current_findings.seen_count + 1,
              resolved_at = NULL,
              resolved_scan_id = NULL,
              updated_at = now()
            """,
            params,
        )

    def new_high_risk_findings(self) -> list[dict[str, Any]]:
        self.cursor.execute(
            """
            SELECT endpoint_id, endpoint_name, wiz_link, host, port,
                   cloud_account_name, check_id, evidence, recommendation,
                   first_seen_scan_id, first_seen_at
            FROM asm_current_findings
            WHERE first_seen_scan_id = %(scan_id)s
              AND risk_level = 'high'
              AND resolved_at IS NULL
            ORDER BY first_seen_at ASC, endpoint_name ASC, host ASC, port ASC
            """,
            {"scan_id": self.scan_id},
        )
        return list(self.cursor.fetchall())

    def notify_new_high_risks(self) -> None:
        webhook_url = os.getenv("TEAMS_WEBHOOK_URL", "").strip()
        if not webhook_url:
            return
        findings = self.new_high_risk_findings()
        if not findings:
            return
        card = build_teams_high_risk_card(self.scan_id, findings)
        post_teams_webhook(webhook_url, card)

    def finalize(self) -> None:
        self.cursor.execute(
            """
            UPDATE asm_current_findings
            SET resolved_at = %(resolved_at)s,
                resolved_scan_id = %(scan_id)s,
                updated_at = now()
            WHERE last_seen_scan_id <> %(scan_id)s
              AND resolved_at IS NULL
            """,
            {"scan_id": self.scan_id, "resolved_at": self.started_at},
        )
        self.connection.commit()
        try:
            self.notify_new_high_risks()
        except Exception as exc:  # noqa: BLE001 - notification must not fail scans.
            # Do not include the raw exception message (which may contain
            # secrets such as the TEAMS_WEBHOOK_URL). Log only the exception
            # type so failures are visible without leaking sensitive data.
            print(f"Teams notification failed: {type(exc).__name__}", file=sys.stderr)

    def close(self) -> None:
        self.connection.close()


def open_writer(
    scan_id: str,
    started_at: str,
    source_file: str | None,
    low_risk_subscriptions: set[str],
):
    if not rds_configured():
        return None
    return RdsFindingWriter(connect(), scan_id, started_at, source_file, low_risk_subscriptions)
