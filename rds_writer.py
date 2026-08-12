from __future__ import annotations

import datetime
import json
import os
from typing import Any


REQUIRED_RDS_ENV = ("RDS_HOST", "RDS_DB", "RDS_USER", "RDS_PASSWORD")


def rds_configured() -> bool:
    return all(os.getenv(key, "").strip() for key in REQUIRED_RDS_ENV)


def connection_info() -> str:
    return (
        f"host={os.environ['RDS_HOST']} "
        f"port={os.getenv('RDS_PORT', '5432')} "
        f"dbname={os.environ['RDS_DB']} "
        f"user={os.environ['RDS_USER']} "
        f"password={os.environ['RDS_PASSWORD']} "
        f"sslmode={os.getenv('RDS_SSLMODE', 'prefer')}"
    )


def connect():
    try:
        import psycopg  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RuntimeError("RDS writing requires psycopg. Install with: pip3 install 'psycopg[binary]'") from exc
    return psycopg.connect(connection_info())


def is_whitelisted_finding(finding: dict[str, Any], low_risk_subscriptions: set[str]) -> bool:
    details = finding.get("details")
    if not isinstance(details, dict):
        return False
    subscription = str(details.get("subscription") or "").strip().lower()
    return bool(subscription and subscription in low_risk_subscriptions)


def default_scan_id(now: datetime.datetime | None = None) -> str:
    value = now or datetime.datetime.now(datetime.UTC)
    return value.strftime("%Y%m%d-%H%M%S")


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
        details = finding.get("details")
        if not isinstance(details, dict):
            details = {}
        params = {
            "scan_id": self.scan_id,
            "endpoint_id": finding.get("endpoint_id"),
            "endpoint_name": finding.get("endpoint_name"),
            "wiz_link": finding.get("wiz_link"),
            "host": finding.get("host"),
            "port": finding.get("port"),
            "cloud_platform": finding.get("cloudPlatform"),
            "cloud_account_name": finding.get("cloudAccountName"),
            "tag_emails": finding.get("tagEmails") if isinstance(finding.get("tagEmails"), list) else [],
            "exposure_level": finding.get("exposureLevel"),
            "check_id": finding.get("check_id"),
            "risk_level": finding.get("risk_level"),
            "whitelisted": is_whitelisted_finding(finding, self.low_risk_subscriptions),
            "http_status": str(details.get("http_status") or details.get("status") or "") or None,
            "http_response": finding.get("http_response"),
            "llm_opinion": finding.get("llm_opinion"),
            "evidence": finding.get("evidence"),
            "recommendation": finding.get("recommendation"),
            "details": json.dumps(details, ensure_ascii=False),
            "raw": json.dumps(finding, ensure_ascii=False),
        }
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
        self.connection.commit()

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
