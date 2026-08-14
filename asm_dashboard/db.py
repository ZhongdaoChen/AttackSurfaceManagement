from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

import rds_writer


DEFAULT_PAGE_SIZE = 200
EXPOSURE_TREND_START_DATE = datetime.date(2026, 8, 13)


@dataclass(frozen=True)
class FilterState:
    risk_levels: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    cloud_platforms: list[str] = field(default_factory=list)
    cloud_accounts: list[str] = field(default_factory=list)
    check_ids: list[str] = field(default_factory=list)
    exposure_levels: list[str] = field(default_factory=list)
    search: str = ""
    first_seen_start: datetime.date | None = None
    first_seen_end: datetime.date | None = None


@dataclass(frozen=True)
class PageResult:
    rows: list[dict[str, Any]]
    total: int
    page: int
    page_size: int


def connect():
    return rds_writer.connect()


def configured() -> bool:
    return rds_writer.rds_configured()


def _as_dict(row: Any) -> dict[str, Any]:
    return dict(row)


def _fetch_all(cursor) -> list[dict[str, Any]]:
    return [_as_dict(row) for row in cursor.fetchall()]


def _fetch_count(cursor) -> int:
    row = cursor.fetchone()
    if row is None:
        return 0
    if isinstance(row, dict):
        return int(row.get("count") or 0)
    return int(row[0] or 0)


def _filter_clauses(
    filters: FilterState,
    prefix: str = "",
    first_seen_column: str = "first_seen_at",
) -> tuple[list[str], dict[str, Any]]:
    def column(name: str) -> str:
        return f"{prefix}.{name}" if prefix else name

    clauses: list[str] = []
    params: dict[str, Any] = {}
    if filters.risk_levels:
        clauses.append(f"{column('risk_level')} = ANY(%(risk_levels)s)")
        params["risk_levels"] = filters.risk_levels
    if filters.ports:
        clauses.append(f"{column('port')} = ANY(%(ports)s)")
        params["ports"] = filters.ports
    if filters.cloud_platforms:
        clauses.append(f"{column('cloud_platform')} = ANY(%(cloud_platforms)s)")
        params["cloud_platforms"] = filters.cloud_platforms
    if filters.cloud_accounts:
        clauses.append(f"{column('cloud_account_name')} = ANY(%(cloud_accounts)s)")
        params["cloud_accounts"] = filters.cloud_accounts
    if filters.check_ids:
        clauses.append(f"{column('check_id')} = ANY(%(check_ids)s)")
        params["check_ids"] = filters.check_ids
    if filters.exposure_levels:
        clauses.append(f"{column('exposure_level')} = ANY(%(exposure_levels)s)")
        params["exposure_levels"] = filters.exposure_levels
    search = filters.search.strip()
    if search:
        clauses.append(f"({column('endpoint_name')} ILIKE %(search)s OR {column('host')} ILIKE %(search)s)")
        params["search"] = f"%{search}%"
    if filters.first_seen_start is not None:
        clauses.append(f"{first_seen_column} >= %(first_seen_start)s")
        params["first_seen_start"] = filters.first_seen_start
    if filters.first_seen_end is not None:
        clauses.append(f"{first_seen_column} < %(first_seen_end_exclusive)s")
        params["first_seen_end_exclusive"] = filters.first_seen_end + datetime.timedelta(days=1)
    return clauses, params


def _page_bounds(page: int, page_size: int) -> tuple[int, int]:
    safe_page = max(1, page)
    safe_page_size = max(1, min(page_size, DEFAULT_PAGE_SIZE))
    return safe_page, safe_page_size


def fetch_latest_scan(connection) -> dict[str, Any] | None:
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT scan_id, started_at, source_file
        FROM asm_scans
        ORDER BY started_at DESC, scan_id DESC
        LIMIT 1
        """,
        {},
    )
    row = cursor.fetchone()
    return _as_dict(row) if row is not None else None


CURRENT_SELECT = """
finding_key, endpoint_id, endpoint_name, wiz_link, host, port,
cloud_platform, cloud_account_name, tag_emails, exposure_level,
check_id, risk_level, whitelisted, http_status, http_response,
llm_opinion, evidence, recommendation, details, raw,
first_seen_scan_id, first_seen_at, last_seen_scan_id, last_seen_at,
seen_count, resolved_at, resolved_scan_id, created_at, updated_at
"""


def fetch_current_findings(connection, filters: FilterState, page: int, page_size: int) -> PageResult:
    clauses, params = _filter_clauses(filters)
    where_sql = " AND ".join(["resolved_at IS NULL", "whitelisted = FALSE", *clauses])
    safe_page, safe_page_size = _page_bounds(page, page_size)
    page_params = {**params, "limit": safe_page_size, "offset": (safe_page - 1) * safe_page_size}
    cursor = connection.cursor()
    cursor.execute(f"SELECT COUNT(*) AS count FROM asm_current_findings WHERE {where_sql}", params)
    total = _fetch_count(cursor)
    cursor.execute(
        f"""
        SELECT {CURRENT_SELECT}
        FROM asm_current_findings
        WHERE {where_sql}
        ORDER BY first_seen_at DESC, endpoint_name ASC
        LIMIT %(limit)s OFFSET %(offset)s
        """,
        page_params,
    )
    return PageResult(rows=_fetch_all(cursor), total=total, page=safe_page, page_size=safe_page_size)


def fetch_historical_findings(
    connection,
    selected_date: datetime.date,
    filters: FilterState,
    page: int,
    page_size: int,
) -> PageResult:
    first_seen_expr = "COALESCE(c.first_seen_at, s.started_at)"
    clauses, params = _filter_clauses(filters, prefix="f", first_seen_column=first_seen_expr)
    where_sql = " AND ".join(
        [
            "s.started_at >= %(start_date)s",
            "s.started_at < %(end_date)s",
            *clauses,
        ]
    )
    safe_page, safe_page_size = _page_bounds(page, page_size)
    base_params = {
        **params,
        "start_date": selected_date,
        "end_date": selected_date + datetime.timedelta(days=1),
    }
    page_params = {**base_params, "limit": safe_page_size, "offset": (safe_page - 1) * safe_page_size}
    join_sql = """
        FROM asm_findings f
        JOIN asm_scans s ON s.scan_id = f.scan_id
        LEFT JOIN asm_current_findings c
          ON COALESCE(c.endpoint_id, '') = COALESCE(f.endpoint_id, '')
         AND COALESCE(c.check_id, '') = COALESCE(f.check_id, '')
         AND COALESCE(c.host, '') = COALESCE(f.host, '')
         AND COALESCE(c.port, -1) = COALESCE(f.port, -1)
    """
    cursor = connection.cursor()
    cursor.execute(
        f"""
        SELECT COUNT(*) AS count
        {join_sql}
        WHERE {where_sql}
        """,
        base_params,
    )
    total = _fetch_count(cursor)
    cursor.execute(
        f"""
        SELECT f.*, s.started_at AS scan_started_at, {first_seen_expr} AS first_seen_at
        {join_sql}
        WHERE {where_sql}
        ORDER BY s.started_at DESC, f.endpoint_name ASC
        LIMIT %(limit)s OFFSET %(offset)s
        """,
        page_params,
    )
    return PageResult(rows=_fetch_all(cursor), total=total, page=safe_page, page_size=safe_page_size)


def fetch_current_kpi_rows(connection) -> list[dict[str, Any]]:
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT *
        FROM asm_current_findings
        WHERE resolved_at IS NULL
          AND whitelisted = FALSE
        """,
        {},
    )
    return _fetch_all(cursor)


def fetch_resolved_high_count_since(connection, since: datetime.datetime) -> int:
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT COUNT(*) AS count
        FROM asm_current_findings
        WHERE risk_level = 'high'
          AND whitelisted = FALSE
          AND resolved_at >= %(since)s
        """,
        {"since": since},
    )
    return _fetch_count(cursor)


def fetch_trend_rows(connection) -> list[dict[str, Any]]:
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT
          s.scan_id,
          s.started_at AS scan_started_at,
          COUNT(DISTINCT f.id) AS high_risk_count,
          COUNT(DISTINCT c.finding_key) AS mitigated_count
        FROM asm_scans s
        LEFT JOIN asm_findings f ON f.scan_id = s.scan_id
          AND f.risk_level = 'high'
          AND f.whitelisted = FALSE
        LEFT JOIN asm_current_findings c ON c.resolved_scan_id = s.scan_id
          AND c.risk_level = 'high'
        WHERE s.started_at >= %(trend_start)s
        GROUP BY s.scan_id, s.started_at
        ORDER BY s.started_at ASC, s.scan_id ASC
        """,
        {"trend_start": EXPOSURE_TREND_START_DATE},
    )
    return _fetch_all(cursor)


def fetch_filter_options(connection, current_only: bool = True) -> dict[str, list[Any]]:
    table = "asm_current_findings" if current_only else "asm_findings"
    where = "WHERE resolved_at IS NULL AND whitelisted = FALSE" if current_only else ""
    cursor = connection.cursor()
    cursor.execute(
        f"""
        SELECT
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT risk_level), NULL) AS risk_levels,
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT port), NULL) AS ports,
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT cloud_platform), NULL) AS cloud_platforms,
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT cloud_account_name), NULL) AS cloud_accounts,
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT check_id), NULL) AS check_ids,
          ARRAY_REMOVE(ARRAY_AGG(DISTINCT exposure_level), NULL) AS exposure_levels
        FROM {table}
        {where}
        """,
        {},
    )
    row = cursor.fetchone() or {}
    return {key: sorted(value or []) for key, value in _as_dict(row).items()}


def create_whitelist_rule(connection, endpoint_name: str, port: int | None, reason: str, operator_name: str) -> None:
    endpoint = endpoint_name.strip()
    clean_reason = reason.strip()
    clean_operator = operator_name.strip()
    if not endpoint:
        raise ValueError("endpoint_name is required")
    if not clean_reason:
        raise ValueError("reason is required")
    if not clean_operator:
        raise ValueError("operator_name is required")
    params = {
        "endpoint_name": endpoint,
        "port": port,
        "reason": clean_reason,
        "operator_name": clean_operator,
    }
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO asm_whitelist_rules (endpoint_name, port, reason, operator_name)
        VALUES (%(endpoint_name)s, %(port)s, %(reason)s, %(operator_name)s)
        """,
        params,
    )
    cursor.execute(
        """
        UPDATE asm_current_findings
        SET whitelisted = TRUE, updated_at = now()
        WHERE endpoint_name = %(endpoint_name)s
          AND COALESCE(port, -1) = COALESCE(%(port)s, -1)
        """,
        params,
    )
    cursor.execute(
        """
        UPDATE asm_findings
        SET whitelisted = TRUE
        WHERE endpoint_name = %(endpoint_name)s
          AND COALESCE(port, -1) = COALESCE(%(port)s, -1)
        """,
        params,
    )
    connection.commit()


def fetch_whitelist_rules(connection) -> list[dict[str, Any]]:
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT id, endpoint_name, port, reason, operator_name, active,
               created_at, deactivated_at, deactivated_by, deactivation_reason
        FROM asm_whitelist_rules
        ORDER BY active DESC, created_at DESC, id DESC
        """,
        {},
    )
    return _fetch_all(cursor)


def deactivate_whitelist_rule(connection, rule_id: int, operator_name: str, reason: str) -> None:
    clean_reason = reason.strip()
    clean_operator = operator_name.strip()
    if not clean_reason:
        raise ValueError("reason is required")
    if not clean_operator:
        raise ValueError("operator_name is required")
    cursor = connection.cursor()
    cursor.execute(
        """
        UPDATE asm_whitelist_rules
        SET active = FALSE,
            deactivated_at = now(),
            deactivated_by = %(operator_name)s,
            deactivation_reason = %(reason)s
        WHERE id = %(rule_id)s
          AND active = TRUE
        """,
        {"rule_id": rule_id, "operator_name": clean_operator, "reason": clean_reason},
    )
    connection.commit()
