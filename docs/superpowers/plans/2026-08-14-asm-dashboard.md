# ASM Streamlit Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Streamlit ASM dashboard backed by the existing RDS PostgreSQL tables, with current-state executive metrics, historical scan views, and auditable endpoint+port whitelist rules.

**Architecture:** Add a focused `asm_dashboard` package for auth, DB queries, metrics, and Streamlit pages. Extend the existing RDS schema and writer so dashboard-created whitelist rules are applied to future scans. Keep Streamlit UI thin: it calls typed query/mutation helpers and pure metric helpers that are unit tested with fake connections and in-memory rows.

**Tech Stack:** Python 3, Streamlit, pandas, Plotly, psycopg v3, PostgreSQL, unittest.

## Global Constraints

- Reuse the existing `RDS_*` environment variables and `.env` loading pattern.
- Use `DASHBOARD_PASSWORD` for simple password protection.
- If `DASHBOARD_PASSWORD` is absent, the app must fail closed and show a clear configuration error rather than running unauthenticated.
- Do not store passwords or RDS secrets in source code.
- Current Status must show only rows where `resolved_at IS NULL` and `whitelisted = FALSE`.
- Historical Results must use `asm_scans.started_at` as the selected date basis and include whitelisted findings.
- Dashboard whitelist rules match by `endpoint_name + port`.
- Creating a whitelist rule updates `asm_current_findings` and all matching `asm_findings` rows to `whitelisted = TRUE`.
- Deactivating a rule stops future automatic whitelist matching and does not revert existing current/history flags.
- Default list page size is 200 rows.
- Trend window defaults to all history, aggregated by `asm_scans.started_at` date.
- Use tests with fake connection/cursor objects where possible; local tests must not require RDS network access.

---

## File structure

- Modify `schema.sql`: add `asm_whitelist_rules` table and lookup indexes.
- Modify `rds_writer.py`: add dashboard whitelist lookup and apply it before inserting history/current rows.
- Modify `requirements.txt`: add `streamlit`, `pandas`, and `plotly`.
- Create `asm_dashboard/__init__.py`: package marker.
- Create `asm_dashboard/auth.py`: password presence/check helpers with no Streamlit dependency.
- Create `asm_dashboard/db.py`: RDS connection reuse, SQL query helpers, pagination/filter SQL, whitelist mutations.
- Create `asm_dashboard/metrics.py`: pure Python/pandas metric and table helpers.
- Create `asm_dashboard/app.py`: Streamlit navigation, pages, charts, tables, and whitelist forms.
- Create `test_dashboard_auth.py`: auth helper tests.
- Create `test_dashboard_db.py`: SQL construction and whitelist mutation tests using fake cursors.
- Create `test_dashboard_metrics.py`: metric aggregation and pagination helper tests.
- Modify `test_rds_writer.py`: schema and future-scan whitelist tests.
- Modify `README.md`: dashboard setup and run instructions.

---

### Task 1: Schema and future-scan whitelist application

**Files:**
- Modify: `schema.sql`
- Modify: `rds_writer.py`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Consumes: existing `rds_writer.finding_insert_params(finding, scan_id, low_risk_subscriptions) -> dict[str, Any]`.
- Produces: `rds_writer.dashboard_whitelisted(cursor, endpoint_name: Any, port: Any) -> bool`, used by `RdsFindingWriter.write()`.
- Produces: `asm_whitelist_rules` table with active lookup by `endpoint_name + port`.

- [ ] **Step 1: Write failing schema test**

Add this test to `test_rds_writer.py` inside `RdsWriterTests`:

```python
    def test_schema_defines_dashboard_whitelist_rules(self):
        schema = Path("schema.sql").read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS asm_whitelist_rules", schema)
        self.assertIn("endpoint_name TEXT NOT NULL", schema)
        self.assertIn("port INTEGER", schema)
        self.assertIn("reason TEXT NOT NULL", schema)
        self.assertIn("operator_name TEXT NOT NULL", schema)
        self.assertIn("active BOOLEAN NOT NULL DEFAULT TRUE", schema)
        self.assertIn("deactivated_at TIMESTAMPTZ", schema)
        self.assertIn("idx_asm_whitelist_rules_active_lookup", schema)
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_schema_defines_dashboard_whitelist_rules
```

Expected: FAIL because `asm_whitelist_rules` is not in `schema.sql`.

- [ ] **Step 3: Add whitelist schema**

Append this block to `schema.sql` after the existing `asm_current_findings` indexes:

```sql
CREATE TABLE IF NOT EXISTS asm_whitelist_rules (
  id BIGSERIAL PRIMARY KEY,
  endpoint_name TEXT NOT NULL,
  port INTEGER,
  reason TEXT NOT NULL,
  operator_name TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deactivated_at TIMESTAMPTZ,
  deactivated_by TEXT,
  deactivation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_asm_whitelist_rules_active_lookup
  ON asm_whitelist_rules(endpoint_name, COALESCE(port, -1))
  WHERE active = TRUE;

CREATE INDEX IF NOT EXISTS idx_asm_whitelist_rules_active
  ON asm_whitelist_rules(active);
```

- [ ] **Step 4: Run schema test to verify it passes**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_schema_defines_dashboard_whitelist_rules
```

Expected: PASS.

- [ ] **Step 5: Write failing tests for dashboard whitelist lookup and writer application**

Extend `FakeCursor` in `test_rds_writer.py` so `fetchone()` is available:

```python
    def fetchone(self):
        return self.result_rows[0] if self.result_rows else None
```

Add these tests to `RdsWriterTests`:

```python
    def test_dashboard_whitelisted_queries_active_endpoint_port_rule(self):
        cursor = FakeCursor(result_rows=[{"id": 1}])

        self.assertTrue(rds_writer.dashboard_whitelisted(cursor, "https://app.example.com:443", 443))

        sql, params = cursor.executions[0]
        self.assertIn("FROM asm_whitelist_rules", sql)
        self.assertIn("active = TRUE", sql)
        self.assertIn("endpoint_name = %(endpoint_name)s", sql)
        self.assertIn("COALESCE(port, -1) = COALESCE(%(port)s, -1)", sql)
        self.assertEqual(params, {"endpoint_name": "https://app.example.com:443", "port": 443})

    def test_writer_marks_future_scan_finding_whitelisted_from_dashboard_rule(self):
        connection = FakeConnection(result_rows=[{"id": 1}])
        finding = {
            "endpoint_id": "endpoint-1",
            "endpoint_name": "https://app.example.com:443",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
            "risk_level": "high",
            "details": {"status": 200},
        }
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-14T10:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions=set(),
        )

        writer.write(finding)

        history_sql, history_params = connection.cursor_obj.executions[2]
        current_sql, current_params = connection.cursor_obj.executions[3]
        self.assertIn("INSERT INTO asm_findings", history_sql)
        self.assertIn("INSERT INTO asm_current_findings", current_sql)
        self.assertTrue(history_params["whitelisted"])
        self.assertTrue(current_params["whitelisted"])
```

- [ ] **Step 6: Run whitelist tests to verify they fail**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_dashboard_whitelisted_queries_active_endpoint_port_rule \
  test_rds_writer.RdsWriterTests.test_writer_marks_future_scan_finding_whitelisted_from_dashboard_rule
```

Expected: FAIL with `AttributeError` for `dashboard_whitelisted`.

- [ ] **Step 7: Implement dashboard whitelist lookup in `rds_writer.py`**

Add this function after `is_whitelisted_finding()`:

```python
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
```

Then update `RdsFindingWriter.write()` immediately after `params = finding_insert_params(...)`:

```python
        if dashboard_whitelisted(self.cursor, params.get("endpoint_name"), params.get("port")):
            params["whitelisted"] = True
```

- [ ] **Step 8: Run targeted tests to verify they pass**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_schema_defines_dashboard_whitelist_rules \
  test_rds_writer.RdsWriterTests.test_dashboard_whitelisted_queries_active_endpoint_port_rule \
  test_rds_writer.RdsWriterTests.test_writer_marks_future_scan_finding_whitelisted_from_dashboard_rule
```

Expected: PASS.

- [ ] **Step 9: Run existing RDS writer tests**

Run:

```bash
python3 -m unittest test_rds_writer
```

Expected: PASS.

- [ ] **Step 10: Commit**

Run:

```bash
git add schema.sql rds_writer.py test_rds_writer.py
git commit -m "feat: apply dashboard whitelist rules to RDS writes" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Dashboard auth, DB query, and mutation layer

**Files:**
- Create: `asm_dashboard/__init__.py`
- Create: `asm_dashboard/auth.py`
- Create: `asm_dashboard/db.py`
- Create: `test_dashboard_auth.py`
- Create: `test_dashboard_db.py`

**Interfaces:**
- Consumes: `rds_writer.connect()`, `rds_writer.rds_configured()`.
- Produces: `auth.password_configured() -> bool`.
- Produces: `auth.password_matches(candidate: str | None) -> bool`.
- Produces: `db.FilterState` dataclass.
- Produces: `db.PageResult` dataclass.
- Produces: `db.fetch_current_findings(connection, filters: FilterState, page: int, page_size: int) -> PageResult`.
- Produces: `db.fetch_historical_findings(connection, selected_date: datetime.date, filters: FilterState, page: int, page_size: int) -> PageResult`.
- Produces: `db.fetch_latest_scan(connection) -> dict[str, Any] | None`.
- Produces: `db.fetch_current_kpi_rows(connection) -> list[dict[str, Any]]`.
- Produces: `db.fetch_trend_rows(connection) -> list[dict[str, Any]]`.
- Produces: `db.create_whitelist_rule(connection, endpoint_name: str, port: int | None, reason: str, operator_name: str) -> None`.
- Produces: `db.fetch_whitelist_rules(connection) -> list[dict[str, Any]]`.
- Produces: `db.deactivate_whitelist_rule(connection, rule_id: int, operator_name: str, reason: str) -> None`.

- [ ] **Step 1: Write failing auth tests**

Create `test_dashboard_auth.py`:

```python
import os
import unittest
from unittest.mock import patch

from asm_dashboard import auth


class DashboardAuthTests(unittest.TestCase):
    def test_password_configured_requires_non_empty_env_value(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(auth.password_configured())
        with patch.dict(os.environ, {"DASHBOARD_PASSWORD": "  "}, clear=True):
            self.assertFalse(auth.password_configured())
        with patch.dict(os.environ, {"DASHBOARD_PASSWORD": "secret"}, clear=True):
            self.assertTrue(auth.password_configured())

    def test_password_matches_uses_constant_time_comparison(self):
        with patch.dict(os.environ, {"DASHBOARD_PASSWORD": "secret"}, clear=True):
            self.assertTrue(auth.password_matches("secret"))
            self.assertFalse(auth.password_matches("wrong"))
            self.assertFalse(auth.password_matches(None))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run auth tests to verify they fail**

Run:

```bash
python3 -m unittest test_dashboard_auth
```

Expected: FAIL because `asm_dashboard` does not exist.

- [ ] **Step 3: Implement auth helpers**

Create `asm_dashboard/__init__.py`:

```python
"""Streamlit dashboard for Attack Surface Management RDS data."""
```

Create `asm_dashboard/auth.py`:

```python
from __future__ import annotations

import hmac
import os


def configured_password() -> str:
    return os.getenv("DASHBOARD_PASSWORD", "").strip()


def password_configured() -> bool:
    return bool(configured_password())


def password_matches(candidate: str | None) -> bool:
    expected = configured_password()
    if not expected or candidate is None:
        return False
    return hmac.compare_digest(candidate, expected)
```

- [ ] **Step 4: Run auth tests to verify they pass**

Run:

```bash
python3 -m unittest test_dashboard_auth
```

Expected: PASS.

- [ ] **Step 5: Write failing DB layer tests**

Create `test_dashboard_db.py`:

```python
import datetime
import unittest

from asm_dashboard import db


class FakeCursor:
    def __init__(self, rows=None, scalar=None):
        self.executions = []
        self.rows = list(rows or [])
        self.scalar = scalar

    def execute(self, sql, params=None):
        self.executions.append((sql, params or {}))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        if self.rows:
            return self.rows[0]
        if self.scalar is not None:
            return {"count": self.scalar}
        return None


class FakeConnection:
    def __init__(self, rows=None, scalar=None):
        self.cursor_obj = FakeCursor(rows=rows, scalar=scalar)
        self.commits = 0

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1


class DashboardDbTests(unittest.TestCase):
    def test_fetch_latest_scan_orders_by_started_at_then_scan_id(self):
        connection = FakeConnection(rows=[{"scan_id": "scan-2", "started_at": "2026-08-14T10:00:00+08:00"}])

        row = db.fetch_latest_scan(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_scans", sql)
        self.assertIn("ORDER BY started_at DESC, scan_id DESC", sql)
        self.assertEqual(params, {})
        self.assertEqual(row["scan_id"], "scan-2")

    def test_fetch_current_findings_excludes_resolved_and_whitelisted_with_filters(self):
        connection = FakeConnection(rows=[{"finding_key": "key-1"}], scalar=1)
        filters = db.FilterState(
            risk_levels=["high"],
            ports=[443],
            cloud_platforms=["AWS"],
            cloud_accounts=["Account One"],
            check_ids=["llm_sensitive_content"],
            exposure_levels=["HIGH"],
            search="app.example.com",
            first_seen_start=datetime.date(2026, 8, 1),
            first_seen_end=datetime.date(2026, 8, 14),
        )

        result = db.fetch_current_findings(connection, filters, page=2, page_size=200)

        count_sql, count_params = connection.cursor_obj.executions[0]
        data_sql, data_params = connection.cursor_obj.executions[1]
        self.assertIn("resolved_at IS NULL", data_sql)
        self.assertIn("whitelisted = FALSE", data_sql)
        self.assertIn("risk_level = ANY(%(risk_levels)s)", data_sql)
        self.assertIn("port = ANY(%(ports)s)", data_sql)
        self.assertIn("cloud_platform = ANY(%(cloud_platforms)s)", data_sql)
        self.assertIn("cloud_account_name = ANY(%(cloud_accounts)s)", data_sql)
        self.assertIn("check_id = ANY(%(check_ids)s)", data_sql)
        self.assertIn("exposure_level = ANY(%(exposure_levels)s)", data_sql)
        self.assertIn("OFFSET %(offset)s", data_sql)
        self.assertEqual(count_params["risk_levels"], ["high"])
        self.assertEqual(data_params["offset"], 200)
        self.assertEqual(result.total, 1)
        self.assertEqual(result.rows, [{"finding_key": "key-1"}])

    def test_create_whitelist_rule_inserts_rule_and_backfills_current_and_history(self):
        connection = FakeConnection()

        db.create_whitelist_rule(
            connection,
            endpoint_name="https://app.example.com:443",
            port=443,
            reason="Business accepted",
            operator_name="Alice",
        )

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("INSERT INTO asm_whitelist_rules", executed_sql)
        self.assertIn("UPDATE asm_current_findings", executed_sql)
        self.assertIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)

    def test_deactivate_whitelist_rule_only_updates_rule_metadata(self):
        connection = FakeConnection()

        db.deactivate_whitelist_rule(connection, rule_id=7, operator_name="Alice", reason="Expired exception")

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("UPDATE asm_whitelist_rules", executed_sql)
        self.assertNotIn("UPDATE asm_current_findings", executed_sql)
        self.assertNotIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 6: Run DB tests to verify they fail**

Run:

```bash
python3 -m unittest test_dashboard_db
```

Expected: FAIL because `asm_dashboard.db` is missing.

- [ ] **Step 7: Implement DB layer**

Create `asm_dashboard/db.py`:

```python
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Any

import rds_writer


DEFAULT_PAGE_SIZE = 200


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


def _fetch_all(cursor) -> list[dict[str, Any]]:
    return list(cursor.fetchall())


def _fetch_count(cursor) -> int:
    row = cursor.fetchone()
    if row is None:
        return 0
    if isinstance(row, dict):
        return int(row.get("count") or 0)
    return int(row[0] or 0)


def _filter_clauses(filters: FilterState, prefix: str = "") -> tuple[list[str], dict[str, Any]]:
    column = lambda name: f"{prefix}.{name}" if prefix else name
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
        clauses.append(f"{column('first_seen_at')} >= %(first_seen_start)s")
        params["first_seen_start"] = filters.first_seen_start
    if filters.first_seen_end is not None:
        clauses.append(f"{column('first_seen_at')} < %(first_seen_end_exclusive)s")
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
    return dict(row) if row is not None else None


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
    where = ["resolved_at IS NULL", "whitelisted = FALSE", *clauses]
    where_sql = " AND ".join(where)
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
        ORDER BY risk_level DESC, first_seen_at DESC, endpoint_name ASC
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
    clauses, params = _filter_clauses(filters, prefix="f")
    where = [
        "s.started_at >= %(start_date)s",
        "s.started_at < %(end_date)s",
        *clauses,
    ]
    where_sql = " AND ".join(where)
    safe_page, safe_page_size = _page_bounds(page, page_size)
    base_params = {
        **params,
        "start_date": selected_date,
        "end_date": selected_date + datetime.timedelta(days=1),
    }
    page_params = {**base_params, "limit": safe_page_size, "offset": (safe_page - 1) * safe_page_size}
    cursor = connection.cursor()
    cursor.execute(
        f"""
        SELECT COUNT(*) AS count
        FROM asm_findings f
        JOIN asm_scans s ON s.scan_id = f.scan_id
        WHERE {where_sql}
        """,
        base_params,
    )
    total = _fetch_count(cursor)
    cursor.execute(
        f"""
        SELECT f.*, s.started_at AS scan_started_at, c.first_seen_at AS first_seen_at
        FROM asm_findings f
        JOIN asm_scans s ON s.scan_id = f.scan_id
        LEFT JOIN asm_current_findings c
          ON COALESCE(c.endpoint_id, '') = COALESCE(f.endpoint_id, '')
         AND COALESCE(c.check_id, '') = COALESCE(f.check_id, '')
         AND COALESCE(c.host, '') = COALESCE(f.host, '')
         AND COALESCE(c.port, -1) = COALESCE(f.port, -1)
        WHERE {where_sql}
        ORDER BY s.started_at DESC, f.risk_level DESC, f.endpoint_name ASC
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


def fetch_trend_rows(connection) -> list[dict[str, Any]]:
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT finding_key, first_seen_at, resolved_at, risk_level, check_id, port, whitelisted
        FROM asm_current_findings
        """,
        {},
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
    return {key: sorted(value or []) for key, value in dict(row).items()}


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
```

- [ ] **Step 8: Run auth and DB tests**

Run:

```bash
python3 -m unittest test_dashboard_auth test_dashboard_db
```

Expected: PASS.

- [ ] **Step 9: Commit**

Run:

```bash
git add asm_dashboard/__init__.py asm_dashboard/auth.py asm_dashboard/db.py test_dashboard_auth.py test_dashboard_db.py
git commit -m "feat: add dashboard auth and RDS data layer" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Dashboard metrics and table formatting

**Files:**
- Create: `asm_dashboard/metrics.py`
- Create: `test_dashboard_metrics.py`

**Interfaces:**
- Consumes: rows returned by `asm_dashboard.db.fetch_current_kpi_rows()` and `fetch_trend_rows()`.
- Produces: `metrics.current_kpis(rows: list[dict[str, Any]], latest_scan_id: str | None) -> dict[str, int]`.
- Produces: `metrics.trend_frame(rows: list[dict[str, Any]]) -> pandas.DataFrame`.
- Produces: `metrics.distribution(rows: list[dict[str, Any]], key: str, limit: int = 10) -> pandas.DataFrame`.
- Produces: `metrics.endpoint_link(endpoint_name: Any) -> str`.

- [ ] **Step 1: Write failing metrics tests**

Create `test_dashboard_metrics.py`:

```python
import unittest

from asm_dashboard import metrics


class DashboardMetricsTests(unittest.TestCase):
    def test_current_kpis_counts_ciso_metrics(self):
        rows = [
            {
                "finding_key": "a",
                "risk_level": "high",
                "first_seen_scan_id": "scan-2",
                "check_id": "llm_sensitive_content",
                "port": 443,
            },
            {
                "finding_key": "b",
                "risk_level": "low",
                "first_seen_scan_id": "scan-1",
                "check_id": "non_standard_open_port",
                "port": 9200,
            },
            {
                "finding_key": "c",
                "risk_level": "medium",
                "first_seen_scan_id": "scan-2",
                "check_id": "llm_sensitive_content",
                "port": 8080,
            },
        ]

        result = metrics.current_kpis(rows, latest_scan_id="scan-2", resolved_latest_scan=4)

        self.assertEqual(result["active_findings"], 3)
        self.assertEqual(result["active_high"], 1)
        self.assertEqual(result["new_latest_scan"], 2)
        self.assertEqual(result["resolved_latest_scan"], 4)
        self.assertEqual(result["sensitive_exposure_80_443"], 1)
        self.assertEqual(result["current_non_standard_ports"], 1)

    def test_endpoint_link_returns_markdown_link_only_for_http_urls(self):
        self.assertEqual(
            metrics.endpoint_link("https://app.example.com"),
            "[https://app.example.com](https://app.example.com)",
        )
        self.assertEqual(metrics.endpoint_link("app.example.com"), "app.example.com")
        self.assertEqual(metrics.endpoint_link(None), "")

    def test_distribution_counts_top_values(self):
        rows = [{"risk_level": "high"}, {"risk_level": "high"}, {"risk_level": "low"}, {"risk_level": None}]

        frame = metrics.distribution(rows, "risk_level")

        self.assertEqual(frame.to_dict("records"), [{"risk_level": "high", "count": 2}, {"risk_level": "low", "count": 1}])
```

- [ ] **Step 2: Run metrics tests to verify they fail**

Run:

```bash
python3 -m unittest test_dashboard_metrics
```

Expected: FAIL because `asm_dashboard.metrics` does not exist.

- [ ] **Step 3: Implement metrics helpers**

Create `asm_dashboard/metrics.py`:

```python
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
```

- [ ] **Step 4: Run metrics tests**

Run:

```bash
python3 -m unittest test_dashboard_metrics
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add asm_dashboard/metrics.py test_dashboard_metrics.py
git commit -m "feat: add dashboard metric helpers" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Streamlit Current Status page

**Files:**
- Create: `asm_dashboard/app.py`
- Modify: `requirements.txt`

**Interfaces:**
- Consumes: `auth.password_configured()`, `auth.password_matches()`, `db.connect()`, `db.configured()`, `db.fetch_latest_scan()`, `db.fetch_current_kpi_rows()`, `db.fetch_current_findings()`, `db.fetch_filter_options()`, `db.create_whitelist_rule()`, `metrics.current_kpis()`, `metrics.distribution()`, `metrics.trend_frame()`, `metrics.endpoint_link()`.
- Produces: `app.main() -> None`, runnable with `streamlit run asm_dashboard/app.py`.
- Produces: Current Status page with auth gate, KPI cards, charts, filters, pagination, row detail panel, and whitelist form.

- [ ] **Step 1: Add dashboard dependencies**

Modify `requirements.txt` to:

```text
psycopg[binary]>=3.2,<4
streamlit>=1.36,<2
pandas>=2.2,<3
plotly>=5.22,<6
```

- [ ] **Step 2: Write a lightweight import smoke test**

Create `test_dashboard_app.py`:

```python
import unittest


class DashboardAppTests(unittest.TestCase):
    def test_app_module_imports(self):
        import asm_dashboard.app as app

        self.assertTrue(callable(app.main))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run app import test to verify it fails**

Run:

```bash
python3 -m unittest test_dashboard_app
```

Expected before dependencies are installed: either FAIL with missing `asm_dashboard.app` or missing `streamlit`. If it fails only because dependencies are not installed, install requirements in Step 4 before rerunning.

- [ ] **Step 4: Install/restore dependencies if needed**

Run only if Step 3 failed because `streamlit`, `pandas`, or `plotly` is missing:

```bash
pip3 install -r requirements.txt
```

Expected: packages install successfully.

- [ ] **Step 5: Implement Current Status Streamlit page**

Create `asm_dashboard/app.py`:

```python
from __future__ import annotations

import datetime
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from asm_dashboard import auth, db, metrics
from assess_attack_surface import load_dotenv


PAGE_SIZE = 200


def require_login() -> bool:
    load_dotenv()
    if not auth.password_configured():
        st.error("DASHBOARD_PASSWORD is not configured. Dashboard access is disabled.")
        return False
    if st.session_state.get("authenticated"):
        return True
    with st.form("login_form"):
        password = st.text_input("Dashboard password", type="password")
        submitted = st.form_submit_button("Sign in")
    if submitted and auth.password_matches(password):
        st.session_state["authenticated"] = True
        st.rerun()
    if submitted:
        st.error("Invalid password.")
    return False


def get_connection():
    load_dotenv()
    if not db.configured():
        st.error("RDS configuration is incomplete. Set RDS_HOST, RDS_DB, RDS_USER, and RDS_PASSWORD.")
        st.stop()
    return db.connect()


def sidebar_page() -> str:
    st.sidebar.title("ASM Dashboard")
    return st.sidebar.radio("Navigation", ["Current Status", "Historical Results", "Whitelist Rules"])


def filter_state(options: dict[str, list[Any]], key_prefix: str = "current") -> db.FilterState:
    with st.expander("Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        with col1:
            risk_levels = st.multiselect("Risk Level", options.get("risk_levels", []), key=f"{key_prefix}_risk")
            ports = st.multiselect("Port", options.get("ports", []), key=f"{key_prefix}_port")
        with col2:
            cloud_platforms = st.multiselect("Cloud Platform", options.get("cloud_platforms", []), key=f"{key_prefix}_platform")
            cloud_accounts = st.multiselect("Cloud Account Name", options.get("cloud_accounts", []), key=f"{key_prefix}_account")
        with col3:
            check_ids = st.multiselect("Check ID", options.get("check_ids", []), key=f"{key_prefix}_check")
            exposure_levels = st.multiselect("Exposure Level", options.get("exposure_levels", []), key=f"{key_prefix}_exposure")
        search = st.text_input("Endpoint or host search", key=f"{key_prefix}_search")
        date_range = st.date_input("First Seen date range", value=(), key=f"{key_prefix}_first_seen")
    first_seen_start = date_range[0] if isinstance(date_range, tuple) and len(date_range) >= 1 else None
    first_seen_end = date_range[1] if isinstance(date_range, tuple) and len(date_range) >= 2 else None
    return db.FilterState(
        risk_levels=list(risk_levels),
        ports=list(ports),
        cloud_platforms=list(cloud_platforms),
        cloud_accounts=list(cloud_accounts),
        check_ids=list(check_ids),
        exposure_levels=list(exposure_levels),
        search=search,
        first_seen_start=first_seen_start,
        first_seen_end=first_seen_end,
    )


def render_kpis(kpis: dict[str, int]) -> None:
    labels = [
        ("Active Findings", "active_findings"),
        ("Active High", "active_high"),
        ("New Latest Scan", "new_latest_scan"),
        ("Resolved Latest Scan", "resolved_latest_scan"),
        ("Sensitive Exposure 80/443", "sensitive_exposure_80_443"),
        ("Current Non-standard Ports", "current_non_standard_ports"),
    ]
    cols = st.columns(3)
    for index, (label, key) in enumerate(labels):
        cols[index % 3].metric(label, kpis.get(key, 0))


def render_current_charts(current_rows: list[dict[str, Any]], trend_rows: list[dict[str, Any]]) -> None:
    trend = metrics.trend_frame(trend_rows)
    left, right = st.columns([2, 1])
    with left:
        st.subheader("Exposure trend")
        if trend.empty:
            st.info("No trend data available.")
        else:
            st.plotly_chart(px.line(trend, x="date", y="count", color="metric", markers=True), use_container_width=True)
    with right:
        st.subheader("Risk distribution")
        risk = metrics.distribution(current_rows, "risk_level")
        if risk.empty:
            st.info("No risk distribution data.")
        else:
            st.plotly_chart(px.pie(risk, names="risk_level", values="count"), use_container_width=True)
    col1, col2, col3 = st.columns(3)
    for column, title, key in [
        (col1, "Cloud Accounts", "cloud_account_name"),
        (col2, "Cloud Platforms", "cloud_platform"),
        (col3, "Top Check IDs", "check_id"),
    ]:
        with column:
            st.subheader(title)
            frame = metrics.distribution(current_rows, key)
            if frame.empty:
                st.info("No data.")
            else:
                st.plotly_chart(px.bar(frame, x=key, y="count"), use_container_width=True)


def table_frame(rows: list[dict[str, Any]]) -> pd.DataFrame:
    records = []
    for row in rows:
        records.append(
            {
                "Endpoint Name": metrics.endpoint_link(row.get("endpoint_name")),
                "Port": row.get("port"),
                "Cloud Platform": row.get("cloud_platform"),
                "Cloud Account Name": row.get("cloud_account_name"),
                "Risk Level": row.get("risk_level"),
                "Evidence": row.get("evidence"),
                "First Seen At": row.get("first_seen_at"),
                "Check ID": row.get("check_id"),
                "Exposure Level": row.get("exposure_level"),
                "_row": row,
            }
        )
    return pd.DataFrame(records)


def render_page_controls(total: int, key: str) -> int:
    page_count = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    return st.number_input("Page", min_value=1, max_value=page_count, value=1, step=1, key=key)


def render_current_table(connection, filters: db.FilterState) -> None:
    total_probe = db.fetch_current_findings(connection, filters, page=1, page_size=PAGE_SIZE)
    page = render_page_controls(total_probe.total, "current_page")
    result = total_probe if page == 1 else db.fetch_current_findings(connection, filters, page=page, page_size=PAGE_SIZE)
    st.caption(f"{result.total} findings, showing page {result.page} with up to {result.page_size} rows.")
    frame = table_frame(result.rows)
    if frame.empty:
        st.info("No current findings match the filters.")
        return
    visible = frame.drop(columns=["_row"])
    selection = st.dataframe(
        visible,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
    )
    selected_rows = selection.get("selection", {}).get("rows", [])
    if not selected_rows:
        return
    selected = frame.iloc[selected_rows[0]]["_row"]
    st.subheader("Finding details")
    st.json(selected, expanded=False)
    with st.form("whitelist_selected"):
        st.write(f"Whitelist `{selected.get('endpoint_name')}` port `{selected.get('port')}`")
        reason = st.text_area("Reason")
        operator_name = st.text_input("Operator name")
        submitted = st.form_submit_button("Confirm whitelist")
    if submitted:
        try:
            db.create_whitelist_rule(
                connection,
                endpoint_name=str(selected.get("endpoint_name") or ""),
                port=selected.get("port"),
                reason=reason,
                operator_name=operator_name,
            )
        except Exception as exc:
            st.error(f"Whitelist failed: {type(exc).__name__}: {exc}")
        else:
            st.success("Whitelist rule created and matching current/history findings updated.")
            st.rerun()


def current_status_page(connection) -> None:
    st.title("ASM Current Status")
    st.caption("Executive view of active, non-whitelisted attack surface findings.")
    latest = db.fetch_latest_scan(connection)
    latest_scan_id = latest.get("scan_id") if latest else None
    current_rows = db.fetch_current_kpi_rows(connection)
    resolved_latest_scan = 0
    kpis = metrics.current_kpis(current_rows, latest_scan_id=latest_scan_id, resolved_latest_scan=resolved_latest_scan)
    render_kpis(kpis)
    render_current_charts(current_rows, db.fetch_trend_rows(connection))
    options = db.fetch_filter_options(connection, current_only=True)
    filters = filter_state(options, key_prefix="current")
    render_current_table(connection, filters)


def main() -> None:
    st.set_page_config(page_title="ASM Dashboard", layout="wide")
    if not require_login():
        return
    connection = get_connection()
    page = sidebar_page()
    if page == "Current Status":
        current_status_page(connection)
    elif page == "Historical Results":
        st.title("Historical Results")
        st.info("Historical Results will be implemented in the next task.")
    else:
        st.title("Whitelist Rules")
        st.info("Whitelist Rules will be implemented in the next task.")


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Run app import smoke test**

Run:

```bash
python3 -m unittest test_dashboard_app
```

Expected: PASS.

- [ ] **Step 7: Run all dashboard helper tests**

Run:

```bash
python3 -m unittest test_dashboard_auth test_dashboard_db test_dashboard_metrics test_dashboard_app
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add requirements.txt asm_dashboard/app.py test_dashboard_app.py
git commit -m "feat: add Streamlit current status dashboard" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: Historical Results and Whitelist Rules pages

**Files:**
- Modify: `asm_dashboard/app.py`
- Modify: `test_dashboard_db.py`

**Interfaces:**
- Consumes: `db.fetch_historical_findings()`, `db.fetch_whitelist_rules()`, `db.deactivate_whitelist_rule()`.
- Produces: Historical Results page with date picker, summary cards, filters, pagination, table, and details.
- Produces: Whitelist Rules page with active/inactive rules and deactivation form.

- [ ] **Step 1: Add DB tests for historical date basis and rules listing**

Append these tests to `DashboardDbTests` in `test_dashboard_db.py`:

```python
    def test_fetch_historical_findings_uses_scan_started_date_and_includes_whitelisted(self):
        connection = FakeConnection(rows=[{"id": 1, "whitelisted": True}], scalar=1)

        result = db.fetch_historical_findings(
            connection,
            selected_date=datetime.date(2026, 8, 14),
            filters=db.FilterState(),
            page=1,
            page_size=200,
        )

        data_sql, data_params = connection.cursor_obj.executions[1]
        self.assertIn("JOIN asm_scans s ON s.scan_id = f.scan_id", data_sql)
        self.assertIn("s.started_at >= %(start_date)s", data_sql)
        self.assertIn("s.started_at < %(end_date)s", data_sql)
        self.assertNotIn("f.whitelisted = FALSE", data_sql)
        self.assertEqual(data_params["start_date"], datetime.date(2026, 8, 14))
        self.assertEqual(result.rows, [{"id": 1, "whitelisted": True}])

    def test_fetch_whitelist_rules_orders_active_first(self):
        connection = FakeConnection(rows=[{"id": 1, "active": True}])

        rows = db.fetch_whitelist_rules(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_whitelist_rules", sql)
        self.assertIn("ORDER BY active DESC, created_at DESC, id DESC", sql)
        self.assertEqual(params, {})
        self.assertEqual(rows, [{"id": 1, "active": True}])
```

- [ ] **Step 2: Run new DB tests**

Run:

```bash
python3 -m unittest \
  test_dashboard_db.DashboardDbTests.test_fetch_historical_findings_uses_scan_started_date_and_includes_whitelisted \
  test_dashboard_db.DashboardDbTests.test_fetch_whitelist_rules_orders_active_first
```

Expected: PASS if Task 2 implementation already covered these helpers. If FAIL, adjust `asm_dashboard/db.py` to match the tested SQL semantics before continuing.

- [ ] **Step 3: Implement Historical Results UI**

Replace the placeholder `elif page == "Historical Results":` block in `asm_dashboard/app.py` with a call to a new function:

```python
    elif page == "Historical Results":
        historical_results_page(connection)
```

Add this function before `main()`:

```python
def historical_results_page(connection) -> None:
    st.title("Historical Results")
    st.caption("Scan-history view by asm_scans.started_at date. Includes whitelisted findings.")
    selected_date = st.date_input("Scan date", value=datetime.date.today(), key="history_date")
    options = db.fetch_filter_options(connection, current_only=False)
    filters = filter_state(options, key_prefix="history")
    total_probe = db.fetch_historical_findings(connection, selected_date, filters, page=1, page_size=PAGE_SIZE)
    rows = total_probe.rows
    high_count = sum(1 for row in rows if str(row.get("risk_level") or "").lower() == "high")
    whitelisted_count = sum(1 for row in rows if bool(row.get("whitelisted")))
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Scans on date", len({row.get("scan_id") for row in rows if row.get("scan_id")}))
    col2.metric("Total findings", total_probe.total)
    col3.metric("High findings on page", high_count)
    col4.metric("Whitelisted on page", whitelisted_count)
    page = render_page_controls(total_probe.total, "history_page")
    result = total_probe if page == 1 else db.fetch_historical_findings(connection, selected_date, filters, page=page, page_size=PAGE_SIZE)
    st.caption(f"{result.total} findings, showing page {result.page} with up to {result.page_size} rows.")
    frame = table_frame(result.rows)
    if frame.empty:
        st.info("No historical findings match the filters.")
        return
    visible = frame.drop(columns=["_row"])
    if "scan_id" not in visible.columns:
        visible["scan_id"] = [row.get("scan_id") for row in result.rows]
    if "scan_started_at" not in visible.columns:
        visible["scan_started_at"] = [row.get("scan_started_at") for row in result.rows]
    selection = st.dataframe(
        visible,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
    )
    selected_rows = selection.get("selection", {}).get("rows", [])
    if selected_rows:
        st.subheader("Historical finding details")
        st.json(frame.iloc[selected_rows[0]]["_row"], expanded=False)
```

- [ ] **Step 4: Implement Whitelist Rules UI**

Replace the placeholder `else:` block in `asm_dashboard/app.py` with:

```python
    else:
        whitelist_rules_page(connection)
```

Add this function before `main()`:

```python
def whitelist_rules_page(connection) -> None:
    st.title("Whitelist Rules")
    st.caption("Dashboard-managed endpoint_name + port whitelist rules.")
    rules = db.fetch_whitelist_rules(connection)
    if not rules:
        st.info("No whitelist rules have been created.")
        return
    frame = pd.DataFrame(rules)
    selection = st.dataframe(
        frame,
        use_container_width=True,
        hide_index=True,
        selection_mode="single-row",
        on_select="rerun",
    )
    selected_rows = selection.get("selection", {}).get("rows", [])
    if not selected_rows:
        return
    selected = rules[selected_rows[0]]
    st.subheader("Rule details")
    st.json(selected, expanded=False)
    if not selected.get("active"):
        st.info("This rule is already inactive.")
        return
    with st.form("deactivate_rule"):
        operator_name = st.text_input("Operator name")
        reason = st.text_area("Deactivation reason")
        submitted = st.form_submit_button("Deactivate rule")
    if submitted:
        try:
            db.deactivate_whitelist_rule(
                connection,
                rule_id=int(selected["id"]),
                operator_name=operator_name,
                reason=reason,
            )
        except Exception as exc:
            st.error(f"Deactivate failed: {type(exc).__name__}: {exc}")
        else:
            st.success("Whitelist rule deactivated. Existing whitelisted findings were not reverted.")
            st.rerun()
```

- [ ] **Step 5: Run dashboard tests**

Run:

```bash
python3 -m unittest test_dashboard_auth test_dashboard_db test_dashboard_metrics test_dashboard_app
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add asm_dashboard/app.py test_dashboard_db.py
git commit -m "feat: add dashboard history and whitelist pages" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: Documentation and end-to-end validation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: all dashboard modules from Tasks 1-5.
- Produces: documented setup/run workflow for the Streamlit dashboard.

- [ ] **Step 1: Update README with dashboard setup**

Add this section after the existing RDS PostgreSQL write section in `README.md`:

```markdown
### ASM Streamlit Dashboard

The dashboard reads ASM status from the same RDS PostgreSQL tables used by scan writes.

Install dependencies:

```bash
pip3 install -r requirements.txt
```

Configure the environment, or put the values in `.env`:

| Variable | Required | Description |
| --- | --- | --- |
| `RDS_HOST` | Yes | RDS PostgreSQL host |
| `RDS_PORT` | No | RDS PostgreSQL port, defaults to `5432` |
| `RDS_DB` | Yes | Database name |
| `RDS_USER` | Yes | Database user |
| `RDS_PASSWORD` | Yes | Database password |
| `RDS_SSLMODE` | No | PostgreSQL SSL mode, defaults to `prefer` |
| `DASHBOARD_PASSWORD` | Yes | Password required to open the dashboard |

Run:

```bash
streamlit run asm_dashboard/app.py
```

The default page is Current Status. It shows only active, non-whitelisted current findings. Historical Results is available from the sidebar and includes whitelisted rows for the selected scan date. Whitelist Rules shows dashboard-created endpoint_name + port rules and allows deactivation; deactivation does not revert already-whitelisted findings.
```

- [ ] **Step 2: Run targeted unit tests**

Run:

```bash
python3 -m unittest test_rds_writer test_dashboard_auth test_dashboard_db test_dashboard_metrics test_dashboard_app
```

Expected: PASS.

- [ ] **Step 3: Run full unit test suite**

Run:

```bash
python3 -m unittest
```

Expected: PASS.

- [ ] **Step 4: Verify app import with dependencies**

Run:

```bash
python3 -c "import asm_dashboard.app; print('dashboard import ok')"
```

Expected output:

```text
dashboard import ok
```

- [ ] **Step 5: Check final git diff**

Run:

```bash
git --no-pager diff --stat
git --no-pager diff --check
```

Expected: diff contains only dashboard/schema/RDS writer/tests/README/requirements changes; `diff --check` exits 0.

- [ ] **Step 6: Commit**

Run:

```bash
git add README.md
git commit -m "docs: document ASM dashboard" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

If README was the only remaining uncommitted change, this completes the dashboard implementation branch.

---

## Self-review notes

Spec coverage:

- Current Status landing page: Task 4.
- Historical Results as secondary page: Task 5.
- Whitelist Rules page and deactivation behavior: Tasks 2 and 5.
- `endpoint_name + port` whitelist matching and future scan application: Task 1.
- Current/history whitelist backfill: Task 2.
- KPI and trend metrics: Task 3 and Task 4.
- Filters and 200-row pagination: Task 2 and Task 4.
- Password protection and fail-closed behavior: Task 2 and Task 4.
- Dependencies and docs: Task 4 and Task 6.

Placeholder scan: no forbidden placeholder markers or unspecified cross-references are intentionally left in this plan.

Type consistency: `FilterState`, `PageResult`, auth helpers, DB helpers, and metrics helpers are defined before later tasks consume them.
