# Specific Finding Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a dashboard-managed finding-level whitelist that suppresses exactly one stable ASM finding across future scans without whitelisting the finding's whole cloud account.

**Architecture:** Keep the existing account-level downgrade and endpoint/port whitelist semantics unchanged. Add a separate `asm_finding_whitelist_rules` table keyed by the existing `finding_key = sha256(endpoint_id, check_id, host, port)`, then wire RDS writes, dashboard creation/deactivation, and Exposure Trend metrics to that rule type. The dashboard must expose finding-level whitelist actions separately from endpoint/port whitelist actions so operators understand the scope before confirming.

**Tech Stack:** Python 3, PostgreSQL SQL in `schema.sql`, psycopg-compatible parameter dictionaries, Streamlit dashboard, standard-library `unittest`.

## Global Constraints

- Finding-level whitelist rules match by existing `rds_writer.finding_key(params: dict[str, Any]) -> str`.
- The finding identity is `endpoint_id + check_id + host + port`.
- Do not whitelist the cloud account for this feature.
- Do not whitelist other checks, hosts, ports, or findings on the same endpoint.
- Preserve existing `LOW_RISK_SUBSCRIPTIONS` account-level downgrade behavior.
- Preserve existing `asm_whitelist_rules` endpoint_name + port behavior.
- Deactivation only affects future scans and does not bulk-revert historical `whitelisted=true` rows.
- Dashboard input validation must surface explicit errors for missing `finding_key`, `reason`, or `operator_name`.
- Do not swallow database write errors.

---

## File Structure

- Modify `schema.sql`: add `asm_finding_whitelist_rules` and indexes.
- Modify `rds_writer.py`: add active finding-rule lookup and include it in `RdsFindingWriter.write()`.
- Modify `asm_dashboard/db.py`: add create/fetch/deactivate APIs for finding rules and include finding-rule effective times in trend SQL.
- Modify `asm_dashboard/app.py`: add a distinct `Whitelist this finding` dialog/action and split whitelist rule management by rule type.
- Modify `README.md`: update dashboard whitelist documentation to describe finding-level and endpoint/port-level scopes.
- Modify `test_rds_writer.py`: add schema and writer lookup tests.
- Modify `test_dashboard_db.py`: add dashboard DB create/fetch/deactivate/trend tests.
- Modify `test_dashboard_app.py`: add UI source tests for separate finding and endpoint whitelist actions.

---

### Task 1: Add the finding whitelist schema

**Files:**
- Modify: `schema.sql`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Consumes: existing PostgreSQL schema file `schema.sql`.
- Produces: table `asm_finding_whitelist_rules`.
- Produces: active lookup index `idx_asm_finding_whitelist_rules_active_lookup`.

- [ ] **Step 1: Write the failing schema test**

Add this test method inside `RdsWriterTests` in `test_rds_writer.py`, immediately after `test_schema_defines_dashboard_whitelist_rules`:

```python
    def test_schema_defines_finding_whitelist_rules(self):
        schema = Path("schema.sql").read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS asm_finding_whitelist_rules", schema)
        self.assertIn("finding_key TEXT NOT NULL", schema)
        self.assertIn("endpoint_name TEXT", schema)
        self.assertIn("host TEXT", schema)
        self.assertIn("port INTEGER", schema)
        self.assertIn("check_id TEXT", schema)
        self.assertIn("cloud_account_name TEXT", schema)
        self.assertIn("reason TEXT NOT NULL", schema)
        self.assertIn("operator_name TEXT NOT NULL", schema)
        self.assertIn("active BOOLEAN NOT NULL DEFAULT TRUE", schema)
        self.assertIn("deactivated_at TIMESTAMPTZ", schema)
        self.assertIn("idx_asm_finding_whitelist_rules_active_lookup", schema)
        self.assertIn("idx_asm_finding_whitelist_rules_active", schema)
```

- [ ] **Step 2: Run the schema test to verify it fails**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_schema_defines_finding_whitelist_rules -v
```

Expected: `FAILED` because `asm_finding_whitelist_rules` does not exist yet.

- [ ] **Step 3: Add the schema**

Append this block to `schema.sql` after the existing `asm_whitelist_rules` indexes:

```sql
CREATE TABLE IF NOT EXISTS asm_finding_whitelist_rules (
  id BIGSERIAL PRIMARY KEY,
  finding_key TEXT NOT NULL,

  endpoint_name TEXT,
  host TEXT,
  port INTEGER,
  check_id TEXT,
  cloud_account_name TEXT,

  reason TEXT NOT NULL,
  operator_name TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deactivated_at TIMESTAMPTZ,
  deactivated_by TEXT,
  deactivation_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_asm_finding_whitelist_rules_active_lookup
  ON asm_finding_whitelist_rules(finding_key)
  WHERE active = TRUE;

CREATE INDEX IF NOT EXISTS idx_asm_finding_whitelist_rules_active
  ON asm_finding_whitelist_rules(active);
```

- [ ] **Step 4: Run the schema test to verify it passes**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_schema_defines_finding_whitelist_rules -v
```

Expected: `OK`.

- [ ] **Step 5: Commit the schema change**

Run:

```bash
git add schema.sql test_rds_writer.py
git commit -m "feat: add finding whitelist schema" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Apply finding whitelist rules during future scans

**Files:**
- Modify: `rds_writer.py`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Consumes: `finding_key(params: dict[str, Any]) -> str`.
- Produces: `dashboard_finding_whitelisted(cursor, finding_key_value: Any) -> bool`.
- Updates: `RdsFindingWriter.write(finding: dict[str, Any]) -> None` so active finding-level rules set `params["whitelisted"] = True`.

- [ ] **Step 1: Add row-by-row `fetchone()` support to the fake cursor**

Replace the `FakeCursor` class constructor and `fetchone()` method in `test_rds_writer.py` with:

```python
class FakeCursor:
    def __init__(self, rowcounts=None, result_rows=None, fetchone_rows=None):
        self.executions = []
        self.rowcounts = list(rowcounts or [])
        self.result_rows = list(result_rows or [])
        self.fetchone_rows = list(fetchone_rows or [])
        self.rowcount = 1

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        self.rowcount = self.rowcounts.pop(0) if self.rowcounts else 1

    def fetchall(self):
        return self.result_rows

    def fetchone(self):
        if self.fetchone_rows:
            return self.fetchone_rows.pop(0)
        return self.result_rows[0] if self.result_rows else None
```

Replace the `FakeConnection` constructor with:

```python
class FakeConnection:
    def __init__(self, rowcounts=None, result_rows=None, fetchone_rows=None):
        self.cursor_obj = FakeCursor(rowcounts=rowcounts, result_rows=result_rows, fetchone_rows=fetchone_rows)
        self.commits = 0
        self.closed = False
```

- [ ] **Step 2: Add a helper for execution lookup**

Add this helper above `class RdsWriterTests` in `test_rds_writer.py`:

```python
def execution_containing(connection: FakeConnection, text: str):
    for sql, params in connection.cursor_obj.executions:
        if text in sql:
            return sql, params
    raise AssertionError(f"No SQL execution contained {text!r}")
```

- [ ] **Step 3: Make existing writer tests independent of execution indexes**

In `test_writer_marks_future_scan_finding_whitelisted_from_dashboard_rule`, replace:

```python
        history_sql, history_params = connection.cursor_obj.executions[2]
        current_sql, current_params = connection.cursor_obj.executions[3]
```

with:

```python
        history_sql, history_params = execution_containing(connection, "INSERT INTO asm_findings")
        current_sql, current_params = execution_containing(connection, "INSERT INTO asm_current_findings")
```

In `test_writer_upserts_current_finding_after_history_insert`, replace:

```python
        current_sql, current_params = connection.cursor_obj.executions[3]
```

with:

```python
        current_sql, current_params = execution_containing(connection, "INSERT INTO asm_current_findings")
```

In `test_writer_skips_current_upsert_when_history_insert_conflicts`, replace the final assertion block with:

```python
        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("INSERT INTO asm_findings", executed_sql)
        self.assertNotIn("INSERT INTO asm_current_findings", executed_sql)
```

- [ ] **Step 4: Write the failing lookup test**

Add this test method after `test_dashboard_whitelisted_queries_active_endpoint_port_rule`:

```python
    def test_dashboard_finding_whitelisted_queries_active_finding_key_rule(self):
        cursor = FakeCursor(result_rows=[{"id": 1}])

        self.assertTrue(rds_writer.dashboard_finding_whitelisted(cursor, "finding-key-1"))

        sql, params = cursor.executions[0]
        self.assertIn("FROM asm_finding_whitelist_rules", sql)
        self.assertIn("active = TRUE", sql)
        self.assertIn("finding_key = %(finding_key)s", sql)
        self.assertEqual(params, {"finding_key": "finding-key-1"})

    def test_dashboard_finding_whitelisted_rejects_blank_key_without_query(self):
        cursor = FakeCursor(result_rows=[{"id": 1}])

        self.assertFalse(rds_writer.dashboard_finding_whitelisted(cursor, " "))

        self.assertEqual(cursor.executions, [])
```

- [ ] **Step 5: Write the failing future-scan behavior tests**

Add these test methods after `test_writer_marks_future_scan_finding_whitelisted_from_dashboard_rule`:

```python
    def test_writer_marks_future_scan_finding_whitelisted_from_finding_rule(self):
        connection = FakeConnection(fetchone_rows=[None, {"id": 7}])
        finding = {
            "endpoint_id": "endpoint-1",
            "endpoint_name": "https://app.example.com:443",
            "host": "app.example.com",
            "port": 443,
            "cloudAccountName": "Account One",
            "check_id": "llm_sensitive_content",
            "risk_level": "high",
            "details": {"status": 200},
        }
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-09-02T09:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions=set(),
        )

        writer.write(finding)

        finding_rule_sql, finding_rule_params = execution_containing(connection, "FROM asm_finding_whitelist_rules")
        history_sql, history_params = execution_containing(connection, "INSERT INTO asm_findings")
        current_sql, current_params = execution_containing(connection, "INSERT INTO asm_current_findings")
        self.assertEqual(
            finding_rule_params,
            {"finding_key": "b3926d5be171d88300a90e163ae33299566eb55df61039e1cacdadf1c89c74e6"},
        )
        self.assertIn("active = TRUE", finding_rule_sql)
        self.assertTrue(history_params["whitelisted"])
        self.assertTrue(current_params["whitelisted"])

    def test_writer_does_not_whitelist_different_finding_in_same_account(self):
        connection = FakeConnection(fetchone_rows=[None, None])
        finding = {
            "endpoint_id": "endpoint-2",
            "endpoint_name": "https://other.example.com:443",
            "host": "other.example.com",
            "port": 443,
            "cloudAccountName": "Account One",
            "check_id": "llm_sensitive_content",
            "risk_level": "high",
            "details": {"status": 200},
        }
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-09-02T09:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions=set(),
        )

        writer.write(finding)

        history_sql, history_params = execution_containing(connection, "INSERT INTO asm_findings")
        current_sql, current_params = execution_containing(connection, "INSERT INTO asm_current_findings")
        self.assertFalse(history_params["whitelisted"])
        self.assertFalse(current_params["whitelisted"])
```

- [ ] **Step 6: Run the targeted tests to verify they fail**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_dashboard_finding_whitelisted_queries_active_finding_key_rule \
  test_rds_writer.RdsWriterTests.test_dashboard_finding_whitelisted_rejects_blank_key_without_query \
  test_rds_writer.RdsWriterTests.test_writer_marks_future_scan_finding_whitelisted_from_finding_rule \
  test_rds_writer.RdsWriterTests.test_writer_does_not_whitelist_different_finding_in_same_account \
  -v
```

Expected: `FAILED` because `dashboard_finding_whitelisted()` is not defined and `RdsFindingWriter.write()` does not query finding-level rules.

- [ ] **Step 7: Add finding-rule lookup**

Add this function in `rds_writer.py` immediately after `dashboard_whitelisted()`:

```python
def dashboard_finding_whitelisted(cursor, finding_key_value: Any) -> bool:
    key = str(finding_key_value or "").strip()
    if not key:
        return False
    cursor.execute(
        """
        SELECT id
        FROM asm_finding_whitelist_rules
        WHERE active = TRUE
          AND finding_key = %(finding_key)s
        LIMIT 1
        """,
        {"finding_key": key},
    )
    return cursor.fetchone() is not None
```

- [ ] **Step 8: Wire finding-rule lookup into writes**

In `RdsFindingWriter.write()` in `rds_writer.py`, replace:

```python
        if dashboard_whitelisted(self.cursor, params.get("endpoint_name"), params.get("port")):
            params["whitelisted"] = True
```

with:

```python
        if dashboard_whitelisted(self.cursor, params.get("endpoint_name"), params.get("port")):
            params["whitelisted"] = True
        elif dashboard_finding_whitelisted(self.cursor, params.get("finding_key")):
            params["whitelisted"] = True
```

- [ ] **Step 9: Run targeted writer tests**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_dashboard_whitelisted_queries_active_endpoint_port_rule \
  test_rds_writer.RdsWriterTests.test_dashboard_finding_whitelisted_queries_active_finding_key_rule \
  test_rds_writer.RdsWriterTests.test_dashboard_finding_whitelisted_rejects_blank_key_without_query \
  test_rds_writer.RdsWriterTests.test_writer_marks_future_scan_finding_whitelisted_from_dashboard_rule \
  test_rds_writer.RdsWriterTests.test_writer_marks_future_scan_finding_whitelisted_from_finding_rule \
  test_rds_writer.RdsWriterTests.test_writer_does_not_whitelist_different_finding_in_same_account \
  test_rds_writer.RdsWriterTests.test_writer_upserts_current_finding_after_history_insert \
  test_rds_writer.RdsWriterTests.test_writer_skips_current_upsert_when_history_insert_conflicts \
  -v
```

Expected: `OK`.

- [ ] **Step 10: Commit the writer change**

Run:

```bash
git add rds_writer.py test_rds_writer.py
git commit -m "feat: apply finding whitelist during scans" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Add dashboard DB APIs for finding whitelist rules

**Files:**
- Modify: `asm_dashboard/db.py`
- Modify: `test_dashboard_db.py`

**Interfaces:**
- Consumes: selected current finding row as `dict[str, Any]`.
- Produces: `create_finding_whitelist_rule(connection, row: dict[str, Any], reason: str, operator_name: str) -> None`.
- Produces: `fetch_finding_whitelist_rules(connection) -> list[dict[str, Any]]`.
- Produces: `deactivate_finding_whitelist_rule(connection, rule_id: int, operator_name: str, reason: str) -> None`.

- [ ] **Step 1: Write failing creation and validation tests**

Add these test methods inside `DashboardDbTests` in `test_dashboard_db.py`, immediately after `test_create_whitelist_rule_inserts_rule_and_backfills_current_and_history`:

```python
    def test_create_finding_whitelist_rule_inserts_rule_and_backfills_only_selected_finding(self):
        connection = FakeConnection()
        row = {
            "finding_key": "finding-key-1",
            "endpoint_id": "endpoint-1",
            "endpoint_name": "https://app.example.com:443",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
            "cloud_account_name": "Account One",
        }

        db.create_finding_whitelist_rule(
            connection,
            row=row,
            reason="Business accepted for this exact finding",
            operator_name="Alice",
        )

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        insert_sql, insert_params = connection.cursor_obj.executions[0]
        current_sql, current_params = connection.cursor_obj.executions[1]
        history_sql, history_params = connection.cursor_obj.executions[2]
        self.assertIn("INSERT INTO asm_finding_whitelist_rules", insert_sql)
        self.assertEqual(insert_params["finding_key"], "finding-key-1")
        self.assertEqual(insert_params["endpoint_name"], "https://app.example.com:443")
        self.assertEqual(insert_params["host"], "app.example.com")
        self.assertEqual(insert_params["port"], 443)
        self.assertEqual(insert_params["check_id"], "llm_sensitive_content")
        self.assertEqual(insert_params["cloud_account_name"], "Account One")
        self.assertIn("UPDATE asm_current_findings", current_sql)
        self.assertIn("WHERE finding_key = %(finding_key)s", current_sql)
        self.assertEqual(current_params["finding_key"], "finding-key-1")
        self.assertIn("UPDATE asm_findings", history_sql)
        self.assertIn("COALESCE(endpoint_id, '') = COALESCE(%(endpoint_id)s, '')", history_sql)
        self.assertIn("COALESCE(check_id, '') = COALESCE(%(check_id)s, '')", history_sql)
        self.assertIn("COALESCE(host, '') = COALESCE(%(host)s, '')", history_sql)
        self.assertIn("COALESCE(port, -1) = COALESCE(%(port)s, -1)", history_sql)
        self.assertNotIn("cloud_account_name = %(cloud_account_name)s", executed_sql)
        self.assertEqual(history_params["endpoint_id"], "endpoint-1")
        self.assertEqual(history_params["check_id"], "llm_sensitive_content")
        self.assertEqual(history_params["host"], "app.example.com")
        self.assertEqual(history_params["port"], 443)
        self.assertEqual(connection.commits, 1)

    def test_create_finding_whitelist_rule_requires_finding_key_reason_and_operator(self):
        connection = FakeConnection()
        valid_row = {
            "finding_key": "finding-key-1",
            "endpoint_id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
        }

        with self.assertRaisesRegex(ValueError, "finding_key is required"):
            db.create_finding_whitelist_rule(connection, row={**valid_row, "finding_key": " "}, reason="ok", operator_name="Alice")
        with self.assertRaisesRegex(ValueError, "reason is required"):
            db.create_finding_whitelist_rule(connection, row=valid_row, reason=" ", operator_name="Alice")
        with self.assertRaisesRegex(ValueError, "operator_name is required"):
            db.create_finding_whitelist_rule(connection, row=valid_row, reason="ok", operator_name=" ")
        self.assertEqual(connection.cursor_obj.executions, [])
        self.assertEqual(connection.commits, 0)
```

- [ ] **Step 2: Write failing fetch and deactivate tests**

Add these test methods after `test_fetch_whitelist_rules_orders_active_first`:

```python
    def test_fetch_finding_whitelist_rules_orders_active_first(self):
        connection = FakeConnection(rows=[{"id": 1, "finding_key": "finding-key-1", "active": True}])

        rows = db.fetch_finding_whitelist_rules(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_finding_whitelist_rules", sql)
        self.assertIn("ORDER BY active DESC, created_at DESC, id DESC", sql)
        self.assertEqual(params, {})
        self.assertEqual(rows, [{"id": 1, "finding_key": "finding-key-1", "active": True}])

    def test_deactivate_finding_whitelist_rule_only_updates_rule_metadata(self):
        connection = FakeConnection()

        db.deactivate_finding_whitelist_rule(connection, rule_id=7, operator_name="Alice", reason="Expired exception")

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("UPDATE asm_finding_whitelist_rules", executed_sql)
        self.assertNotIn("UPDATE asm_current_findings", executed_sql)
        self.assertNotIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)
```

- [ ] **Step 3: Run targeted tests to verify they fail**

Run:

```bash
python3 -m unittest \
  test_dashboard_db.DashboardDbTests.test_create_finding_whitelist_rule_inserts_rule_and_backfills_only_selected_finding \
  test_dashboard_db.DashboardDbTests.test_create_finding_whitelist_rule_requires_finding_key_reason_and_operator \
  test_dashboard_db.DashboardDbTests.test_fetch_finding_whitelist_rules_orders_active_first \
  test_dashboard_db.DashboardDbTests.test_deactivate_finding_whitelist_rule_only_updates_rule_metadata \
  -v
```

Expected: `FAILED` because the new dashboard DB functions do not exist.

- [ ] **Step 4: Add creation API**

Add this function in `asm_dashboard/db.py` immediately after `create_whitelist_rule()`:

```python
def create_finding_whitelist_rule(connection, row: dict[str, Any], reason: str, operator_name: str) -> None:
    finding_key = str(row.get("finding_key") or "").strip()
    clean_reason = reason.strip()
    clean_operator = operator_name.strip()
    if not finding_key:
        raise ValueError("finding_key is required")
    if not clean_reason:
        raise ValueError("reason is required")
    if not clean_operator:
        raise ValueError("operator_name is required")
    params = {
        "finding_key": finding_key,
        "endpoint_id": row.get("endpoint_id"),
        "endpoint_name": row.get("endpoint_name"),
        "host": row.get("host"),
        "port": row.get("port"),
        "check_id": row.get("check_id"),
        "cloud_account_name": row.get("cloud_account_name"),
        "reason": clean_reason,
        "operator_name": clean_operator,
    }
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO asm_finding_whitelist_rules (
          finding_key, endpoint_name, host, port, check_id,
          cloud_account_name, reason, operator_name
        )
        VALUES (
          %(finding_key)s, %(endpoint_name)s, %(host)s, %(port)s, %(check_id)s,
          %(cloud_account_name)s, %(reason)s, %(operator_name)s
        )
        """,
        params,
    )
    cursor.execute(
        """
        WITH latest_scan AS (
          SELECT scan_id
          FROM asm_scans
          ORDER BY started_at DESC, scan_id DESC
          LIMIT 1
        )
        UPDATE asm_current_findings
        SET whitelisted = TRUE,
            resolved_at = now(),
            resolved_scan_id = (SELECT scan_id FROM latest_scan),
            updated_at = now()
        WHERE finding_key = %(finding_key)s
        """,
        params,
    )
    cursor.execute(
        """
        UPDATE asm_findings
        SET whitelisted = TRUE
        WHERE COALESCE(endpoint_id, '') = COALESCE(%(endpoint_id)s, '')
          AND COALESCE(check_id, '') = COALESCE(%(check_id)s, '')
          AND COALESCE(host, '') = COALESCE(%(host)s, '')
          AND COALESCE(port, -1) = COALESCE(%(port)s, -1)
        """,
        params,
    )
    connection.commit()
```

- [ ] **Step 5: Add fetch API**

Add this function in `asm_dashboard/db.py` immediately after `fetch_whitelist_rules()`:

```python
def fetch_finding_whitelist_rules(connection) -> list[dict[str, Any]]:
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT id, finding_key, endpoint_name, host, port, check_id,
               cloud_account_name, reason, operator_name, active,
               created_at, deactivated_at, deactivated_by, deactivation_reason
        FROM asm_finding_whitelist_rules
        ORDER BY active DESC, created_at DESC, id DESC
        """,
        {},
    )
    return _fetch_all(cursor)
```

- [ ] **Step 6: Add deactivate API**

Add this function in `asm_dashboard/db.py` immediately after `deactivate_whitelist_rule()`:

```python
def deactivate_finding_whitelist_rule(connection, rule_id: int, operator_name: str, reason: str) -> None:
    clean_reason = reason.strip()
    clean_operator = operator_name.strip()
    if not clean_reason:
        raise ValueError("reason is required")
    if not clean_operator:
        raise ValueError("operator_name is required")
    cursor = connection.cursor()
    cursor.execute(
        """
        UPDATE asm_finding_whitelist_rules
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

- [ ] **Step 7: Run targeted dashboard DB tests**

Run:

```bash
python3 -m unittest \
  test_dashboard_db.DashboardDbTests.test_create_finding_whitelist_rule_inserts_rule_and_backfills_only_selected_finding \
  test_dashboard_db.DashboardDbTests.test_create_finding_whitelist_rule_requires_finding_key_reason_and_operator \
  test_dashboard_db.DashboardDbTests.test_fetch_finding_whitelist_rules_orders_active_first \
  test_dashboard_db.DashboardDbTests.test_deactivate_finding_whitelist_rule_only_updates_rule_metadata \
  -v
```

Expected: `OK`.

- [ ] **Step 8: Commit dashboard DB APIs**

Run:

```bash
git add asm_dashboard/db.py test_dashboard_db.py
git commit -m "feat: add finding whitelist dashboard APIs" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Include finding-level whitelist rules in trend metrics

**Files:**
- Modify: `asm_dashboard/db.py`
- Modify: `test_dashboard_db.py`

**Interfaces:**
- Consumes: `asm_finding_whitelist_rules.finding_key`.
- Updates: `fetch_trend_rows(connection) -> list[dict[str, Any]]`.
- Produces: Exposure Trend rows where `Cumulative Mitigated` includes finding-level whitelist effective time.

- [ ] **Step 1: Write the failing trend SQL test**

In `test_fetch_trend_rows_returns_active_high_and_cumulative_mitigated_by_scan`, add these assertions after the existing whitelist effective source assertions:

```python
        self.assertIn("finding_rule_effective", sql)
        self.assertIn("asm_finding_whitelist_rules frule", sql)
        self.assertIn("frule.finding_key", sql)
        self.assertIn("finding_whitelist_effective", sql)
        self.assertIn("JOIN finding_rule_effective frule_effective", sql)
        self.assertIn("active_w.whitelist_effective_at > s.started_at", sql)
```

- [ ] **Step 2: Run the trend test to verify it fails**

Run:

```bash
python3 -m unittest test_dashboard_db.DashboardDbTests.test_fetch_trend_rows_returns_active_high_and_cumulative_mitigated_by_scan -v
```

Expected: `FAILED` because the trend SQL does not mention finding-level whitelist rules.

- [ ] **Step 3: Replace the trend SQL**

In `asm_dashboard/db.py`, replace the SQL string inside `fetch_trend_rows()` with this SQL. Keep the surrounding `cursor.execute(..., {"trend_start": EXPOSURE_TREND_START_DATE})` and `return _fetch_all(cursor)`:

```sql
        WITH trend_scans AS (
          SELECT scan_id, started_at
          FROM asm_scans
          WHERE started_at >= %(trend_start)s
        ),
        rule_effective AS (
          SELECT
            r.endpoint_name,
            COALESCE(r.port, -1) AS rule_port,
            MIN(rule_scan.started_at) AS whitelist_effective_at
          FROM asm_whitelist_rules r
          JOIN LATERAL (
            SELECT s.started_at
            FROM asm_scans s
            WHERE s.started_at <= r.created_at
            ORDER BY s.started_at DESC, s.scan_id DESC
            LIMIT 1
          ) rule_scan ON TRUE
          GROUP BY r.endpoint_name, COALESCE(r.port, -1)
        ),
        finding_rule_effective AS (
          SELECT
            frule.finding_key,
            MIN(rule_scan.started_at) AS whitelist_effective_at
          FROM asm_finding_whitelist_rules frule
          JOIN LATERAL (
            SELECT s.started_at
            FROM asm_scans s
            WHERE s.started_at <= frule.created_at
            ORDER BY s.started_at DESC, s.scan_id DESC
            LIMIT 1
          ) rule_scan ON TRUE
          GROUP BY frule.finding_key
        ),
        dashboard_whitelist_effective AS (
          SELECT
            c.finding_key,
            active_r.whitelist_effective_at
          FROM asm_current_findings c
          JOIN rule_effective active_r
            ON active_r.endpoint_name = c.endpoint_name
           AND active_r.rule_port = COALESCE(c.port, -1)
          WHERE c.whitelisted = TRUE
        ),
        finding_whitelist_effective AS (
          SELECT
            c.finding_key,
            frule_effective.whitelist_effective_at
          FROM asm_current_findings c
          JOIN finding_rule_effective frule_effective
            ON frule_effective.finding_key = c.finding_key
          WHERE c.whitelisted = TRUE
        ),
        historical_whitelist_effective AS (
          SELECT
            c.finding_key,
            MIN(ws.started_at) AS whitelist_effective_at
          FROM asm_current_findings c
          JOIN asm_findings f
            ON COALESCE(f.endpoint_id, '') = COALESCE(c.endpoint_id, '')
           AND COALESCE(f.check_id, '') = COALESCE(c.check_id, '')
           AND COALESCE(f.host, '') = COALESCE(c.host, '')
           AND COALESCE(f.port, -1) = COALESCE(c.port, -1)
           AND f.whitelisted = TRUE
          JOIN asm_scans ws ON ws.scan_id = f.scan_id
          LEFT JOIN rule_effective fr
            ON fr.endpoint_name = f.endpoint_name
           AND fr.rule_port = COALESCE(f.port, -1)
          LEFT JOIN finding_rule_effective ffr
            ON ffr.finding_key = c.finding_key
          WHERE (
            (fr.whitelist_effective_at IS NULL AND ffr.whitelist_effective_at IS NULL)
            OR (fr.whitelist_effective_at IS NOT NULL AND ws.started_at >= fr.whitelist_effective_at)
            OR (ffr.whitelist_effective_at IS NOT NULL AND ws.started_at >= ffr.whitelist_effective_at)
          )
          GROUP BY c.finding_key
        ),
        resolved_whitelist_effective AS (
          SELECT
            c.finding_key,
            rs.started_at AS whitelist_effective_at
          FROM asm_current_findings c
          JOIN asm_scans rs ON rs.scan_id = c.resolved_scan_id
        ),
        whitelist_effective AS (
          SELECT finding_key, MIN(whitelist_effective_at) AS whitelist_effective_at
          FROM (
            SELECT finding_key, whitelist_effective_at FROM dashboard_whitelist_effective
            UNION ALL
            SELECT finding_key, whitelist_effective_at FROM finding_whitelist_effective
            UNION ALL
            SELECT finding_key, whitelist_effective_at FROM resolved_whitelist_effective
            UNION ALL
            SELECT finding_key, whitelist_effective_at FROM historical_whitelist_effective
          ) combined
          GROUP BY finding_key
        ),
        active_high_counts AS (
          SELECT
            s.scan_id,
            COUNT(*) AS active_high_count
          FROM trend_scans s
          JOIN asm_findings active_f ON active_f.scan_id = s.scan_id
          LEFT JOIN asm_current_findings active_c
            ON COALESCE(active_c.endpoint_id, '') = COALESCE(active_f.endpoint_id, '')
           AND COALESCE(active_c.check_id, '') = COALESCE(active_f.check_id, '')
           AND COALESCE(active_c.host, '') = COALESCE(active_f.host, '')
           AND COALESCE(active_c.port, -1) = COALESCE(active_f.port, -1)
          LEFT JOIN whitelist_effective active_w
            ON active_w.finding_key = active_c.finding_key
          WHERE active_f.risk_level = 'high'
            AND (
              active_f.whitelisted = FALSE
              OR (
                active_f.whitelisted = TRUE
                AND active_w.whitelist_effective_at IS NOT NULL
                AND active_w.whitelist_effective_at > s.started_at
              )
            )
          GROUP BY s.scan_id
        ),
        mitigated_counts AS (
          SELECT
            s.scan_id,
            COUNT(*) AS mitigated_count
          FROM trend_scans s
          JOIN asm_current_findings c ON c.first_seen_at <= s.started_at
          LEFT JOIN whitelist_effective w ON w.finding_key = c.finding_key
          WHERE c.risk_level = 'high'
            AND (
              c.resolved_at <= s.started_at
              OR w.whitelist_effective_at <= s.started_at
            )
          GROUP BY s.scan_id
        )
        SELECT
          s.scan_id,
          s.started_at AS scan_started_at,
          COALESCE(a.active_high_count, 0) AS active_high_count,
          COALESCE(m.mitigated_count, 0) AS mitigated_count
        FROM trend_scans s
        LEFT JOIN active_high_counts a ON a.scan_id = s.scan_id
        LEFT JOIN mitigated_counts m ON m.scan_id = s.scan_id
        ORDER BY s.started_at ASC, s.scan_id ASC
```

- [ ] **Step 4: Run the trend test**

Run:

```bash
python3 -m unittest test_dashboard_db.DashboardDbTests.test_fetch_trend_rows_returns_active_high_and_cumulative_mitigated_by_scan -v
```

Expected: `OK`.

- [ ] **Step 5: Commit trend metrics**

Run:

```bash
git add asm_dashboard/db.py test_dashboard_db.py
git commit -m "feat: count finding whitelist in exposure trend" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: Add distinct dashboard UI for finding-level whitelisting

**Files:**
- Modify: `asm_dashboard/app.py`
- Modify: `test_dashboard_app.py`

**Interfaces:**
- Consumes: `db.create_finding_whitelist_rule(connection, row: dict[str, Any], reason: str, operator_name: str) -> None`.
- Consumes: `db.fetch_finding_whitelist_rules(connection) -> list[dict[str, Any]]`.
- Consumes: `db.deactivate_finding_whitelist_rule(connection, rule_id: int, operator_name: str, reason: str) -> None`.
- Updates: `render_finding_row(connection, row: dict[str, Any], page_key: str, index: int, allow_whitelist: bool) -> None`.
- Updates: `whitelist_rules_page(connection) -> None`.

- [ ] **Step 1: Write failing source tests for distinct actions**

Add these test methods inside `DashboardAppTests` in `test_dashboard_app.py`:

```python
    def test_current_row_exposes_distinct_finding_and_endpoint_whitelist_actions(self):
        source = Path("asm_dashboard/app.py").read_text(encoding="utf-8")
        start = source.index("def render_finding_row")
        end = source.index("\n\ndef render_finding_table", start)
        body = source[start:end]

        self.assertIn("Whitelist this finding", body)
        self.assertIn("Whitelist endpoint + port", body)
        self.assertIn("open_finding_whitelist_dialog", body)
        self.assertIn("open_whitelist_dialog", body)

    def test_finding_whitelist_dialog_calls_finding_rule_api_and_explains_scope(self):
        source = Path("asm_dashboard/app.py").read_text(encoding="utf-8")
        start = source.index("def open_finding_whitelist_dialog")
        end = source.index("\n\ndef render_link", start)
        body = source[start:end]

        self.assertIn("Whitelist this finding", body)
        self.assertIn("does not whitelist the cloud account", body)
        self.assertIn("does not whitelist other findings on the same endpoint", body)
        self.assertIn("db.create_finding_whitelist_rule", body)
```

- [ ] **Step 2: Write failing source test for separated rules page**

Add this test method inside `DashboardAppTests`:

```python
    def test_whitelist_rules_page_separates_finding_and_endpoint_rules(self):
        source = Path("asm_dashboard/app.py").read_text(encoding="utf-8")
        start = source.index("def whitelist_rules_page")
        end = source.index("\n\ndef main", start)
        body = source[start:end]

        self.assertIn("Finding Whitelist Rules", body)
        self.assertIn("Endpoint/Port Whitelist Rules", body)
        self.assertIn("db.fetch_finding_whitelist_rules", body)
        self.assertIn("db.fetch_whitelist_rules", body)
        self.assertIn("db.deactivate_finding_whitelist_rule", source)
        self.assertIn("db.deactivate_whitelist_rule", source)
```

- [ ] **Step 3: Run UI tests to verify they fail**

Run:

```bash
python3 -m unittest \
  test_dashboard_app.DashboardAppTests.test_current_row_exposes_distinct_finding_and_endpoint_whitelist_actions \
  test_dashboard_app.DashboardAppTests.test_finding_whitelist_dialog_calls_finding_rule_api_and_explains_scope \
  test_dashboard_app.DashboardAppTests.test_whitelist_rules_page_separates_finding_and_endpoint_rules \
  -v
```

Expected: `FAILED` because the finding-level UI functions and labels do not exist.

- [ ] **Step 4: Rename the existing dialog title and submit button**

In `asm_dashboard/app.py`, update `open_whitelist_dialog()` so the dialog title and submit button clarify endpoint/port scope:

```python
def open_whitelist_dialog(connection, row: dict[str, Any], dialog_key: str) -> None:
    @st.dialog("Whitelist endpoint + port")
    def whitelist_dialog() -> None:
        st.write(f"Endpoint: `{row.get('endpoint_name')}`")
        st.write(f"Port: `{row.get('port')}`")
        st.caption("This rule applies to future findings with the same endpoint name and port.")
        with st.form(dialog_key):
            reason = st.text_area("Reason")
            operator_name = st.text_input("Operator Name")
            submitted = st.form_submit_button("Confirm endpoint + port whitelist")
        if submitted:
            try:
                db.create_whitelist_rule(
                    connection,
                    endpoint_name=str(row.get("endpoint_name") or ""),
                    port=row.get("port"),
                    reason=reason,
                    operator_name=operator_name,
                )
            except Exception as exc:
                st.error(f"Whitelist failed: {type(exc).__name__}: {exc}")
            else:
                st.success("Endpoint + port whitelist rule created and matching current/history findings updated.")
                st.rerun()

    whitelist_dialog()
```

- [ ] **Step 5: Add the finding-level dialog**

Add this function immediately after `open_whitelist_dialog()` in `asm_dashboard/app.py`:

```python
def open_finding_whitelist_dialog(connection, row: dict[str, Any], dialog_key: str) -> None:
    @st.dialog("Whitelist this finding")
    def finding_whitelist_dialog() -> None:
        st.write(f"Finding key: `{row.get('finding_key')}`")
        st.write(f"Endpoint: `{row.get('endpoint_name')}`")
        st.write(f"Host: `{row.get('host')}`")
        st.write(f"Port: `{row.get('port')}`")
        st.write(f"Check: `{row.get('check_id')}`")
        st.caption(
            "This rule does not whitelist the cloud account, does not whitelist other findings on the same endpoint, "
            "and does not whitelist other checks, hosts, or ports."
        )
        with st.form(dialog_key):
            reason = st.text_area("Reason")
            operator_name = st.text_input("Operator Name")
            submitted = st.form_submit_button("Confirm finding whitelist")
        if submitted:
            try:
                db.create_finding_whitelist_rule(
                    connection,
                    row=row,
                    reason=reason,
                    operator_name=operator_name,
                )
            except Exception as exc:
                st.error(f"Finding whitelist failed: {type(exc).__name__}: {exc}")
            else:
                st.success("Finding whitelist rule created and only this specific finding was updated.")
                st.rerun()

    finding_whitelist_dialog()
```

- [ ] **Step 6: Add separate row actions**

In `render_finding_row()` in `asm_dashboard/app.py`, replace the expanded whitelist button block:

```python
        if allow_whitelist and st.button("Whitelist", key=f"open_whitelist_{page_key}_{model['identity']}"):
            open_whitelist_dialog(connection, row, f"whitelist_{page_key}_{model['identity']}")
```

with:

```python
        if allow_whitelist:
            finding_col, endpoint_col = st.columns(2)
            if finding_col.button(
                "Whitelist this finding",
                key=f"open_finding_whitelist_{page_key}_{model['identity']}",
            ):
                open_finding_whitelist_dialog(connection, row, f"finding_whitelist_{page_key}_{model['identity']}")
            if endpoint_col.button(
                "Whitelist endpoint + port",
                key=f"open_endpoint_whitelist_{page_key}_{model['identity']}",
            ):
                open_whitelist_dialog(connection, row, f"endpoint_whitelist_{page_key}_{model['identity']}")
```

- [ ] **Step 7: Add finding-rule renderer**

Add this function immediately before `whitelist_rules_page()` in `asm_dashboard/app.py`:

```python
def render_finding_whitelist_rules(connection) -> None:
    rules = db.fetch_finding_whitelist_rules(connection)
    if not rules:
        st.info("No finding whitelist rules have been created.")
        return
    header = st.columns([0.8, 2.2, 2.4, 1.6, 0.8, 1.4, 1.6, 1.0, 2.0, 1.4, 1.4])
    titles = [
        "Details",
        "Finding Key",
        "Endpoint Name",
        "Host",
        "Port",
        "Check ID",
        "Cloud Account",
        "Active",
        "Reason",
        "Operator Name",
        "Created At",
    ]
    for column, title in zip(header, titles, strict=True):
        column.markdown(f"**{title}**")
    for index, rule in enumerate(rules, start=1):
        identity = str(rule.get("id") or index)
        expanded_key = "expanded_finding_whitelist_rule"
        columns = st.columns([0.8, 2.2, 2.4, 1.6, 0.8, 1.4, 1.6, 1.0, 2.0, 1.4, 1.4])
        is_expanded = st.session_state.get(expanded_key) == identity
        if columns[0].button(expand_icon(is_expanded), key=f"expand_finding_whitelist_rule_{identity}"):
            st.session_state[expanded_key] = None if is_expanded else identity
            st.rerun()
        columns[1].write(rule.get("finding_key") or "")
        columns[2].write(rule.get("endpoint_name") or "")
        columns[3].write(rule.get("host") or "")
        columns[4].write(rule.get("port") or "")
        columns[5].write(rule.get("check_id") or "")
        columns[6].write(rule.get("cloud_account_name") or "")
        columns[7].write("Yes" if rule.get("active") else "No")
        columns[8].write(rule.get("reason") or "")
        columns[9].write(rule.get("operator_name") or "")
        columns[10].write(display_date_only(rule.get("created_at")))
        if st.session_state.get(expanded_key) != identity:
            continue
        st.json(rule, expanded=ROW_DETAIL_JSON_EXPANDED)
        if not rule.get("active"):
            st.info("This finding rule is already inactive.")
            continue
        with st.form(f"deactivate_finding_rule_{identity}"):
            operator_name = st.text_input("Operator name")
            reason = st.text_area("Deactivation reason")
            submitted = st.form_submit_button("Deactivate finding rule")
        if submitted:
            try:
                db.deactivate_finding_whitelist_rule(
                    connection,
                    rule_id=int(rule["id"]),
                    operator_name=operator_name,
                    reason=reason,
                )
            except Exception as exc:
                st.error(f"Deactivate failed: {type(exc).__name__}: {exc}")
            else:
                st.success("Finding whitelist rule deactivated. Existing whitelisted findings were not reverted.")
                st.rerun()
```

- [ ] **Step 8: Extract endpoint-rule renderer**

Create this function by moving the current body of `whitelist_rules_page()` into a new helper immediately after `render_finding_whitelist_rules()`:

```python
def render_endpoint_whitelist_rules(connection) -> None:
    rules = db.fetch_whitelist_rules(connection)
    if not rules:
        st.info("No endpoint/port whitelist rules have been created.")
        return
    header = st.columns([0.8, 2.8, 0.8, 1.0, 2.4, 1.5, 1.5])
    for column, title in zip(
        header,
        ["Details", "Endpoint Name", "Port", "Active", "Reason", "Operator Name", "Created At"],
        strict=True,
    ):
        column.markdown(f"**{title}**")
    for index, rule in enumerate(rules, start=1):
        identity = str(rule.get("id") or index)
        expanded_key = "expanded_whitelist_rule"
        columns = st.columns([0.8, 2.8, 0.8, 1.0, 2.4, 1.5, 1.5])
        is_expanded = st.session_state.get(expanded_key) == identity
        if columns[0].button(expand_icon(is_expanded), key=f"expand_whitelist_rule_{identity}"):
            st.session_state[expanded_key] = None if is_expanded else identity
            st.rerun()
        columns[1].write(rule.get("endpoint_name") or "")
        columns[2].write(rule.get("port") or "")
        columns[3].write("Yes" if rule.get("active") else "No")
        columns[4].write(rule.get("reason") or "")
        columns[5].write(rule.get("operator_name") or "")
        columns[6].write(display_date_only(rule.get("created_at")))
        if st.session_state.get(expanded_key) != identity:
            continue
        st.json(rule, expanded=ROW_DETAIL_JSON_EXPANDED)
        if not rule.get("active"):
            st.info("This rule is already inactive.")
            continue
        with st.form(f"deactivate_rule_{identity}"):
            operator_name = st.text_input("Operator name")
            reason = st.text_area("Deactivation reason")
            submitted = st.form_submit_button("Deactivate endpoint + port rule")
        if submitted:
            try:
                db.deactivate_whitelist_rule(
                    connection,
                    rule_id=int(rule["id"]),
                    operator_name=operator_name,
                    reason=reason,
                )
            except Exception as exc:
                st.error(f"Deactivate failed: {type(exc).__name__}: {exc}")
            else:
                st.success("Endpoint + port whitelist rule deactivated. Existing whitelisted findings were not reverted.")
                st.rerun()
```

- [ ] **Step 9: Replace `whitelist_rules_page()`**

Replace `whitelist_rules_page()` with:

```python
def whitelist_rules_page(connection) -> None:
    st.title("Whitelist Rules")
    st.caption("Manage finding-level rules separately from endpoint/port whitelist rules.")
    finding_tab, endpoint_tab = st.tabs(["Finding Whitelist Rules", "Endpoint/Port Whitelist Rules"])
    with finding_tab:
        render_finding_whitelist_rules(connection)
    with endpoint_tab:
        render_endpoint_whitelist_rules(connection)
```

- [ ] **Step 10: Run targeted UI tests**

Run:

```bash
python3 -m unittest \
  test_dashboard_app.DashboardAppTests.test_current_row_exposes_distinct_finding_and_endpoint_whitelist_actions \
  test_dashboard_app.DashboardAppTests.test_finding_whitelist_dialog_calls_finding_rule_api_and_explains_scope \
  test_dashboard_app.DashboardAppTests.test_whitelist_rules_page_separates_finding_and_endpoint_rules \
  test_dashboard_app.DashboardAppTests.test_whitelist_rules_page_does_not_use_streamlit_dataframe \
  -v
```

Expected: `OK`.

- [ ] **Step 11: Commit dashboard UI**

Run:

```bash
git add asm_dashboard/app.py test_dashboard_app.py
git commit -m "feat: separate finding whitelist dashboard UI" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 6: Update documentation and run final verification

**Files:**
- Modify: `README.md`
- Verify: `schema.sql`
- Verify: `rds_writer.py`
- Verify: `asm_dashboard/db.py`
- Verify: `asm_dashboard/app.py`
- Verify: `test_rds_writer.py`
- Verify: `test_dashboard_db.py`
- Verify: `test_dashboard_app.py`

**Interfaces:**
- Produces: user-facing README documentation for the two dashboard whitelist scopes.
- Produces: final test evidence for the whole feature.

- [ ] **Step 1: Update README dashboard whitelist text**

In `README.md`, replace the dashboard paragraph that currently says:

```markdown
默认页面是 Current Status，只展示 active 且非 whitelisted 的 current findings。Historical Results 在侧边栏中按扫描日期查看历史结果，并包含 whitelisted 记录。Whitelist Rules 展示 dashboard 创建的 `endpoint_name + port` 白名单规则并支持停用；停用只影响未来扫描，不回滚已经标记为 whitelisted 的 findings。
```

with:

```markdown
默认页面是 Current Status，只展示 active 且非 whitelisted 的 current findings。Historical Results 在侧边栏中按扫描日期查看历史结果，并包含 whitelisted 记录。Current Status 展开单条 finding 后可以选择 `Whitelist this finding`（只对白名单中的 `finding_key = endpoint_id + check_id + host + port` 生效）或 `Whitelist endpoint + port`（对相同 endpoint name 和 port 生效）。Whitelist Rules 分开展示 finding 级规则和 endpoint/port 规则，并支持停用；停用只影响未来扫描，不回滚已经标记为 whitelisted 的 findings。
```

- [ ] **Step 2: Run RDS writer tests**

Run:

```bash
python3 -m unittest test_rds_writer -v
```

Expected: `OK`.

- [ ] **Step 3: Run dashboard DB tests**

Run:

```bash
python3 -m unittest test_dashboard_db -v
```

Expected: `OK`.

- [ ] **Step 4: Run dashboard app tests**

Run:

```bash
python3 -m unittest test_dashboard_app -v
```

Expected: `OK`.

- [ ] **Step 5: Run related dashboard metrics tests**

Run:

```bash
python3 -m unittest test_dashboard_metrics -v
```

Expected: `OK`.

- [ ] **Step 6: Commit docs and final verified state**

Run:

```bash
git add README.md
git commit -m "docs: document finding whitelist scopes" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

- [ ] **Step 7: Check final git status**

Run:

```bash
git --no-pager status --short
```

Expected: no tracked-file changes from this feature. Existing unrelated untracked files may still appear and should not be added unless the user explicitly asks.
