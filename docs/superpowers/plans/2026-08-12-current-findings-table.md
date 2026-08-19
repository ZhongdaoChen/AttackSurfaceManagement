# Current Findings Table Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve per-scan finding history while maintaining a deduplicated current-state table for active and recently resolved findings.

**Architecture:** Keep `asm_findings` as the immutable scan-history table. Add `asm_current_findings` keyed by a deterministic `finding_key`, and update it from `RdsFindingWriter.write()` after the historical insert succeeds. Add a scan finalization step that marks current findings absent from the completed scan as resolved.

**Tech Stack:** Python 3, PostgreSQL SQL in `schema.sql`, psycopg-compatible parameter dictionaries, `unittest`.

## Global Constraints

- Keep `asm_scans` and `asm_findings` semantics unchanged.
- `asm_findings` continues to store one row per finding per scan, with same-scan duplicates ignored by the existing unique index.
- `asm_current_findings` starts tracking from the first scan after deployment; no historical backfill is required.
- RDS-disabled behavior remains unchanged: no writer opens and no database writes occur when RDS is not configured or `--no-rds` is passed.
- Database write failures must surface to the caller; do not swallow exceptions.
- Use one database connection for historical insert, current-state upsert, and finalization.

---

## File Structure

- Modify `schema.sql`: create `asm_current_findings` and indexes.
- Modify `rds_writer.py`: add deterministic key generation, shared finding parameter construction, current-state upsert, and scan finalization.
- Modify `test_rds_writer.py`: add schema assertions, key-generation tests, current upsert tests, and finalization tests.
- Modify `assess_attack_surface.py`: call `db_writer.finalize()` after a successful scan before closing the writer.
- Modify `test_assess_attack_surface.py`: assert `main()` finalizes the RDS writer before closing it.

---

### Task 1: Add the current findings schema

**Files:**
- Modify: `schema.sql`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Consumes: existing `schema.sql` file.
- Produces: PostgreSQL table `asm_current_findings` with primary key `finding_key` and lifecycle columns used by `rds_writer.RdsFindingWriter`.

- [ ] **Step 1: Write the failing schema test**

Add these imports at the top of `test_rds_writer.py`:

```python
from pathlib import Path
```

Add this test method inside `RdsWriterTests`:

```python
    def test_schema_defines_current_findings_table(self):
        schema = Path("schema.sql").read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS asm_current_findings", schema)
        self.assertIn("finding_key TEXT PRIMARY KEY", schema)
        self.assertIn("first_seen_scan_id TEXT NOT NULL REFERENCES asm_scans(scan_id)", schema)
        self.assertIn("last_seen_scan_id TEXT NOT NULL REFERENCES asm_scans(scan_id)", schema)
        self.assertIn("seen_count INTEGER NOT NULL DEFAULT 1", schema)
        self.assertIn("resolved_at TIMESTAMPTZ", schema)
        self.assertIn("resolved_scan_id TEXT REFERENCES asm_scans(scan_id)", schema)
        self.assertIn("idx_asm_current_findings_active", schema)
        self.assertIn("idx_asm_current_findings_resolved_at", schema)
```

- [ ] **Step 2: Run the schema test to verify it fails**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_schema_defines_current_findings_table -v
```

Expected: `FAIL` because `asm_current_findings` is not in `schema.sql`.

- [ ] **Step 3: Add the current findings table**

Append this block to `schema.sql` after the existing `asm_findings` indexes:

```sql
CREATE TABLE IF NOT EXISTS asm_current_findings (
  finding_key TEXT PRIMARY KEY,

  endpoint_id TEXT,
  endpoint_name TEXT,
  wiz_link TEXT,
  host TEXT,
  port INTEGER,

  cloud_platform TEXT,
  cloud_account_name TEXT,
  tag_emails TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
  exposure_level TEXT,

  check_id TEXT,
  risk_level TEXT,
  whitelisted BOOLEAN NOT NULL DEFAULT FALSE,

  http_status TEXT,
  http_response TEXT,
  llm_opinion TEXT,

  evidence TEXT,
  recommendation TEXT,

  details JSONB NOT NULL DEFAULT '{}'::JSONB,
  raw JSONB NOT NULL,

  first_seen_scan_id TEXT NOT NULL REFERENCES asm_scans(scan_id),
  first_seen_at TIMESTAMPTZ NOT NULL,
  last_seen_scan_id TEXT NOT NULL REFERENCES asm_scans(scan_id),
  last_seen_at TIMESTAMPTZ NOT NULL,
  seen_count INTEGER NOT NULL DEFAULT 1,
  resolved_at TIMESTAMPTZ,
  resolved_scan_id TEXT REFERENCES asm_scans(scan_id),

  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_asm_current_findings_active
  ON asm_current_findings(resolved_at)
  WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_asm_current_findings_resolved_at
  ON asm_current_findings(resolved_at)
  WHERE resolved_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_asm_current_findings_risk_level
  ON asm_current_findings(risk_level);

CREATE INDEX IF NOT EXISTS idx_asm_current_findings_whitelisted
  ON asm_current_findings(whitelisted);

CREATE INDEX IF NOT EXISTS idx_asm_current_findings_endpoint_id
  ON asm_current_findings(endpoint_id);

CREATE INDEX IF NOT EXISTS idx_asm_current_findings_host
  ON asm_current_findings(host);

CREATE INDEX IF NOT EXISTS idx_asm_current_findings_cloud_account_name
  ON asm_current_findings(cloud_account_name);
```

- [ ] **Step 4: Run the schema test to verify it passes**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_schema_defines_current_findings_table -v
```

Expected: `OK`.

- [ ] **Step 5: Commit**

Run:

```bash
git add schema.sql test_rds_writer.py
git commit -m "feat: add current findings schema" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Add deterministic finding parameters and current-state upsert

**Files:**
- Modify: `rds_writer.py`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Consumes: `rds_writer.is_whitelisted_finding(finding: dict[str, Any], low_risk_subscriptions: set[str]) -> bool`.
- Produces: `rds_writer.finding_key(params: dict[str, Any]) -> str`.
- Produces: `rds_writer.finding_insert_params(finding: dict[str, Any], scan_id: str, low_risk_subscriptions: set[str]) -> dict[str, Any]`.
- Produces: `RdsFindingWriter.write(finding: dict[str, Any]) -> None`, which inserts history and then upserts `asm_current_findings` only when the historical insert was not skipped by `ON CONFLICT DO NOTHING`.

- [ ] **Step 1: Update the fake cursor for rowcount-aware tests**

Replace `FakeCursor` in `test_rds_writer.py` with:

```python
class FakeCursor:
    def __init__(self, rowcounts=None):
        self.executions = []
        self.rowcounts = list(rowcounts or [])
        self.rowcount = 1

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        self.rowcount = self.rowcounts.pop(0) if self.rowcounts else 1
```

Replace `FakeConnection` in `test_rds_writer.py` with:

```python
class FakeConnection:
    def __init__(self, rowcounts=None):
        self.cursor_obj = FakeCursor(rowcounts=rowcounts)
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True
```

- [ ] **Step 2: Write failing tests for key generation and current upsert**

Add these test methods inside `RdsWriterTests`:

```python
    def test_finding_key_normalizes_missing_identity_fields(self):
        params = {
            "endpoint_id": None,
            "check_id": "non_standard_open_port",
            "host": "app.example.com",
            "port": None,
        }

        self.assertEqual(
            rds_writer.finding_key(params),
            "b06cee14e86c6a218c0ca7e38685382993f39a45102177928aa51091a62d47f6",
        )

    def test_finding_insert_params_include_current_finding_key(self):
        finding = {
            "endpoint_id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
            "details": {"status": 200},
        }

        params = rds_writer.finding_insert_params(finding, "scan-1", {"fdp"})

        self.assertEqual(
            params["finding_key"],
            "b3926d5be171d88300a90e163ae33299566eb55df61039e1cacdadf1c89c74e6",
        )
        self.assertEqual(params["scan_id"], "scan-1")
        self.assertEqual(params["endpoint_id"], "endpoint-1")
        self.assertEqual(params["http_status"], "200")

    def test_writer_upserts_current_finding_after_history_insert(self):
        connection = FakeConnection()
        finding = {
            "endpoint_id": "endpoint-1",
            "endpoint_name": "https://app.example.com:443",
            "host": "app.example.com",
            "port": 443,
            "cloudPlatform": "AWS",
            "cloudAccountName": "Account One",
            "tagEmails": ["owner@example.com"],
            "exposureLevel": "HIGH",
            "check_id": "llm_sensitive_content",
            "risk_level": "low",
            "evidence": "No sensitive content",
            "recommendation": "Keep monitoring.",
            "wiz_link": "https://app.wiz.io/example",
            "http_response": "No sensitive content",
            "llm_opinion": "No sensitive content Keep monitoring.",
            "details": {"status": 200},
        }

        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T10:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )
        writer.write(finding)

        current_sql, current_params = connection.cursor_obj.executions[2]
        self.assertIn("INSERT INTO asm_current_findings", current_sql)
        self.assertIn("ON CONFLICT (finding_key) DO UPDATE", current_sql)
        self.assertIn("seen_count = asm_current_findings.seen_count + 1", current_sql)
        self.assertIn("resolved_at = NULL", current_sql)
        self.assertEqual(current_params["scan_id"], "scan-1")
        self.assertEqual(current_params["started_at"], "2026-08-12T10:00:00+08:00")
        self.assertEqual(current_params["finding_key"], "b3926d5be171d88300a90e163ae33299566eb55df61039e1cacdadf1c89c74e6")

    def test_writer_skips_current_upsert_when_history_insert_conflicts(self):
        connection = FakeConnection(rowcounts=[1, 0])
        finding = {
            "endpoint_id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
            "details": {"status": 200},
        }

        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T10:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )
        writer.write(finding)

        executed_sql = [sql for sql, _params in connection.cursor_obj.executions]
        self.assertEqual(len(executed_sql), 2)
        self.assertIn("INSERT INTO asm_findings", executed_sql[1])
        self.assertNotIn("asm_current_findings", "\n".join(executed_sql))
```

Keep `test_writer_inserts_scan_and_finding_rows` focused on execution indexes `0` and `1`, which remain the scan insert and historical finding insert. The new current-state upsert appears at execution index `2` and is covered by `test_writer_upserts_current_finding_after_history_insert`.

- [ ] **Step 3: Run the new tests to verify they fail**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_finding_key_normalizes_missing_identity_fields \
  test_rds_writer.RdsWriterTests.test_finding_insert_params_include_current_finding_key \
  test_rds_writer.RdsWriterTests.test_writer_upserts_current_finding_after_history_insert \
  test_rds_writer.RdsWriterTests.test_writer_skips_current_upsert_when_history_insert_conflicts \
  -v
```

Expected: `FAILED` with `AttributeError` for `finding_key` or `finding_insert_params`.

- [ ] **Step 4: Implement key generation and shared parameters**

Add this import near the top of `rds_writer.py`:

```python
import hashlib
```

Add these functions after `is_whitelisted_finding`:

```python
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
    details = finding.get("details")
    if not isinstance(details, dict):
        details = {}
    params = {
        "scan_id": scan_id,
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
        "whitelisted": is_whitelisted_finding(finding, low_risk_subscriptions),
        "http_status": str(details.get("http_status") or details.get("status") or "") or None,
        "http_response": finding.get("http_response"),
        "llm_opinion": finding.get("llm_opinion"),
        "evidence": finding.get("evidence"),
        "recommendation": finding.get("recommendation"),
        "details": json.dumps(details, ensure_ascii=False),
        "raw": json.dumps(finding, ensure_ascii=False),
    }
    params["finding_key"] = finding_key(params)
    return params
```

- [ ] **Step 5: Implement current-state upsert**

In `RdsFindingWriter.__init__`, store `started_at`:

```python
        self.started_at = started_at
```

Replace the beginning of `RdsFindingWriter.write()` through the `params = {...}` block with:

```python
    def write(self, finding: dict[str, Any]) -> None:
        params = finding_insert_params(finding, self.scan_id, self.low_risk_subscriptions)
```

After the existing historical `INSERT INTO asm_findings` `self.cursor.execute(...)` call, replace the single commit with:

```python
        inserted_history = self.cursor.rowcount != 0
        if inserted_history:
            params["started_at"] = self.started_at
            self._upsert_current_finding(params)
        self.connection.commit()
```

Add this method to `RdsFindingWriter` after `write()`:

```python
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
```

- [ ] **Step 6: Run the RDS writer tests**

Run:

```bash
python3 -m unittest test_rds_writer -v
```

Expected: `OK`.

- [ ] **Step 7: Commit**

Run:

```bash
git add rds_writer.py test_rds_writer.py
git commit -m "feat: upsert current findings" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Add scan finalization

**Files:**
- Modify: `rds_writer.py`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Consumes: `RdsFindingWriter.scan_id: str` and `RdsFindingWriter.started_at: str`.
- Produces: `RdsFindingWriter.finalize() -> None`, which marks active current findings absent from the completed scan as resolved.

- [ ] **Step 1: Write the failing finalization test**

Add this test method inside `RdsWriterTests`:

```python
    def test_finalize_marks_findings_missing_from_current_scan_as_resolved(self):
        connection = FakeConnection()
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-2",
            started_at="2026-08-12T11:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        writer.finalize()

        finalize_sql, finalize_params = connection.cursor_obj.executions[1]
        self.assertIn("UPDATE asm_current_findings", finalize_sql)
        self.assertIn("last_seen_scan_id <> %(scan_id)s", finalize_sql)
        self.assertIn("resolved_at IS NULL", finalize_sql)
        self.assertEqual(finalize_params["scan_id"], "scan-2")
        self.assertEqual(finalize_params["resolved_at"], "2026-08-12T11:00:00+08:00")
        self.assertEqual(connection.commits, 2)
```

- [ ] **Step 2: Run the finalization test to verify it fails**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_finalize_marks_findings_missing_from_current_scan_as_resolved -v
```

Expected: `FAILED` with `AttributeError: 'RdsFindingWriter' object has no attribute 'finalize'`.

- [ ] **Step 3: Implement `finalize()`**

Add this method to `RdsFindingWriter` before `close()`:

```python
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
```

- [ ] **Step 4: Run the finalization test**

Run:

```bash
python3 -m unittest test_rds_writer.RdsWriterTests.test_finalize_marks_findings_missing_from_current_scan_as_resolved -v
```

Expected: `OK`.

- [ ] **Step 5: Run all RDS writer tests**

Run:

```bash
python3 -m unittest test_rds_writer -v
```

Expected: `OK`.

- [ ] **Step 6: Commit**

Run:

```bash
git add rds_writer.py test_rds_writer.py
git commit -m "feat: finalize current findings" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 4: Finalize current findings after successful scans

**Files:**
- Modify: `assess_attack_surface.py`
- Modify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: `RdsFindingWriter.finalize() -> None` from Task 3.
- Produces: `assess_attack_surface.main()` calls `db_writer.finalize()` once after all endpoints are processed and before `db_writer.close()`.

- [ ] **Step 1: Write the failing main-flow test update**

In `test_main_uploads_outputs_to_oss_when_configured`, replace:

```python
            rds_writes = []

            class FakeRdsWriter:
                def write(self, item):
                    rds_writes.append(item)

                def close(self):
                    rds_writes.append("closed")
```

with:

```python
            rds_events = []

            class FakeRdsWriter:
                def write(self, item):
                    rds_events.append(("write", item))

                def finalize(self):
                    rds_events.append(("finalize", None))

                def close(self):
                    rds_events.append(("close", None))
```

In the same test, replace:

```python
        self.assertEqual(rds_writes[-1], "closed")
        self.assertEqual(rds_writes[0]["endpoint_name"], "https://app.example.com:443")
```

with:

```python
        self.assertEqual([event for event, _item in rds_events], ["write", "finalize", "close"])
        self.assertEqual(rds_events[0][1]["endpoint_name"], "https://app.example.com:443")
```

- [ ] **Step 2: Run the updated main-flow test to verify it fails**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_main_uploads_outputs_to_oss_when_configured -v
```

Expected: `FAIL` because the event list is `["write", "close"]` and does not include `finalize`.

- [ ] **Step 3: Call `finalize()` after successful scan processing**

In `assess_attack_surface.py`, find the end of the `try:` block in `main()`:

```python
        if csv_writer is not None:
            csv_writer.flush_remaining()
```

Replace it with:

```python
        if csv_writer is not None:
            csv_writer.flush_remaining()
        if db_writer is not None:
            db_writer.finalize()
```

Do not move `db_writer.close()` out of the `finally:` block. If scanning raises an exception before completion, finalization must not run, and close must still run.

- [ ] **Step 4: Run the main-flow test**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_main_uploads_outputs_to_oss_when_configured -v
```

Expected: `OK`.

- [ ] **Step 5: Run the targeted test modules**

Run:

```bash
python3 -m unittest test_rds_writer test_assess_attack_surface -v
```

Expected: `OK`.

- [ ] **Step 6: Commit**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "feat: finalize rds current findings after scans" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 5: Final verification

**Files:**
- Verify: `schema.sql`
- Verify: `rds_writer.py`
- Verify: `assess_attack_surface.py`
- Verify: `test_rds_writer.py`
- Verify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: all previous tasks.
- Produces: a verified implementation with schema, writer, lifecycle finalization, and tests passing.

- [ ] **Step 1: Run all Python unit tests**

Run:

```bash
python3 -m unittest -v
```

Expected: `OK`.

- [ ] **Step 2: Inspect the final diff**

Run:

```bash
git --no-pager diff --stat HEAD~4..HEAD
git --no-pager diff HEAD~4..HEAD -- schema.sql rds_writer.py assess_attack_surface.py test_rds_writer.py test_assess_attack_surface.py
```

Expected: the diff only contains the current findings schema, RDS writer current-state logic, scan finalization call, and matching tests.

- [ ] **Step 3: Commit any verification-only fixes**

If Step 1 or Step 2 required a code correction, commit only the corrected files:

```bash
git add schema.sql rds_writer.py assess_attack_surface.py test_rds_writer.py test_assess_attack_surface.py
git commit -m "fix: stabilize current findings lifecycle" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

If Step 1 and Step 2 already pass with a clean working tree for these files, do not create an empty commit.
