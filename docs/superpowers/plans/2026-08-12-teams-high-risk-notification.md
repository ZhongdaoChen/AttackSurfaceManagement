# Teams High Risk Notification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Send a Microsoft Teams Adaptive Card webhook when a completed RDS-backed scan finds newly seen active High risk endpoints.

**Architecture:** Add Teams notification helpers to `rds_writer.py` because the trigger depends on RDS state and the writer already owns `scan_id`, `started_at`, and the database cursor. `RdsFindingWriter.finalize()` will continue resolving stale findings, then query new High risk rows, build an Adaptive Card, and POST it to `TEAMS_WEBHOOK_URL` when configured. Notification failures are logged to stderr and do not fail the scan.

**Tech Stack:** Python 3 standard library, PostgreSQL via existing psycopg cursor, `urllib.request` for Teams webhook POST, `unittest`.

## Global Constraints

- Teams webhook payload must be a top-level Adaptive Card JSON object.
- Use `TEAMS_WEBHOOK_URL` from the existing `.env` loading flow.
- If `TEAMS_WEBHOOK_URL` is absent or empty, skip Teams notification without failing the scan.
- Query active new High risk findings using `first_seen_scan_id = %(scan_id)s`, `risk_level = 'high'`, and `resolved_at IS NULL`.
- Send no Teams message when the query returns zero rows.
- Include at most the first 10 findings in the card.
- If more than 10 new High risk findings exist, the summary text says only the first 10 are shown.
- Truncate `Evidence` and `Recommendation` values to 300 characters each.
- Include the `Open first finding in Wiz` action only when the first displayed finding has a non-empty `wiz_link`.
- Teams notification failures must not roll back scan or RDS writes.
- Do not print `TEAMS_WEBHOOK_URL`.

---

## File Structure

- Modify `rds_writer.py`: add Adaptive Card construction, new High risk query, Teams webhook sender, and call it from `RdsFindingWriter.finalize()`.
- Modify `test_rds_writer.py`: extend fake cursor support for result rows and add tests for card generation, query behavior, missing URL skip, and webhook failure logging.

---

### Task 1: Adaptive Card builder

**Files:**
- Modify: `rds_writer.py`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Produces: `truncate_text(value: Any, limit: int = 300) -> str`
- Produces: `finding_heading(finding: dict[str, Any]) -> str`
- Produces: `build_teams_high_risk_card(scan_id: str, findings: list[dict[str, Any]]) -> dict[str, Any]`

- [ ] **Step 1: Write failing card builder tests**

Add these tests to `test_rds_writer.py` inside `RdsWriterTests`:

```python
    def test_build_teams_high_risk_card_uses_top_level_adaptive_card(self):
        findings = [
            {
                "endpoint_name": "https://app.example.com:9200",
                "wiz_link": "https://app.wiz.io/example",
                "host": "app.example.com",
                "port": 9200,
                "cloud_account_name": "Account One",
                "check_id": "non_standard_open_port",
                "evidence": "Open non-standard internet-facing port 9200.",
                "recommendation": "Close or restrict the port.",
                "first_seen_scan_id": "scan-1",
                "first_seen_at": "2026-08-12T11:20:00+08:00",
            }
        ]

        card = rds_writer.build_teams_high_risk_card("scan-1", findings)

        self.assertEqual(card["type"], "AdaptiveCard")
        self.assertEqual(card["version"], "1.4")
        self.assertEqual(card["body"][0]["text"], "ASM 新增 High Risk 告警")
        self.assertIn("本次扫描发现 1 个新增 High Risk endpoint。", card["body"][1]["text"])
        self.assertEqual(card["actions"][0]["type"], "Action.OpenUrl")
        self.assertEqual(card["actions"][0]["url"], "https://app.wiz.io/example")

    def test_build_teams_high_risk_card_limits_and_truncates_findings(self):
        long_text = "x" * 350
        findings = [
            {
                "endpoint_name": f"https://app-{index}.example.com:9200",
                "host": f"app-{index}.example.com",
                "port": 9200,
                "cloud_account_name": "Account One",
                "check_id": "non_standard_open_port",
                "evidence": long_text,
                "recommendation": long_text,
                "first_seen_scan_id": "scan-1",
                "first_seen_at": "2026-08-12T11:20:00+08:00",
            }
            for index in range(11)
        ]

        card = rds_writer.build_teams_high_risk_card("scan-1", findings)

        self.assertIn("仅展示前 10 个", card["body"][1]["text"])
        finding_titles = [block for block in card["body"] if block.get("weight") == "Bolder" and block.get("separator")]
        self.assertEqual(len(finding_titles), 10)
        fact_sets = [block for block in card["body"] if block.get("type") == "FactSet"]
        evidence_fact = fact_sets[1]["facts"][4]
        self.assertEqual(evidence_fact["title"], "Evidence")
        self.assertTrue(evidence_fact["value"].endswith("..."))
        self.assertLessEqual(len(evidence_fact["value"]), 300)
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_build_teams_high_risk_card_uses_top_level_adaptive_card \
  test_rds_writer.RdsWriterTests.test_build_teams_high_risk_card_limits_and_truncates_findings \
  -v
```

Expected: fail with `AttributeError: module 'rds_writer' has no attribute 'build_teams_high_risk_card'`.

- [ ] **Step 3: Implement card builder helpers**

Add these constants and helpers to `rds_writer.py` after `default_scan_id()`:

```python
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
```

- [ ] **Step 4: Run card builder tests to verify GREEN**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_build_teams_high_risk_card_uses_top_level_adaptive_card \
  test_rds_writer.RdsWriterTests.test_build_teams_high_risk_card_limits_and_truncates_findings \
  -v
```

Expected: `OK`.

- [ ] **Step 5: Commit Task 1**

Run:

```bash
git add rds_writer.py test_rds_writer.py
git commit -m "feat: build teams high risk cards" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 2: Query and send Teams webhook after finalization

**Files:**
- Modify: `rds_writer.py`
- Modify: `test_rds_writer.py`

**Interfaces:**
- Produces: `RdsFindingWriter.new_high_risk_findings() -> list[dict[str, Any]]`
- Produces: `RdsFindingWriter.notify_new_high_risks() -> None`
- Produces: `post_teams_webhook(webhook_url: str, card: dict[str, Any]) -> None`

- [ ] **Step 1: Update test fakes**

Update `FakeCursor` in `test_rds_writer.py`:

```python
class FakeCursor:
    def __init__(self, rowcounts=None, result_rows=None):
        self.executions = []
        self.rowcounts = list(rowcounts or [])
        self.result_rows = list(result_rows or [])
        self.rowcount = 1

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        self.rowcount = self.rowcounts.pop(0) if self.rowcounts else 1

    def fetchall(self):
        return self.result_rows
```

Update `FakeConnection` in `test_rds_writer.py`:

```python
class FakeConnection:
    def __init__(self, rowcounts=None, result_rows=None):
        self.cursor_obj = FakeCursor(rowcounts=rowcounts, result_rows=result_rows)
        self.commits = 0
        self.closed = False
```

- [ ] **Step 2: Write failing query and notification tests**

Add these tests to `test_rds_writer.py`:

```python
    def test_new_high_risk_findings_queries_current_scan_active_highs(self):
        connection = FakeConnection(result_rows=[{"endpoint_name": "https://app.example.com:9200"}])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        rows = writer.new_high_risk_findings()

        query_sql, query_params = connection.cursor_obj.executions[1]
        self.assertIn("FROM asm_current_findings", query_sql)
        self.assertIn("first_seen_scan_id = %(scan_id)s", query_sql)
        self.assertIn("risk_level = 'high'", query_sql)
        self.assertIn("resolved_at IS NULL", query_sql)
        self.assertEqual(query_params["scan_id"], "scan-1")
        self.assertEqual(rows, [{"endpoint_name": "https://app.example.com:9200"}])

    def test_notify_new_high_risks_skips_when_webhook_url_missing(self):
        connection = FakeConnection(result_rows=[{"endpoint_name": "https://app.example.com:9200"}])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        with patch.dict(os.environ, {}, clear=True), patch.object(rds_writer, "post_teams_webhook") as post:
            writer.notify_new_high_risks()

        post.assert_not_called()

    def test_notify_new_high_risks_posts_card_when_rows_exist(self):
        row = {
            "endpoint_name": "https://app.example.com:9200",
            "wiz_link": "https://app.wiz.io/example",
            "host": "app.example.com",
            "port": 9200,
            "cloud_account_name": "Account One",
            "check_id": "non_standard_open_port",
            "evidence": "Open port.",
            "recommendation": "Close it.",
            "first_seen_scan_id": "scan-1",
            "first_seen_at": "2026-08-12T11:20:00+08:00",
        }
        connection = FakeConnection(result_rows=[row])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        with patch.dict(os.environ, {"TEAMS_WEBHOOK_URL": "https://teams.example/webhook"}, clear=True), patch.object(rds_writer, "post_teams_webhook") as post:
            writer.notify_new_high_risks()

        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], "https://teams.example/webhook")
        self.assertEqual(post.call_args.args[1]["type"], "AdaptiveCard")

    def test_finalize_logs_teams_failure_without_raising(self):
        connection = FakeConnection(result_rows=[{"endpoint_name": "https://app.example.com:9200"}])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )
        stderr = StringIO()

        with (
            patch.dict(os.environ, {"TEAMS_WEBHOOK_URL": "https://teams.example/webhook"}, clear=True),
            patch.object(rds_writer, "post_teams_webhook", side_effect=RuntimeError("boom")),
            patch("sys.stderr", stderr),
        ):
            writer.finalize()

        self.assertIn("Teams notification failed: RuntimeError: boom", stderr.getvalue())
```

Add this import to `test_rds_writer.py`:

```python
from io import StringIO
```

- [ ] **Step 3: Run tests to verify RED**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_new_high_risk_findings_queries_current_scan_active_highs \
  test_rds_writer.RdsWriterTests.test_notify_new_high_risks_skips_when_webhook_url_missing \
  test_rds_writer.RdsWriterTests.test_notify_new_high_risks_posts_card_when_rows_exist \
  test_rds_writer.RdsWriterTests.test_finalize_logs_teams_failure_without_raising \
  -v
```

Expected: fail with missing `new_high_risk_findings` or `notify_new_high_risks`.

- [ ] **Step 4: Implement query and notification**

Add imports to `rds_writer.py`:

```python
import sys
import urllib.request
```

Add this function after `build_teams_high_risk_card()`:

```python
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
```

Add these methods to `RdsFindingWriter` before `finalize()`:

```python
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
```

Update `RdsFindingWriter.finalize()` by adding notification after the commit:

```python
        self.connection.commit()
        try:
            self.notify_new_high_risks()
        except Exception as exc:  # noqa: BLE001 - notification must not fail scans.
            print(f"Teams notification failed: {type(exc).__name__}: {exc}", file=sys.stderr)
```

- [ ] **Step 5: Run notification tests to verify GREEN**

Run:

```bash
python3 -m unittest \
  test_rds_writer.RdsWriterTests.test_new_high_risk_findings_queries_current_scan_active_highs \
  test_rds_writer.RdsWriterTests.test_notify_new_high_risks_skips_when_webhook_url_missing \
  test_rds_writer.RdsWriterTests.test_notify_new_high_risks_posts_card_when_rows_exist \
  test_rds_writer.RdsWriterTests.test_finalize_logs_teams_failure_without_raising \
  -v
```

Expected: `OK`.

- [ ] **Step 6: Run all RDS writer tests**

Run:

```bash
python3 -m unittest test_rds_writer -v
```

Expected: `OK`.

- [ ] **Step 7: Commit Task 2**

Run:

```bash
git add rds_writer.py test_rds_writer.py
git commit -m "feat: notify teams for new high risks" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

---

### Task 3: Final verification

**Files:**
- Verify: `rds_writer.py`
- Verify: `test_rds_writer.py`

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: tested Teams webhook notification behavior.

- [ ] **Step 1: Run full unit test suite**

Run:

```bash
python3 -m unittest -v
```

Expected: `OK`.

- [ ] **Step 2: Inspect final diff**

Run:

```bash
git --no-pager diff --stat HEAD~2..HEAD
git --no-pager diff HEAD~2..HEAD -- rds_writer.py test_rds_writer.py
```

Expected: the diff only contains Teams Adaptive Card helpers, current High risk query, webhook POST, finalization notification hook, and tests.

- [ ] **Step 3: Commit verification corrections if needed**

If Step 1 or Step 2 required a correction, commit only the corrected files:

```bash
git add rds_writer.py test_rds_writer.py
git commit -m "fix: stabilize teams high risk notification" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

If Step 1 and Step 2 pass without corrections, do not create an empty commit.
