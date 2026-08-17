# Exposure Trend Active High and Cumulative Mitigated Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Update the Exposure Trend chart so `High Risk` shows active high findings at each scan point and `Mitigated` shows cumulative high-risk mitigations, including whitelisted findings.

**Architecture:** Keep chart rendering unchanged. Compute lifecycle counts in `asm_dashboard.db.fetch_trend_rows()` and keep `asm_dashboard.metrics.trend_frame()` as a thin transformer from database rows to Plotly-ready records.

**Tech Stack:** Python 3, Streamlit dashboard modules, PostgreSQL SQL, pandas, unittest.

## Global Constraints

- `High Risk` trend uses active semantics aligned with Current Status Active High: high risk, active at the scan point, and not whitelisted as of that scan.
- `Mitigated` trend is cumulative up to each scan point.
- High-risk findings marked `whitelisted = TRUE` count as mitigated starting from the first scan where they are known to be whitelisted.
- Do not change chart colors, axes, titles, filters, or Current Status KPI behavior.
- Do not add dependencies or schema migrations.

---

## File Structure

- Modify `asm_dashboard/db.py`: change `fetch_trend_rows()` SQL to return `active_high_count` and cumulative `mitigated_count` per scan. Use existing `asm_whitelist_rules` rows to avoid treating dashboard whitelist history backfill as if it existed before the whitelist rule was created.
- Modify `asm_dashboard/metrics.py`: change `trend_frame()` to map `active_high_count` directly to `High Risk`.
- Modify `test_dashboard_db.py`: replace the trend SQL test with assertions for active high, cumulative mitigation, whitelist effective scan, and aliases.
- Modify `test_dashboard_metrics.py`: replace the trend frame test expectations so High Risk is not reduced by Mitigated.

---

### Task 1: Database Trend Counts

**Files:**
- Modify: `asm_dashboard/db.py:236-258`
- Test: `test_dashboard_db.py:115-137`

**Interfaces:**
- Consumes: `db.EXPOSURE_TREND_START_DATE`
- Produces: `fetch_trend_rows(connection) -> list[dict[str, Any]]` where each row has `scan_id`, `scan_started_at`, `active_high_count`, and `mitigated_count`.

- [ ] **Step 1: Write the failing database SQL test**

Replace `test_fetch_trend_rows_groups_high_risk_and_mitigated_counts_by_scan` in `test_dashboard_db.py` with:

```python
    def test_fetch_trend_rows_returns_active_high_and_cumulative_mitigated_by_scan(self):
        connection = FakeConnection(
            rows=[
                {
                    "scan_id": "scan-1",
                    "scan_started_at": "2026-08-14",
                    "active_high_count": 2,
                    "mitigated_count": 5,
                }
            ]
        )

        rows = db.fetch_trend_rows(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_scans s", sql)
        self.assertIn("active_high_count", sql)
        self.assertIn("mitigated_count", sql)
        self.assertIn("COUNT(DISTINCT c.finding_key) FILTER", sql)
        self.assertIn("c.risk_level = 'high'", sql)
        self.assertIn("c.first_seen_at <= s.started_at", sql)
        self.assertIn("c.last_seen_at >= s.started_at", sql)
        self.assertIn("(c.resolved_at IS NULL OR c.resolved_at > s.started_at)", sql)
        self.assertIn("(w.whitelist_effective_at IS NULL OR w.whitelist_effective_at > s.started_at)", sql)
        self.assertIn("c.resolved_at <= s.started_at", sql)
        self.assertIn("w.whitelist_effective_at <= s.started_at", sql)
        self.assertIn("whitelist_effective", sql)
        self.assertIn("LEFT JOIN asm_findings f", sql)
        self.assertIn("f.whitelisted = TRUE", sql)
        self.assertIn("dashboard_whitelist_effective", sql)
        self.assertIn("asm_whitelist_rules r", sql)
        self.assertIn("s.started_at <= r.created_at", sql)
        self.assertIn("ORDER BY s.started_at DESC, s.scan_id DESC", sql)
        self.assertIn("historical_whitelist_effective", sql)
        self.assertIn("resolved_whitelist_effective", sql)
        self.assertIn("LEFT JOIN asm_scans rs ON rs.scan_id = c.resolved_scan_id", sql)
        self.assertIn("WHERE s.started_at >= %(trend_start)s", sql)
        self.assertIn("GROUP BY s.scan_id, s.started_at", sql)
        self.assertEqual(params, {"trend_start": db.EXPOSURE_TREND_START_DATE})
        self.assertEqual(
            rows,
            [
                {
                    "scan_id": "scan-1",
                    "scan_started_at": "2026-08-14",
                    "active_high_count": 2,
                    "mitigated_count": 5,
                }
            ],
        )
```

- [ ] **Step 2: Run the focused failing test**

Run:

```bash
python -m unittest test_dashboard_db.DashboardDbTests.test_fetch_trend_rows_returns_active_high_and_cumulative_mitigated_by_scan
```

Expected: `FAIL` because the current SQL still returns `high_risk_count`, joins `asm_findings f` by scan, and joins `asm_current_findings c` only by `resolved_scan_id`.

- [ ] **Step 3: Implement the database query**

Replace `fetch_trend_rows()` in `asm_dashboard/db.py` with:

```python
def fetch_trend_rows(connection) -> list[dict[str, Any]]:
    cursor = connection.cursor()
    cursor.execute(
        """
        WITH dashboard_whitelist_effective AS (
          SELECT
            c.finding_key,
            MIN(rule_scan.started_at) AS whitelist_effective_at
          FROM asm_current_findings c
          JOIN asm_whitelist_rules r
            ON r.endpoint_name = c.endpoint_name
           AND COALESCE(r.port, -1) = COALESCE(c.port, -1)
          JOIN LATERAL (
            SELECT s.started_at
            FROM asm_scans s
            WHERE s.started_at <= r.created_at
            ORDER BY s.started_at DESC, s.scan_id DESC
            LIMIT 1
          ) rule_scan ON TRUE
          WHERE c.whitelisted = TRUE
          GROUP BY c.finding_key
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
          WHERE c.whitelisted = TRUE
          GROUP BY c.finding_key
        ),
        resolved_whitelist_effective AS (
          SELECT
            c.finding_key,
            rs.started_at AS whitelist_effective_at
          FROM asm_current_findings c
          JOIN asm_scans rs ON rs.scan_id = c.resolved_scan_id
          WHERE c.whitelisted = TRUE
        ),
        whitelist_effective AS (
          SELECT
            c.finding_key,
            COALESCE(
              d.whitelist_effective_at,
              r.whitelist_effective_at,
              h.whitelist_effective_at
            ) AS whitelist_effective_at
          FROM asm_current_findings c
          LEFT JOIN dashboard_whitelist_effective d ON d.finding_key = c.finding_key
          LEFT JOIN resolved_whitelist_effective r ON r.finding_key = c.finding_key
          LEFT JOIN historical_whitelist_effective h ON h.finding_key = c.finding_key
        )
        SELECT
          s.scan_id,
          s.started_at AS scan_started_at,
          COUNT(DISTINCT c.finding_key) FILTER (
            WHERE c.risk_level = 'high'
              AND c.first_seen_at <= s.started_at
              AND c.last_seen_at >= s.started_at
              AND (c.resolved_at IS NULL OR c.resolved_at > s.started_at)
              AND (w.whitelist_effective_at IS NULL OR w.whitelist_effective_at > s.started_at)
          ) AS active_high_count,
          COUNT(DISTINCT c.finding_key) FILTER (
            WHERE c.risk_level = 'high'
              AND (
                c.resolved_at <= s.started_at
                OR w.whitelist_effective_at <= s.started_at
              )
          ) AS mitigated_count
        FROM asm_scans s
        LEFT JOIN asm_current_findings c ON c.first_seen_at <= s.started_at
        LEFT JOIN whitelist_effective w ON w.finding_key = c.finding_key
        WHERE s.started_at >= %(trend_start)s
        GROUP BY s.scan_id, s.started_at
        ORDER BY s.started_at ASC, s.scan_id ASC
        """,
        {"trend_start": EXPOSURE_TREND_START_DATE},
    )
    return _fetch_all(cursor)
```

- [ ] **Step 4: Run the focused database test**

Run:

```bash
python -m unittest test_dashboard_db.DashboardDbTests.test_fetch_trend_rows_returns_active_high_and_cumulative_mitigated_by_scan
```

Expected: `OK`.

- [ ] **Step 5: Commit the database query change**

Run:

```bash
git add asm_dashboard/db.py test_dashboard_db.py
git commit -m "fix: compute exposure trend lifecycle counts" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit succeeds. If unrelated untracked files exist, do not add them.

---

### Task 2: Trend Frame Mapping

**Files:**
- Modify: `asm_dashboard/metrics.py:49-73`
- Test: `test_dashboard_metrics.py:95-122`

**Interfaces:**
- Consumes: `fetch_trend_rows()` rows containing `active_high_count` and `mitigated_count`.
- Produces: `trend_frame(rows: list[dict[str, Any]]) -> pandas.DataFrame` with columns `date`, `scan_id`, `metric`, `count`.

- [ ] **Step 1: Write the failing metrics test**

Replace `test_trend_frame_uses_scan_dates_and_high_risk_counts` in `test_dashboard_metrics.py` with:

```python
    def test_trend_frame_maps_active_high_and_cumulative_mitigated_counts(self):
        rows = [
            {
                "scan_id": "scan-1",
                "scan_started_at": datetime.datetime(2026, 8, 12, 10, 0),
                "active_high_count": 2,
                "mitigated_count": 1,
            },
            {
                "scan_id": "scan-2",
                "scan_started_at": "2026-08-13T12:00:00+08:00",
                "active_high_count": 5,
                "mitigated_count": 3,
            },
        ]

        frame = metrics.trend_frame(rows)

        self.assertEqual(
            frame.to_dict("records"),
            [
                {"date": datetime.date(2026, 8, 12), "scan_id": "scan-1", "metric": "High Risk", "count": 2},
                {"date": datetime.date(2026, 8, 12), "scan_id": "scan-1", "metric": "Mitigated", "count": 1},
                {"date": datetime.date(2026, 8, 13), "scan_id": "scan-2", "metric": "High Risk", "count": 5},
                {"date": datetime.date(2026, 8, 13), "scan_id": "scan-2", "metric": "Mitigated", "count": 3},
            ],
        )
```

- [ ] **Step 2: Run the focused failing metrics test**

Run:

```bash
python -m unittest test_dashboard_metrics.DashboardMetricsTests.test_trend_frame_maps_active_high_and_cumulative_mitigated_counts
```

Expected: `FAIL` because `trend_frame()` still reads `high_risk_count` and subtracts `mitigated_count`.

- [ ] **Step 3: Implement direct trend mapping**

In `asm_dashboard/metrics.py`, replace these lines inside `trend_frame()`:

```python
        high_risk_count = int(row.get("high_risk_count") or 0)
        mitigated_count = int(row.get("mitigated_count") or 0)
```

with:

```python
        active_high_count = int(row.get("active_high_count") or 0)
        mitigated_count = int(row.get("mitigated_count") or 0)
```

Then replace the `High Risk` record count:

```python
                "count": max(0, high_risk_count - mitigated_count),
```

with:

```python
                "count": active_high_count,
```

- [ ] **Step 4: Run the focused metrics test**

Run:

```bash
python -m unittest test_dashboard_metrics.DashboardMetricsTests.test_trend_frame_maps_active_high_and_cumulative_mitigated_counts
```

Expected: `OK`.

- [ ] **Step 5: Commit the metrics mapping change**

Run:

```bash
git add asm_dashboard/metrics.py test_dashboard_metrics.py
git commit -m "fix: map exposure trend active high directly" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit succeeds. If unrelated untracked files exist, do not add them.

---

### Task 3: Regression Test Pass

**Files:**
- Test: `test_dashboard_db.py`
- Test: `test_dashboard_metrics.py`
- Test: `test_dashboard_app.py`

**Interfaces:**
- Consumes: implemented `fetch_trend_rows()` and `trend_frame()`.
- Produces: verified dashboard metric behavior without changing chart rendering.

- [ ] **Step 1: Run dashboard metric and DB tests together**

Run:

```bash
python -m unittest test_dashboard_db test_dashboard_metrics test_dashboard_app
```

Expected: `OK`.

- [ ] **Step 2: Inspect git status**

Run:

```bash
git --no-pager status --short
```

Expected: only pre-existing untracked data/plan files may remain. There should be no unstaged changes in `asm_dashboard/db.py`, `asm_dashboard/metrics.py`, `test_dashboard_db.py`, or `test_dashboard_metrics.py`.

- [ ] **Step 3: Stop on unexpected failures**

If Step 1 fails, do not guess. Inspect the failing assertion and the command output, then fix the exact implementation or test mismatch before rerunning Step 1. No commit is required when Step 1 and Step 2 are already clean.

Expected: final state has passing tests and no uncommitted tracked changes from this plan.
