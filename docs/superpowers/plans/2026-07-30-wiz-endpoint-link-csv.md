# Wiz Endpoint Link CSV Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a clickable Wiz application endpoint link to every final CSV row.

**Architecture:** Keep the existing finding JSONL shape unchanged and enrich only CSV serialization. Add one focused URL builder in `assess_attack_surface.py`, then have `csv_row_for_finding()` populate a new `Wiz链接` column from each finding's `endpoint_id`.

**Tech Stack:** Python 3 standard library, `csv`, `unittest`.

## Global Constraints

- The Wiz console URL format is `https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%27{endpoint_id}*2cENDPOINT%29%29`.
- Add a new CSV column named `Wiz链接`.
- If `endpoint_id` is present, `Wiz链接` contains the Wiz console URL for that endpoint.
- If `endpoint_id` is missing or empty, `Wiz链接` is empty.
- Existing CSV columns and meanings stay unchanged.
- JSONL output keeps its existing fields; no new JSON-only behavior is required.

---

## File Structure

- Modify `assess_attack_surface.py`
  - Add `WIZ_ENDPOINT_URL_PREFIX` and `WIZ_ENDPOINT_URL_SUFFIX` constants near `CSV_FIELDNAMES`.
  - Add `wiz_endpoint_url(endpoint_id: Any) -> str`.
  - Add `Wiz链接` to `CSV_FIELDNAMES`.
  - Add `Wiz链接` to `csv_row_for_finding()`.
- Modify `test_assess_attack_surface.py`
  - Update the existing CSV row test to include `endpoint_id` and expected `Wiz链接`.
  - Add a missing-id CSV row assertion.
  - Update `test_main_fetches_latest_wiz_endpoints_by_default()` to assert the generated CSV includes `Wiz链接`.

---

### Task 1: CSV Wiz Endpoint Link

**Files:**
- Modify: `assess_attack_surface.py:558-604`
- Modify: `test_assess_attack_surface.py:760-820`
- Modify: `test_assess_attack_surface.py:960-1005`

**Interfaces:**
- Consumes: `finding_item["endpoint_id"]` already produced by `finding(endpoint, ...)`.
- Produces:
  - `WIZ_ENDPOINT_URL_PREFIX: str`
  - `WIZ_ENDPOINT_URL_SUFFIX: str`
  - `wiz_endpoint_url(endpoint_id: Any) -> str`
  - CSV rows with a `Wiz链接` column.

- [ ] **Step 1: Write failing test for CSV link when endpoint_id exists**

In `test_assess_attack_surface.py`, update the first finding in `test_write_findings_csv_outputs_requested_columns_with_llm_summary()` to include:

```python
                "endpoint_id": "2e7dca40-b6e1-5e11-aa7e-3303642a6ef0",
```

Then update the expected first row to include:

```python
                "Wiz链接": "https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%272e7dca40-b6e1-5e11-aa7e-3303642a6ef0*2cENDPOINT%29%29",
```

The full expected row should be:

```python
            {
                "endpoint_name": "https://app.example.com:443",
                "Wiz链接": "https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%272e7dca40-b6e1-5e11-aa7e-3303642a6ef0*2cENDPOINT%29%29",
                "端口号": "443",
                "cloudPlatform": "AWS",
                "http状态码": "200",
                "http response": "<input name='token' value='secret-token'>",
                "LLM意见": "LLM found a sensitive token in the login HTML. Protect the token.",
                "risk_level": "medium",
            }
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_write_findings_csv_outputs_requested_columns_with_llm_summary
```

Expected: FAIL because the `Wiz链接` column is missing.

- [ ] **Step 3: Implement CSV link column**

In `assess_attack_surface.py`, replace `CSV_FIELDNAMES` with:

```python
WIZ_ENDPOINT_URL_PREFIX = "https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%27"
WIZ_ENDPOINT_URL_SUFFIX = "*2cENDPOINT%29%29"
CSV_FIELDNAMES = [
    "endpoint_name",
    "Wiz链接",
    "端口号",
    "cloudPlatform",
    "http状态码",
    "http response",
    "LLM意见",
    "risk_level",
]
```

Add this helper above `csv_row_for_finding()`:

```python
def wiz_endpoint_url(endpoint_id: Any) -> str:
    endpoint_id_text = str(endpoint_id or "").strip()
    if not endpoint_id_text:
        return ""
    return f"{WIZ_ENDPOINT_URL_PREFIX}{endpoint_id_text}{WIZ_ENDPOINT_URL_SUFFIX}"
```

Update the dict returned by `csv_row_for_finding()` to include `Wiz链接` immediately after `endpoint_name`:

```python
        "Wiz链接": wiz_endpoint_url(finding_item.get("endpoint_id")),
```

- [ ] **Step 4: Run CSV link test to verify it passes**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_write_findings_csv_outputs_requested_columns_with_llm_summary
```

Expected: OK.

- [ ] **Step 5: Add missing endpoint_id assertion**

In the same test, after the existing `rows[1]` assertions, add:

```python
        self.assertEqual(rows[1]["Wiz链接"], "")
```

- [ ] **Step 6: Add main-flow CSV assertion**

In `test_main_fetches_latest_wiz_endpoints_by_default()`, after reading `json_rows`, also read `csv_rows`:

```python
            with open(csv_path, encoding="utf-8", newline="") as csv_file:
                csv_rows = list(csv.DictReader(csv_file))
```

Then add this assertion after `self.assertEqual(json_rows[0]["endpoint_name"], "https://wiz.example.com:443")`:

```python
        self.assertEqual(
            csv_rows[0]["Wiz链接"],
            "https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%27endpoint-1*2cENDPOINT%29%29",
        )
```

- [ ] **Step 7: Run focused tests**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_write_findings_csv_outputs_requested_columns_with_llm_summary \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_main_fetches_latest_wiz_endpoints_by_default
```

Expected: OK.

- [ ] **Step 8: Run full test suite**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py
```

Expected: OK.

- [ ] **Step 9: Commit**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py docs/superpowers/plans/2026-07-30-wiz-endpoint-link-csv.md
git commit -m "feat: add Wiz endpoint links to CSV output" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit succeeds.
