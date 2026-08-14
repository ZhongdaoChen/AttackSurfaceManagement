# ASM Dashboard Table Refinement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refine the dashboard trend chart and finding list so rows expand inline, links render cleanly, and pagination lives below the list.

**Architecture:** Keep the existing Streamlit app and add small pure formatting helpers in `asm_dashboard.metrics`. Replace dataframe row selection with Streamlit expanders that render each page fully and expose row-level whitelist forms for Current Status only.

**Tech Stack:** Python 3, Streamlit, pandas, Plotly, unittest.

## Global Constraints

- Exposure trend x-axis must render at day granularity.
- Page selector must be displayed below the list.
- Do not use an internal vertical scroll container for the 200 rows on a page.
- Endpoint Name visible text must be the raw URL/string, not markdown syntax.
- Wiz Link visible text must be `Wiz Link`, linked to the database `wiz_link` value.
- Expanded current rows must include whitelist action; expanded historical rows must not.

---

### Task 1: Link formatting helpers

**Files:**
- Modify: `asm_dashboard/metrics.py`
- Modify: `test_dashboard_metrics.py`

**Interfaces:**
- Produces: `metrics.markdown_link(label: Any, url: Any) -> str`
- Produces: `metrics.endpoint_link(endpoint_name: Any) -> str`
- Produces: `metrics.wiz_link(wiz_url: Any) -> str`

- [ ] **Step 1: Write failing tests for clean endpoint and Wiz links**

Add tests that assert endpoint URL visible text is plain and Wiz visible text is `Wiz Link`.

- [ ] **Step 2: Run tests and confirm failure**

Run `python3 -m unittest test_dashboard_metrics`.

- [ ] **Step 3: Implement helpers**

Implement `markdown_link`, update `endpoint_link`, and add `wiz_link`.

- [ ] **Step 4: Run tests**

Run `python3 -m unittest test_dashboard_metrics`.

### Task 2: Expander list UI and daily trend axis

**Files:**
- Modify: `asm_dashboard/app.py`
- Modify: `test_dashboard_app.py`

**Interfaces:**
- Produces: `app.row_summary_markdown(row: dict[str, Any]) -> str`
- Produces: `app.render_finding_list(connection, result, page_key: str, allow_whitelist: bool) -> None`

- [ ] **Step 1: Write failing tests for row summary links**

Add tests for `row_summary_markdown()` including Endpoint Name and Wiz Link markdown.

- [ ] **Step 2: Run tests and confirm failure**

Run `python3 -m unittest test_dashboard_app`.

- [ ] **Step 3: Implement expander list**

Replace dataframe table rendering with expander rows. Move page selector below the rendered list. Use `expanded=False` by default. In Current Status, render whitelist form inside each expanded row. In Historical Results, render details only.

- [ ] **Step 4: Force daily x-axis**

After creating the Plotly line figure, call `figure.update_xaxes(dtick="D1", tickformat="%Y-%m-%d")`.

- [ ] **Step 5: Run dashboard tests**

Run `python3 -m unittest test_dashboard_app test_dashboard_metrics`.

### Task 3: Verify and commit

**Files:**
- Modify: `asm_dashboard/app.py`
- Modify: `asm_dashboard/metrics.py`
- Modify: `test_dashboard_app.py`
- Modify: `test_dashboard_metrics.py`
- Create: `docs/superpowers/specs/2026-08-14-asm-dashboard-table-refinement-design.md`
- Create: `docs/superpowers/plans/2026-08-14-asm-dashboard-table-refinement.md`

- [ ] **Step 1: Run full tests**

Run `python3 -m unittest`.

- [ ] **Step 2: Commit**

Commit the refinement implementation and docs.

## Self-review notes

Spec coverage is complete: daily trend axis, bottom pagination, full-page row rendering, expander details, endpoint/Wiz links, and row-level whitelist actions are covered by Tasks 1-2.
