# ASM Dashboard Table Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Restore the dashboard finding list to a table while keeping row detail expansion, clean URL links, Wiz Link column, and dialog-based whitelist workflow.

**Architecture:** Use `st.dataframe` with single-row selection for the table and render selected-row details below it. Keep link formatting in pure helpers and use Streamlit `LinkColumn` for clickable endpoint and Wiz links without markdown syntax.

**Tech Stack:** Python 3, Streamlit, pandas, unittest.

## Global Constraints

- List must look like the previous table format.
- Add an expand affordance column, but expansion is implemented as row selection plus a details panel because Streamlit native dataframe cannot embed per-row buttons.
- Endpoint Name must display raw URL/string text without `[]` markdown syntax and be clickable.
- Wiz Link column must display `Wiz Link` and link to the row `wiz_link`.
- Whitelist must be a button in the selected-row details panel.
- Whitelist button opens a Streamlit dialog requiring Reason and Operator Name.
- Page selector remains below the table.

---

### Task 1: Table view-model tests and helpers

**Files:**
- Modify: `asm_dashboard/app.py`
- Modify: `test_dashboard_app.py`

**Interfaces:**
- Produces: `app.table_records(rows: list[dict[str, Any]]) -> list[dict[str, Any]]`

- [ ] **Step 1: Write failing tests**

Add tests proving table records include `Expand`, raw `Endpoint Name`, `Endpoint URL`, fixed `Wiz Link`, and `Wiz URL`.

- [ ] **Step 2: Run failing test**

Run `python3 -m unittest test_dashboard_app`.

- [ ] **Step 3: Implement helper**

Add `table_records()` and update `table_frame()` to use it.

- [ ] **Step 4: Run tests**

Run `python3 -m unittest test_dashboard_app`.

### Task 2: Restore dataframe table and dialog whitelist

**Files:**
- Modify: `asm_dashboard/app.py`

**Interfaces:**
- Produces: `app.open_whitelist_dialog(connection, row: dict[str, Any], dialog_key: str) -> None`
- Produces: `app.render_finding_table(connection, result: db.PageResult, page_key: str, allow_whitelist: bool) -> None`

- [ ] **Step 1: Replace expander list with dataframe**

Use `st.dataframe(..., selection_mode="single-row", on_select="rerun", column_config={...})`.

- [ ] **Step 2: Configure link columns**

Set `Endpoint Name` as a `LinkColumn` using `Endpoint URL`. Set `Wiz Link` as a `LinkColumn` using `Wiz URL`.

- [ ] **Step 3: Render selected details**

When a row is selected, render full `st.json(row)` below the table.

- [ ] **Step 4: Add Whitelist button and dialog**

When `allow_whitelist` is true, show `Whitelist` button in the details panel. Clicking opens `st.dialog` with Reason and Operator Name form and calls `db.create_whitelist_rule()`.

- [ ] **Step 5: Keep bottom pagination**

Render `render_page_controls()` after the table/details panel.

### Task 3: Verify and ship

**Files:**
- Modify: `asm_dashboard/app.py`
- Modify: `test_dashboard_app.py`
- Create: `docs/superpowers/plans/2026-08-14-asm-dashboard-table-selection.md`

- [ ] **Step 1: Run focused tests**

Run `python3 -m unittest test_dashboard_app test_dashboard_metrics`.

- [ ] **Step 2: Run full tests**

Run `python3 -m unittest`.

- [ ] **Step 3: Commit and push**

Commit changes and push `main`.

## Self-review notes

This plan covers table restoration, expand affordance, clean endpoint display, Wiz Link column, dialog whitelist workflow, and bottom pagination.
