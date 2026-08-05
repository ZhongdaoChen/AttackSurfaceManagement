# High Exposure Wiz Filter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fetch only Wiz application endpoints whose `exposureLevel` is `HIGH`.

**Architecture:** Keep pagination and GraphQL query text unchanged. Change only the `filterBy` variables sent by `iter_application_endpoints()` and update tests/docs to match.

**Tech Stack:** Python 3 standard library, Wiz GraphQL API, `unittest`.

## Global Constraints

- Default Wiz fetching filters by project and `exposureLevel=HIGH`.
- Input JSONL mode remains unchanged.
- No dependency changes.
- Existing pagination behavior remains unchanged.

---

### Task 1: Add HIGH exposure filter to Wiz GraphQL variables

**Files:**
- Modify: `test_wiz_auth_poc.py`
- Modify: `wiz_auth_poc.py`

**Interfaces:**
- Consumes: `iter_application_endpoints(config: WizConfig, access_token: str, page_size: int = DEFAULT_PAGE_SIZE) -> Iterator[dict[str, Any]]`
- Produces: each `execute_graphql()` call receives `variables["filterBy"] == {"project": [config.project_id], "exposureLevel": ["HIGH"]}`.

- [ ] **Step 1: Update tests to expect exposureLevel HIGH**

In `test_wiz_auth_poc.py`, update the expected `filterBy` dictionaries in:

- `test_list_application_endpoints_paginates_until_done`
- `test_list_application_endpoints_filters_by_configured_project`

Expected filter:

```python
{"project": ["project-id"], "exposureLevel": ["HIGH"]}
```

- [ ] **Step 2: Run focused tests to verify they fail**

Run:

```bash
python3 -m unittest test_wiz_auth_poc.WizAuthPoCTests.test_list_application_endpoints_paginates_until_done test_wiz_auth_poc.WizAuthPoCTests.test_list_application_endpoints_filters_by_configured_project
```

Expected: FAIL because implementation still sends only `project`.

- [ ] **Step 3: Implement the variable change**

In `wiz_auth_poc.py`, change:

```python
{"first": page_size, "after": after, "filterBy": {"project": [config.project_id]}}
```

to:

```python
{"first": page_size, "after": after, "filterBy": {"project": [config.project_id], "exposureLevel": ["HIGH"]}}
```

- [ ] **Step 4: Run focused tests to verify they pass**

Run the same focused tests. Expected: PASS.

---

### Task 2: Documentation and full verification

**Files:**
- Modify: `README.md`
- Test: `test_assess_attack_surface.py`
- Test: `test_wiz_auth_poc.py`

**Interfaces:**
- Produces: README scope note matching HIGH exposure filter behavior.

- [ ] **Step 1: Update README scope note**

Replace the old scope statement with:

```markdown
脚本默认从 Wiz 拉取指定 project 下 `exposureLevel=HIGH` 的 `applicationEndpoints`：

```python
filterBy: {"project": [WIZ_PROJECT_ID], "exposureLevel": ["HIGH"]}
```

如果使用 `--input` 扫描已导出的 JSONL，则会扫描输入文件中的所有 endpoint，不再额外按 `exposureLevel` 过滤。
```

- [ ] **Step 2: Run full tests**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py test_wiz_auth_poc.py
```

Expected: all tests pass.

- [ ] **Step 3: Commit implementation**

Run:

```bash
git add wiz_auth_poc.py test_wiz_auth_poc.py README.md docs/superpowers/plans/2026-08-05-high-exposure-wiz-filter.md
git commit -m "feat: filter Wiz endpoints to high exposure" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```
