# Non-Standard Port Content Probe Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Probe HTTPS and HTTP content on non-standard open ports before assigning fallback non-standard-port risk.

**Architecture:** Keep `NonStandardPortChecker` as the entry point for non-80/443 ports. Add helper logic that tries `https://host:port/` then `http://host:port/`, reuses existing `content_findings_for_response()` for content classification, and falls back to the existing non-standard-port finding when both probes fail.

**Tech Stack:** Python 3 standard library, existing scanner HTTP fetch helpers, existing LLM handoff via `response_summaries`, `unittest`.

## Global Constraints

- Non-standard open ports should try HTTPS and HTTP content probes.
- If a probe returns an HTTP response, classify response content before fallback.
- If LLM is enabled and response status is 200, let `LlmSensitiveContentChecker` produce the final LLM finding.
- If both probes fail, preserve existing fallback behavior including FDP/`197575089658` low-risk subscription exception.
- Do not shell out to `curl`.
- No dependency changes.

---

### Task 1: Add content probe tests

**Files:**
- Modify: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes: `assess_endpoint(endpoint, checkers, context)`
- Produces: tests proving non-standard ports classify reachable HTTPS/HTTP content.

- [ ] **Step 1: Add sensitive HTTPS probe test**

Add a test where endpoint `71.131.246.78:9200` returns HTTPS 200 with `Index of /` and `backup.zip`, then assert `https_sensitive_content_heuristic` and `high`.

- [ ] **Step 2: Add HTTPS fail then HTTP success test**

Add a test where HTTPS raises `URLError`, HTTP returns a login page, then assert `https_login_page` and `low`, and verify both URLs were attempted in order.

- [ ] **Step 3: Add LLM low handoff test**

Add a test where non-standard HTTPS returns HTTP 200 ordinary content with LLM enabled, then assert `assess_endpoint()` returns one `llm_sensitive_content` finding with `low`.

- [ ] **Step 4: Run focused tests for RED**

Run the three new tests. Expected: FAIL because current checker returns fallback `non_standard_open_port`.

---

### Task 2: Implement probes and fallback

**Files:**
- Modify: `assess_attack_surface.py`

**Interfaces:**
- Produces: `non_standard_port_content_findings(endpoint, context) -> list[dict[str, Any]] | None`
- Produces: `fallback_non_standard_port_finding(endpoint, port) -> dict[str, Any]`

- [ ] **Step 1: Extract existing fallback finding**

Move the current `NonStandardPortChecker` finding construction into a helper that preserves subscription exception behavior.

- [ ] **Step 2: Add HTTPS/HTTP probe helper**

Try `fetch_endpoint(endpoint, "https", context)` and `fetch_endpoint(endpoint, "http", context)` in order. On first response, call `content_findings_for_response()` with detail overrides containing `non_standard_port`, `probe_scheme`, and fallback probe errors collected so far.

- [ ] **Step 3: Wire helper into `NonStandardPortChecker.check()`**

If probe helper returns findings:

- Return those findings.
- If it returns `[]` because LLM is enabled and status 200, return `[]` so `LlmSensitiveContentChecker` handles it.
- If both schemes fail, return fallback non-standard-port finding.

- [ ] **Step 4: Run focused tests for GREEN**

Run the three focused tests. Expected: PASS.

---

### Task 3: Full validation and commit

**Files:**
- Modify: `README.md`
- Test: `test_assess_attack_surface.py`
- Test: `test_wiz_auth_poc.py`

**Interfaces:**
- Documentation describes that non-standard ports are content-probed before fallback risk.

- [ ] **Step 1: Update README risk text**

Mention that non-standard ports are probed over HTTPS/HTTP and content-sensitive results can override fallback port risk.

- [ ] **Step 2: Run full tests**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py test_wiz_auth_poc.py
```

Expected: all tests pass.

- [ ] **Step 3: Commit implementation**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py README.md docs/superpowers/plans/2026-08-06-nonstandard-port-content-probe.md
git commit -m "feat: probe nonstandard port content" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```
