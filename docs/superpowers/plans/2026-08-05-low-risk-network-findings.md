# Low Risk Network Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reclassify selected network/configuration findings from medium or unknown to low.

**Architecture:** Keep logic in `assess_attack_surface.py`. Update existing checker risk levels for HTTP 80 no-redirect and TLS certificate errors, then add a narrow HTTPS connection-reset branch before the generic checker error handler.

**Tech Stack:** Python 3 standard library, `urllib.error`, `unittest`.

## Global Constraints

- `http_without_https_redirect` risk level must be `low`.
- `https_tls_certificate_error` risk level must be `low`.
- Direct HTTPS connection reset should produce `check_id = "https_connection_reset"` and `risk_level = "low"`.
- Other checker exceptions remain generic `unknown` findings.
- No dependency changes.

---

### Task 1: Lower HTTP no-redirect and TLS certificate findings

**Files:**
- Modify: `test_assess_attack_surface.py`
- Modify: `assess_attack_surface.py`

**Interfaces:**
- Consumes: `HttpRedirectChecker.check(endpoint, context) -> list[dict[str, Any]]`
- Consumes: `HttpsContentChecker.check(endpoint, context) -> list[dict[str, Any]]`
- Produces: existing finding IDs with `risk_level = "low"`.

- [ ] **Step 1: Update tests to expect low**

In `test_assess_attack_surface.py`, change:

```python
self.assertEqual(findings[0]["risk_level"], "medium")
```

to:

```python
self.assertEqual(findings[0]["risk_level"], "low")
```

only in:

- `test_http_80_without_https_redirect_is_reduce_candidate`
- `test_https_content_checker_reports_tls_certificate_error`

- [ ] **Step 2: Run focused tests to verify they fail**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_without_https_redirect_is_reduce_candidate test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_reports_tls_certificate_error
```

Expected: FAIL because implementation still returns `medium`.

- [ ] **Step 3: Implement risk-level changes**

In `assess_attack_surface.py`:

- Change the `http_without_https_redirect` finding risk from `"medium"` to `"low"`.
- Change the `https_tls_certificate_error` finding risk from `"medium"` to `"low"`.

- [ ] **Step 4: Run focused tests to verify they pass**

Run the same focused tests. Expected: PASS.

---

### Task 2: Add low-risk HTTPS connection reset handling

**Files:**
- Modify: `test_assess_attack_surface.py`
- Modify: `assess_attack_surface.py`

**Interfaces:**
- Produces: `is_connection_reset_error(exc: BaseException) -> bool`
- Produces: direct HTTPS connection reset finding with `check_id = "https_connection_reset"` and `risk_level = "low"`.

- [ ] **Step 1: Write failing connection reset tests**

Add or update tests in `test_assess_attack_surface.py`:

```python
def test_https_content_checker_reports_connection_reset_as_low_risk(self):
    endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

    def fetcher(request, timeout, context=None):
        raise ConnectionResetError("Connection reset by peer")

    findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["check_id"], "https_connection_reset")
    self.assertEqual(findings[0]["risk_level"], "low")
    self.assertIn("Connection reset by peer", findings[0]["evidence"])

def test_https_content_checker_reports_urlerror_connection_reset_as_low_risk(self):
    endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

    def fetcher(request, timeout, context=None):
        raise asm.urllib.error.URLError(ConnectionResetError("Connection reset by peer"))

    findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["check_id"], "https_connection_reset")
    self.assertEqual(findings[0]["risk_level"], "low")
```

- [ ] **Step 2: Run focused tests to verify they fail**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_reports_connection_reset_as_low_risk test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_reports_urlerror_connection_reset_as_low_risk
```

Expected: FAIL because connection reset is not handled by `HttpsContentChecker` yet.

- [ ] **Step 3: Implement helper and checker branch**

In `assess_attack_surface.py`, add:

```python
def is_connection_reset_error(exc: BaseException) -> bool:
    if isinstance(exc, ConnectionResetError):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ConnectionResetError):
        return True
    return "connection reset by peer" in str(exc).lower()
```

Update `HttpsContentChecker.check()` to catch `(urllib.error.URLError, ConnectionResetError)` and return:

```python
finding(
    endpoint,
    "https_connection_reset",
    "low",
    f"HTTPS endpoint reset the connection: {redirect_fetch_error_reason(exc)}",
    "Retest later or confirm whether the service intentionally resets unauthenticated root-path requests.",
    details={"error": redirect_fetch_error_reason(exc)},
)
```

only when `is_connection_reset_error(exc)` is true. Preserve TLS certificate handling.

- [ ] **Step 4: Run focused tests to verify they pass**

Run the same focused tests. Expected: PASS.

---

### Task 3: Documentation and full verification

**Files:**
- Modify: `README.md`
- Test: `test_assess_attack_surface.py`
- Test: `test_wiz_auth_poc.py`

**Interfaces:**
- Produces: risk-level documentation that matches code behavior.

- [ ] **Step 1: Update README risk descriptions**

Adjust the `low` bullet to include certificate validation failures, HTTP 80 no-redirect, and connection reset. Keep `medium` for review-required cases.

- [ ] **Step 2: Run full tests**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py test_wiz_auth_poc.py
```

Expected: all tests pass.

- [ ] **Step 3: Commit implementation**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py README.md docs/superpowers/plans/2026-08-05-low-risk-network-findings.md
git commit -m "feat: lower selected network findings" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```
