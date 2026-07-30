# Timeout and Connection Reset Handling Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Classify connection resets as low risk and retry timeout failures once with double the configured timeout.

**Architecture:** Add small network-error helpers in `assess_attack_surface.py` instead of broad catch-all behavior. Route all endpoint HTTP fetches through a timeout-retry wrapper, then use explicit finding builders so direct checker failures and redirect target failures preserve useful risk levels and evidence.

**Tech Stack:** Python 3 standard library, `urllib`, `socket`, `http.client`, `unittest`.

## Global Constraints

- Connection reset failures become low-risk findings.
- Timeout failures are retried once with `timeout_seconds * 2`.
- If the retry succeeds, normal response analysis continues.
- If the retry also times out, the scanner emits an explicit timeout failure finding.
- TLS certificate validation failures keep the existing medium-risk behavior.
- The first request uses the configured timeout from `--timeout`.
- Only timeout failures get the double-time retry.
- Other network errors are not retried.
- Treat `ConnectionResetError` or a network failure whose reason text contains `connection reset` as low risk.
- This behavior applies to direct HTTPS content checks, HTTP/HTTPS redirect target fetches, and generic checker network failures surfaced through `assess_endpoint()`.
- Do not add a broad catch-all that hides programming errors.
- Only classify explicit network failures: `urllib.error.URLError`, `TimeoutError`, `socket.timeout`, `http.client.HTTPException`, `OSError`, and their reason values.
- Redirect failures must keep partial `redirect_chain` evidence when a target fetch fails.

---

## File Structure

- Modify `assess_attack_surface.py`
  - Add `import socket`.
  - Add `NetworkFailure` dataclass.
  - Add helpers:
    - `network_error_reason(exc: BaseException) -> str`
    - `is_timeout_error(exc: BaseException) -> bool`
    - `is_connection_reset_error(exc: BaseException) -> bool`
    - `fetch_url_with_timeout_retry(request: urllib.request.Request, context: CheckContext, ssl_context: ssl.SSLContext | None) -> HttpResponse`
    - `network_failure_finding(endpoint: dict[str, Any], check_id: str, exc: BaseException, details: dict[str, Any] | None = None) -> dict[str, Any]`
  - Update `fetch_url_for_absolute_url()` to use the timeout retry wrapper.
  - Update redirect target failure handling to classify connection reset as low risk and timeout retry failures as explicit timeout findings with redirect chain.
  - Update `assess_endpoint()` to classify explicit network failures before falling back to the existing unknown checker error.
- Modify `test_assess_attack_surface.py`
  - Update existing connection-reset redirect tests from medium to low.
  - Add direct HTTPS connection-reset test.
  - Add timeout retry success test.
  - Add timeout retry failure test.

---

### Task 1: Timeout Retry Fetch Wrapper

**Files:**
- Modify: `assess_attack_surface.py:1-145`
- Test: `test_assess_attack_surface.py:1030-1070`

**Interfaces:**
- Consumes: existing `HttpFetcher`, `CheckContext`, `ssl_context_for_scheme()`.
- Produces:
  - `network_error_reason(exc: BaseException) -> str`
  - `is_timeout_error(exc: BaseException) -> bool`
  - `fetch_url_with_timeout_retry(request: urllib.request.Request, context: CheckContext, ssl_context: ssl.SSLContext | None) -> HttpResponse`
  - `fetch_url_for_absolute_url()` uses the retry wrapper.

- [ ] **Step 1: Write timeout retry success test**

Add this test near the existing fetch-related tests in `test_assess_attack_surface.py`:

```python
    def test_fetch_url_for_absolute_url_retries_timeout_with_double_timeout(self):
        calls = []

        def fetcher(request, timeout, context=None):
            calls.append(timeout)
            if len(calls) == 1:
                raise TimeoutError("timed out")
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Recovered</title></html>",
            )

        response = asm.fetch_url_for_absolute_url(
            "https://app.example.com/",
            asm.CheckContext(fetcher=fetcher, timeout_seconds=30),
        )

        self.assertEqual(response.status, 200)
        self.assertEqual(calls, [30, 60])
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_fetch_url_for_absolute_url_retries_timeout_with_double_timeout
```

Expected: ERROR with `TimeoutError: timed out`.

- [ ] **Step 3: Implement timeout retry wrapper**

In `assess_attack_surface.py`, add `import socket` near the other standard imports:

```python
import socket
```

Replace `redirect_fetch_error_reason()` with:

```python
def network_error_reason(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    if reason is not None:
        return str(reason)
    return str(exc)


def is_timeout_error(exc: BaseException) -> bool:
    reason = getattr(exc, "reason", None)
    return (
        isinstance(exc, (TimeoutError, socket.timeout))
        or isinstance(reason, (TimeoutError, socket.timeout))
        or "timed out" in network_error_reason(exc).lower()
        or "timeout" in network_error_reason(exc).lower()
    )
```

Add this helper below `fetch_url_for_absolute_url()` or directly above it:

```python
def fetch_url_with_timeout_retry(
    request: urllib.request.Request,
    context: CheckContext,
    ssl_context: ssl.SSLContext | None,
) -> HttpResponse:
    fetcher = context.fetcher or fetch_url
    try:
        return fetcher(request, context.timeout_seconds, ssl_context)
    except (urllib.error.URLError, TimeoutError, socket.timeout) as exc:
        if not is_timeout_error(exc):
            raise
        return fetcher(request, context.timeout_seconds * 2, ssl_context)
```

Update `fetch_url_for_absolute_url()` to use it:

```python
    return fetch_url_with_timeout_retry(request, context, ssl_context_for_scheme(scheme, context))
```

- [ ] **Step 4: Run timeout retry success test**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_fetch_url_for_absolute_url_retries_timeout_with_double_timeout
```

Expected: OK.

- [ ] **Step 5: Commit task 1**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py docs/superpowers/plans/2026-07-30-timeout-reset-handling.md
git commit -m "feat: retry endpoint fetches with doubled timeout" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit succeeds.

---

### Task 2: Network Failure Finding Classification

**Files:**
- Modify: `assess_attack_surface.py:180-230`
- Modify: `assess_attack_surface.py:270-295`
- Modify: `assess_attack_surface.py:510-530`
- Test: `test_assess_attack_surface.py:220-270`
- Test: `test_assess_attack_surface.py:430-455`

**Interfaces:**
- Consumes: `network_error_reason(exc)`, `is_timeout_error(exc)`, `fetch_url_with_timeout_retry()`.
- Produces:
  - `is_connection_reset_error(exc: BaseException) -> bool`
  - `network_failure_finding(endpoint: dict[str, Any], check_id: str, exc: BaseException, details: dict[str, Any] | None = None) -> dict[str, Any]`
  - Redirect follow failures use low risk for connection reset and explicit timeout evidence for timeout failures.
  - `assess_endpoint()` uses `network_failure_finding()` for explicit network failures.

- [ ] **Step 1: Update redirect connection-reset tests to expect low risk**

In `test_http_80_redirect_target_remote_disconnect_reports_follow_error_with_chain()` and `test_http_80_redirect_target_connection_reset_reports_follow_error_with_chain()`, change:

```python
        self.assertEqual(findings[0]["risk_level"], "medium")
```

to:

```python
        self.assertEqual(findings[0]["risk_level"], "low")
```

- [ ] **Step 2: Add direct HTTPS connection-reset test**

Add this test near `test_https_content_checker_reports_tls_certificate_error`:

```python
    def test_https_content_checker_connection_reset_is_low_risk(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            raise ConnectionResetError("connection reset by peer")

        findings = asm.assess_endpoint(
            endpoint,
            [asm.HttpsContentChecker()],
            asm.CheckContext(fetcher=fetcher),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_content_network_error")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertIn("connection reset", findings[0]["evidence"].lower())
```

- [ ] **Step 3: Add timeout retry failure test**

Add this test near the timeout retry success test from Task 1:

```python
    def test_fetch_url_for_absolute_url_timeout_retry_failure_surfaces_timeout(self):
        calls = []

        def fetcher(request, timeout, context=None):
            calls.append(timeout)
            raise TimeoutError("timed out")

        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}
        findings = asm.assess_endpoint(
            endpoint,
            [asm.HttpsContentChecker()],
            asm.CheckContext(fetcher=fetcher, timeout_seconds=30),
        )

        self.assertEqual(calls, [30, 60])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_content_timeout")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("timed out", findings[0]["evidence"].lower())
```

- [ ] **Step 4: Run tests to verify they fail**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_target_remote_disconnect_reports_follow_error_with_chain \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_target_connection_reset_reports_follow_error_with_chain \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_connection_reset_is_low_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_fetch_url_for_absolute_url_timeout_retry_failure_surfaces_timeout
```

Expected: FAIL because connection reset is still medium/unknown and timeout failure is not classified as `https_content_timeout`.

- [ ] **Step 5: Implement network failure classification**

Add below `is_timeout_error()`:

```python
def is_connection_reset_error(exc: BaseException) -> bool:
    reason = getattr(exc, "reason", None)
    return (
        isinstance(exc, ConnectionResetError)
        or isinstance(reason, ConnectionResetError)
        or "connection reset" in network_error_reason(exc).lower()
    )


def network_failure_finding(
    endpoint: dict[str, Any],
    check_id: str,
    exc: BaseException,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    reason = network_error_reason(exc)
    if is_connection_reset_error(exc):
        return finding(
            endpoint,
            f"{check_id}_network_error",
            "low",
            f"Network request failed because the remote peer reset the connection: {reason}. No content exposure was observed.",
            "Retest later if the endpoint remains in scope; no immediate content exposure was observed from this response.",
            details={**(details or {}), "error_type": type(exc).__name__, "error_reason": reason},
        )
    if is_timeout_error(exc):
        return finding(
            endpoint,
            f"{check_id}_timeout",
            "medium",
            f"Network request timed out after retrying once with double timeout: {reason}.",
            "Retest the endpoint or increase --timeout if the service is expected to respond slowly.",
            details={**(details or {}), "error_type": type(exc).__name__, "error_reason": reason},
        )
    return finding(
        endpoint,
        f"{check_id}_network_error",
        "unknown",
        f"Network request failed: {reason}",
        "Investigate checker/network failure before deciding endpoint risk.",
        details={**(details or {}), "error_type": type(exc).__name__, "error_reason": reason},
    )
```

Update `follow_redirects()` fetch failure block to keep partial chain and carry the exception:

```python
        except (urllib.error.URLError, ValueError, http.client.HTTPException, OSError, TimeoutError, socket.timeout) as exc:
            return RedirectResolution(
                final_response=None,
                redirect_chain=redirect_chain,
                error=f"Redirect target fetch failed for {next_url}: {network_error_reason(exc)}",
                error_exception=exc,
            )
```

To support that, update `RedirectResolution` dataclass:

```python
class RedirectResolution:
    final_response: HttpResponse | None
    redirect_chain: list[dict[str, Any]]
    error: str | None = None
    error_exception: BaseException | None = None
```

Update `redirected_response_findings()` failure block:

```python
    if resolution.error or resolution.final_response is None:
        exc = resolution.error_exception
        if exc is not None:
            return [
                network_failure_finding(
                    endpoint,
                    "http_redirect_follow",
                    exc,
                    details=detail_overrides,
                )
            ]
        return [
            finding(
                endpoint,
                "http_redirect_follow_error",
                "medium",
                f"{label} could not be fully analyzed: {resolution.error}",
                "Investigate the redirect chain and verify the final target does not expose sensitive data.",
                details=detail_overrides,
            )
        ]
```

Finally, update `assess_endpoint()` before the generic `Exception` branch output:

```python
        except (urllib.error.URLError, ValueError, http.client.HTTPException, OSError, TimeoutError, socket.timeout) as exc:
            results.append(network_failure_finding(endpoint, checker.check_id, exc))
        except Exception as exc:
```

- [ ] **Step 6: Run focused classification tests**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_target_remote_disconnect_reports_follow_error_with_chain \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_target_connection_reset_reports_follow_error_with_chain \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_connection_reset_is_low_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_fetch_url_for_absolute_url_timeout_retry_failure_surfaces_timeout
```

Expected: OK.

- [ ] **Step 7: Run full test suite**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py
```

Expected: OK.

- [ ] **Step 8: Commit task 2**

Run:

```bash
git add assess_attack_surface.py test_assess_attack_surface.py docs/superpowers/plans/2026-07-30-timeout-reset-handling.md
git commit -m "feat: classify reset and timeout network failures" -m "Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
```

Expected: commit succeeds.
