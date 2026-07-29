# Redirect Follow Sensitive Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the attack surface scanner follow HTTP redirects and analyze the final target response for sensitive data exposure.

**Architecture:** Keep `fetch_url` non-following so redirect hops remain visible as evidence. Add explicit redirect-follow helpers in `assess_attack_surface.py`, then teach `HttpRedirectChecker` to analyze the final response with the same content-summary, heuristic, and LLM handoff behavior used by direct HTTPS checks.

**Tech Stack:** Python 3, standard library `urllib.request`, `urllib.parse`, `ssl`, `unittest`.

## Global Constraints

- Preserve `fetch_url` behavior: it must continue using `NoRedirectHandler` and must not automatically follow redirects.
- Redirect statuses are 301, 302, 303, 307, and 308.
- Follow same-host and cross-host redirects, HTTPS and HTTP targets, and multi-hop redirect chains.
- Resolve relative `Location` values with `urllib.parse.urljoin`.
- Stop after 5 redirects.
- Follow only `http` and `https` URLs.
- Do not silently ignore missing `Location`, unsupported URL schemes, redirect-limit failures, or fetch failures; emit a finding with the partial chain.
- Respect existing TLS behavior: validate by default and honor `--insecure-tls`.
- Store final redirected response summaries in `context.response_summaries` under the endpoint id so `LlmSensitiveContentChecker` can reuse them.
- Current working directory is not a git repository. Commit steps are included for execution in a git checkout; skip commit commands when `git status` reports `fatal: not a git repository`.

---

## File Structure

- Modify `assess_attack_surface.py`
  - Import `urllib.parse`.
  - Add `MAX_REDIRECTS = 5`.
  - Add `RedirectResolution` dataclass to carry the final response, redirect chain, and optional error.
  - Add helper functions:
    - `fetch_url_for_absolute_url(url: str, context: CheckContext) -> HttpResponse`
    - `ssl_context_for_scheme(scheme: str, context: CheckContext) -> ssl.SSLContext | None`
    - `header_value(headers: dict[str, str], name: str) -> str`
    - `follow_redirects(start_response: HttpResponse, context: CheckContext, max_redirects: int = MAX_REDIRECTS) -> RedirectResolution`
    - `content_findings_for_response(endpoint: dict[str, Any], response: HttpResponse, context: CheckContext, detail_overrides: dict[str, Any] | None = None) -> list[dict[str, Any]]`
  - Refactor `HttpsContentChecker.check()` to call `content_findings_for_response`.
  - Update `HttpRedirectChecker.check()` to follow all redirects and analyze the final response.
- Modify `test_assess_attack_surface.py`
  - Add focused tests for redirect following, chain evidence, relative locations, max-hop failure, missing location failure, and LLM handoff.
- Existing docs/spec file remains unchanged:
  - `docs/superpowers/specs/2026-07-29-redirect-follow-design.md`

---

### Task 1: Redirect Helper Primitives

**Files:**
- Modify: `assess_attack_surface.py:1-104`
- Test: `test_assess_attack_surface.py:1-80`

**Interfaces:**
- Consumes: existing `HttpResponse`, `CheckContext`, `fetch_url`, and `REDIRECT_STATUSES`.
- Produces:
  - `MAX_REDIRECTS: int`
  - `RedirectResolution(final_response: HttpResponse | None, redirect_chain: list[dict[str, Any]], error: str | None = None)`
  - `header_value(headers: dict[str, str], name: str) -> str`
  - `ssl_context_for_scheme(scheme: str, context: CheckContext) -> ssl.SSLContext | None`
  - `fetch_url_for_absolute_url(url: str, context: CheckContext) -> HttpResponse`
  - `follow_redirects(start_response: HttpResponse, context: CheckContext, max_redirects: int = MAX_REDIRECTS) -> RedirectResolution`

- [ ] **Step 1: Write failing tests for multi-hop and relative redirects**

Add these tests after `test_http_80_redirect_to_https_is_low_risk` in `test_assess_attack_surface.py`:

```python
    def test_follow_redirects_supports_multi_hop_redirect_chain(self):
        responses = {
            "http://app.example.com:80/": asm.HttpResponse(
                url="http://app.example.com:80/",
                status=301,
                headers={"Location": "https://login.example.com/start"},
                body=b"",
            ),
            "https://login.example.com/start": asm.HttpResponse(
                url="https://login.example.com/start",
                status=302,
                headers={"Location": "https://login.example.com/final"},
                body=b"",
            ),
            "https://login.example.com/final": asm.HttpResponse(
                url="https://login.example.com/final",
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Final</title></html>",
            ),
        }
        fetched_urls = []

        def fetcher(request, timeout, context=None):
            fetched_urls.append(request.full_url)
            return responses[request.full_url]

        start_response = responses["http://app.example.com:80/"]
        resolution = asm.follow_redirects(start_response, asm.CheckContext(fetcher=fetcher))

        self.assertIsNone(resolution.error)
        self.assertEqual(resolution.final_response.status, 200)
        self.assertEqual(resolution.final_response.url, "https://login.example.com/final")
        self.assertEqual(
            [hop["location"] for hop in resolution.redirect_chain],
            ["https://login.example.com/start", "https://login.example.com/final"],
        )
        self.assertEqual(fetched_urls, ["https://login.example.com/start", "https://login.example.com/final"])

    def test_follow_redirects_resolves_relative_location(self):
        responses = {
            "http://app.example.com:80/": asm.HttpResponse(
                url="http://app.example.com:80/",
                status=302,
                headers={"Location": "/login"},
                body=b"",
            ),
            "http://app.example.com:80/login": asm.HttpResponse(
                url="http://app.example.com:80/login",
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Login</title></html>",
            ),
        }
        fetched_urls = []

        def fetcher(request, timeout, context=None):
            fetched_urls.append(request.full_url)
            return responses[request.full_url]

        start_response = responses["http://app.example.com:80/"]
        resolution = asm.follow_redirects(start_response, asm.CheckContext(fetcher=fetcher))

        self.assertIsNone(resolution.error)
        self.assertEqual(resolution.final_response.url, "http://app.example.com:80/login")
        self.assertEqual(resolution.redirect_chain[0]["resolved_url"], "http://app.example.com:80/login")
        self.assertEqual(fetched_urls, ["http://app.example.com:80/login"])
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_follow_redirects_supports_multi_hop_redirect_chain test_assess_attack_surface.AssessAttackSurfaceTests.test_follow_redirects_resolves_relative_location
```

Expected: FAIL with `AttributeError: module 'assess_attack_surface' has no attribute 'follow_redirects'`.

- [ ] **Step 3: Implement redirect helper primitives**

In `assess_attack_surface.py`, add `import urllib.parse` beside the other `urllib` imports:

```python
import urllib.error
import urllib.parse
import urllib.request
```

Update redirect constants:

```python
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
```

Add this dataclass after `HttpResponse`:

```python
@dataclass(frozen=True)
class RedirectResolution:
    final_response: HttpResponse | None
    redirect_chain: list[dict[str, Any]]
    error: str | None = None
```

Add these helpers after `fetch_url`:

```python
def header_value(headers: dict[str, str], name: str) -> str:
    lowered_name = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered_name:
            return value
    return ""


def ssl_context_for_scheme(scheme: str, context: CheckContext) -> ssl.SSLContext | None:
    if scheme != "https":
        return None
    if context.insecure_tls:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=context.ca_bundle)


def fetch_url_for_absolute_url(url: str, context: CheckContext) -> HttpResponse:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "asm-checker/1.0",
            "Accept": "text/html,application/json,text/plain,*/*;q=0.8",
        },
        method="GET",
    )
    scheme = urllib.parse.urlparse(url).scheme.lower()
    fetcher = context.fetcher or fetch_url
    return fetcher(request, context.timeout_seconds, ssl_context_for_scheme(scheme, context))


def follow_redirects(
    start_response: HttpResponse,
    context: CheckContext,
    max_redirects: int = MAX_REDIRECTS,
) -> RedirectResolution:
    current_response = start_response
    redirect_chain: list[dict[str, Any]] = []

    for _ in range(max_redirects):
        if current_response.status not in REDIRECT_STATUSES:
            return RedirectResolution(final_response=current_response, redirect_chain=redirect_chain)

        location = header_value(current_response.headers, "Location").strip()
        hop: dict[str, Any] = {
            "url": current_response.url,
            "status": current_response.status,
            "location": location,
        }
        if not location:
            redirect_chain.append(hop)
            return RedirectResolution(
                final_response=None,
                redirect_chain=redirect_chain,
                error=f"Redirect response {current_response.status} missing Location header.",
            )

        next_url = urllib.parse.urljoin(current_response.url, location)
        hop["resolved_url"] = next_url
        parsed_next_url = urllib.parse.urlparse(next_url)
        if parsed_next_url.scheme.lower() not in {"http", "https"}:
            redirect_chain.append(hop)
            return RedirectResolution(
                final_response=None,
                redirect_chain=redirect_chain,
                error=f"Unsupported redirect URL scheme: {parsed_next_url.scheme or '<empty>'}.",
            )

        redirect_chain.append(hop)
        try:
            current_response = fetch_url_for_absolute_url(next_url, context)
        except urllib.error.URLError as exc:
            return RedirectResolution(
                final_response=None,
                redirect_chain=redirect_chain,
                error=f"Redirect target fetch failed for {next_url}: {exc.reason}",
            )

    if current_response.status in REDIRECT_STATUSES:
        location = header_value(current_response.headers, "Location").strip()
        hop = {
            "url": current_response.url,
            "status": current_response.status,
            "location": location,
        }
        if location:
            hop["resolved_url"] = urllib.parse.urljoin(current_response.url, location)
        redirect_chain.append(hop)
        return RedirectResolution(
            final_response=None,
            redirect_chain=redirect_chain,
            error=f"Redirect chain exceeded maximum of {max_redirects} redirects.",
        )

    return RedirectResolution(final_response=current_response, redirect_chain=redirect_chain)
```

- [ ] **Step 4: Refactor `fetch_endpoint` to reuse the absolute URL helper**

Replace the request-building body of `fetch_endpoint()` with:

```python
def fetch_endpoint(endpoint: dict[str, Any], scheme: str, context: CheckContext) -> HttpResponse:
    host = str(endpoint.get("host") or "").strip()
    port = endpoint.get("port")
    if not host or not isinstance(port, int):
        raise ValueError("Endpoint must include host and integer port")
    return fetch_url_for_absolute_url(f"{scheme}://{host}:{port}/", context)
```

- [ ] **Step 5: Run tests to verify helper behavior passes**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_follow_redirects_supports_multi_hop_redirect_chain test_assess_attack_surface.AssessAttackSurfaceTests.test_follow_redirects_resolves_relative_location
```

Expected: OK.

- [ ] **Step 6: Run existing TLS context regression test**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_fetch_endpoint_can_use_insecure_tls_context
```

Expected: OK.

- [ ] **Step 7: Commit task 1 in a git checkout**

Run:

```bash
git status --short
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "feat: add explicit redirect follow helpers"
```

Expected in this directory: skip this step if `git status` says `fatal: not a git repository`.

---

### Task 2: Shared Response Content Analysis

**Files:**
- Modify: `assess_attack_surface.py:154-242`
- Test: `test_assess_attack_surface.py:80-180`

**Interfaces:**
- Consumes: `summarize_response(response: HttpResponse) -> dict[str, Any]`, `summary_without_body(summary: dict[str, Any]) -> dict[str, Any]`, `detect_sensitive_signals(body_text: str) -> list[str]`, `looks_like_login_page(body_text: str) -> bool`, and `https_404_review_reasons(endpoint, summary)`.
- Produces:
  - `content_findings_for_response(endpoint: dict[str, Any], response: HttpResponse, context: CheckContext, detail_overrides: dict[str, Any] | None = None) -> list[dict[str, Any]]`
  - `HttpsContentChecker.check()` using the helper without behavior changes.

- [ ] **Step 1: Write a regression test for detail overrides**

Add this test after `test_https_content_checker_flags_directory_listing`:

```python
    def test_content_findings_for_response_adds_detail_overrides(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}
        response = asm.HttpResponse(
            url="https://app.example.com/final",
            status=200,
            headers={"Content-Type": "text/html"},
            body=b"<html><title>Index of /</title><h1>Index of /</h1></html>",
        )

        findings = asm.content_findings_for_response(
            endpoint,
            response,
            asm.CheckContext(),
            detail_overrides={"redirect_chain": [{"status": 301, "location": "https://app.example.com/final"}]},
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_sensitive_content_heuristic")
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertEqual(
            findings[0]["details"]["redirect_chain"],
            [{"status": 301, "location": "https://app.example.com/final"}],
        )
        self.assertEqual(findings[0]["details"]["url"], "https://app.example.com/final")
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_content_findings_for_response_adds_detail_overrides
```

Expected: FAIL with `AttributeError: module 'assess_attack_surface' has no attribute 'content_findings_for_response'`.

- [ ] **Step 3: Add shared response analysis helper**

Add this function above `class HttpsContentChecker`:

```python
def content_findings_for_response(
    endpoint: dict[str, Any],
    response: HttpResponse,
    context: CheckContext,
    detail_overrides: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    summary = summarize_response(response)
    endpoint_id = str(endpoint.get("id", ""))
    if endpoint_id:
        context.response_summaries[endpoint_id] = summary

    details = summary_without_body(summary)
    if detail_overrides:
        details = {**details, **detail_overrides}

    if context.llm_enabled and response.status == 200:
        return []

    if response.status == 404:
        not_found_review_reasons = https_404_review_reasons(endpoint, summary)
        if not_found_review_reasons:
            return [
                finding(
                    endpoint,
                    "https_not_found_review",
                    "medium",
                    f"HTTPS endpoint returned 404, but still requires review: {', '.join(not_found_review_reasons)}.",
                    "Confirm whether other paths or virtual hosts are exposed; remove framework/version disclosures where possible.",
                    details={**details, "review_reasons": not_found_review_reasons},
                )
            ]
        return [
            finding(
                endpoint,
                "https_not_found",
                "low",
                "HTTPS endpoint returned a clean 404 response at the root path.",
                "No immediate content exposure detected at the root path; keep monitoring routed paths separately.",
                details=details,
            )
        ]

    signals = detect_sensitive_signals(summary["body_text"])
    if signals:
        return [
            finding(
                endpoint,
                "https_sensitive_content_heuristic",
                "high",
                f"HTTPS response contains potentially sensitive signals: {', '.join(signals)}.",
                "Review the exposed content, remove sensitive material, add authentication, or restrict network access.",
                details={**details, "signals": signals},
            )
        ]

    if looks_like_login_page(summary["body_text"]):
        return [
            finding(
                endpoint,
                "https_login_page",
                "low",
                "HTTPS endpoint appears to be a login page rather than direct sensitive content.",
                "Keep authentication enforced; validate MFA, rate limiting, and WAF controls separately.",
                details=details,
            )
        ]

    return [
        finding(
            endpoint,
            "https_review_required",
            "medium",
            "HTTPS endpoint is reachable and did not match low-risk login-page or high-risk sensitive-content heuristics.",
            "Review ownership, authentication, expected exposure, and consider LLM-assisted content assessment.",
            details=details,
        )
    ]
```

- [ ] **Step 4: Refactor `HttpsContentChecker.check()` to call the helper**

Replace everything in `HttpsContentChecker.check()` after the TLS error handling block with:

```python
        return content_findings_for_response(endpoint, response, context)
```

The method should become:

```python
class HttpsContentChecker:
    check_id = "https_content"

    def check(self, endpoint: dict[str, Any], context: CheckContext) -> list[dict[str, Any]]:
        if endpoint.get("port") != 443:
            return []
        try:
            response = fetch_endpoint(endpoint, "https", context)
        except urllib.error.URLError as exc:
            if is_tls_certificate_error(exc):
                return [
                    finding(
                        endpoint,
                        "https_tls_certificate_error",
                        "medium",
                        f"HTTPS certificate validation failed: {exc.reason}",
                        "Fix certificate chain/hostname mismatch. Use --insecure-tls only for follow-up content triage, not as a control.",
                        details={"error": str(exc.reason)},
                    )
                ]
            raise
        return content_findings_for_response(endpoint, response, context)
```

- [ ] **Step 5: Run focused shared-analysis test**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_content_findings_for_response_adds_detail_overrides
```

Expected: OK.

- [ ] **Step 6: Run direct HTTPS regression tests**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_identifies_login_page_as_low_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_flags_directory_listing \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_reports_tls_certificate_error \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_marks_clean_404_as_low_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_https_content_checker_keeps_high_exposure_404_as_medium
```

Expected: OK.

- [ ] **Step 7: Commit task 2 in a git checkout**

Run:

```bash
git status --short
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "refactor: share HTTP response exposure analysis"
```

Expected in this directory: skip this step if `git status` says `fatal: not a git repository`.

---

### Task 3: HTTP Redirect Checker Final-Target Analysis

**Files:**
- Modify: `assess_attack_surface.py:123-153`
- Test: `test_assess_attack_surface.py:42-90`

**Interfaces:**
- Consumes: `follow_redirects(start_response, context, max_redirects=MAX_REDIRECTS)`, `content_findings_for_response(endpoint, response, context, detail_overrides=None)`, and `header_value(headers, "Location")`.
- Produces: `HttpRedirectChecker.check()` that returns content-analysis findings for redirected endpoints and preserves `http_without_https_redirect` for non-redirect responses.

- [ ] **Step 1: Replace the old low-risk redirect test with final-target sensitive analysis**

Replace `test_http_80_redirect_to_https_is_low_risk` with:

```python
    def test_http_80_redirect_to_https_sensitive_content_is_high_risk(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}
        responses = {
            "http://app.example.com:80/": asm.HttpResponse(
                url="http://app.example.com:80/",
                status=301,
                headers={"Location": "https://app.example.com/"},
                body=b"",
            ),
            "https://app.example.com/": asm.HttpResponse(
                url="https://app.example.com/",
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Index of /</title><h1>Index of /</h1><a href='backup.zip'>backup.zip</a></html>",
            ),
        }

        def fetcher(request, timeout, context=None):
            return responses[request.full_url]

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_sensitive_content_heuristic")
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertEqual(findings[0]["details"]["final_url"], "https://app.example.com/")
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["status"], 301)
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["location"], "https://app.example.com/")
```

- [ ] **Step 2: Add a test for redirected login page remaining low risk**

Add this test after the sensitive redirect test:

```python
    def test_http_80_redirect_to_login_page_is_low_risk_with_redirect_evidence(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}
        responses = {
            "http://app.example.com:80/": asm.HttpResponse(
                url="http://app.example.com:80/",
                status=302,
                headers={"Location": "https://app.example.com/login"},
                body=b"",
            ),
            "https://app.example.com/login": asm.HttpResponse(
                url="https://app.example.com/login",
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Sign in</title><input type='password'></html>",
            ),
        }

        def fetcher(request, timeout, context=None):
            return responses[request.full_url]

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_login_page")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["final_url"], "https://app.example.com/login")
        self.assertEqual(len(findings[0]["details"]["redirect_chain"]), 1)
```

- [ ] **Step 3: Run tests to verify the first test fails**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_to_https_sensitive_content_is_high_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_to_login_page_is_low_risk_with_redirect_evidence
```

Expected: FAIL because `HttpRedirectChecker` still returns `http_redirect_to_https` and does not fetch the final target.

- [ ] **Step 4: Update `HttpRedirectChecker.check()`**

Replace `HttpRedirectChecker.check()` with:

```python
class HttpRedirectChecker:
    check_id = "http_redirect"

    def check(self, endpoint: dict[str, Any], context: CheckContext) -> list[dict[str, Any]]:
        if endpoint.get("port") != 80:
            return []
        response = fetch_endpoint(endpoint, "http", context)
        location = header_value(response.headers, "Location")
        if response.status in REDIRECT_STATUSES:
            resolution = follow_redirects(response, context)
            detail_overrides = {
                "initial_status": response.status,
                "initial_location": location,
                "redirect_chain": resolution.redirect_chain,
            }
            if resolution.error or resolution.final_response is None:
                return [
                    finding(
                        endpoint,
                        "http_redirect_follow_error",
                        "medium",
                        f"HTTP 80 redirect could not be fully analyzed: {resolution.error}",
                        "Investigate the redirect chain and verify the final target does not expose sensitive data.",
                        details=detail_overrides,
                    )
                ]
            return content_findings_for_response(
                endpoint,
                resolution.final_response,
                context,
                detail_overrides={**detail_overrides, "final_url": resolution.final_response.url},
            )
        return [
            finding(
                endpoint,
                "http_without_https_redirect",
                "medium",
                f"HTTP 80 returned HTTP {response.status} without a forced HTTPS redirect.",
                "Force HTTP to HTTPS or close port 80 if it is not required.",
                details={"status": response.status, "location": location, "title": extract_title(response.body)},
            )
        ]
```

- [ ] **Step 5: Run redirect checker tests**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_to_https_sensitive_content_is_high_risk \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_to_login_page_is_low_risk_with_redirect_evidence \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_without_https_redirect_is_reduce_candidate
```

Expected: OK.

- [ ] **Step 6: Commit task 3 in a git checkout**

Run:

```bash
git status --short
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "feat: analyze final redirect target content"
```

Expected in this directory: skip this step if `git status` says `fatal: not a git repository`.

---

### Task 4: Redirect Error Cases

**Files:**
- Modify: `assess_attack_surface.py:72-153`
- Test: `test_assess_attack_surface.py:42-130`

**Interfaces:**
- Consumes: `follow_redirects()` and `HttpRedirectChecker.check()` from Tasks 1 and 3.
- Produces: medium-risk `http_redirect_follow_error` findings for missing `Location`, unsupported schemes, and redirect limit exhaustion.

- [ ] **Step 1: Add tests for missing Location and max redirects**

Add these tests after `test_http_80_redirect_to_login_page_is_low_risk_with_redirect_evidence`:

```python
    def test_http_80_redirect_missing_location_reports_follow_error(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=302,
                headers={},
                body=b"",
            )

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("missing Location", findings[0]["evidence"])
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["status"], 302)

    def test_http_80_redirect_exceeding_max_redirects_reports_follow_error(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            current_url = request.full_url
            if current_url == "http://app.example.com:80/":
                next_url = "http://app.example.com:80/redirect-1"
            else:
                index = int(current_url.rsplit("-", 1)[1])
                next_url = f"http://app.example.com:80/redirect-{index + 1}"
            return asm.HttpResponse(
                url=current_url,
                status=302,
                headers={"Location": next_url},
                body=b"",
            )

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertIn("exceeded maximum of 5 redirects", findings[0]["evidence"])
        self.assertEqual(len(findings[0]["details"]["redirect_chain"]), 6)
```

- [ ] **Step 2: Add a test for unsupported schemes**

Add this test after the max redirect test:

```python
    def test_http_80_redirect_to_unsupported_scheme_reports_follow_error(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=302,
                headers={"Location": "ftp://files.example.com/public"},
                body=b"",
            )

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertIn("Unsupported redirect URL scheme: ftp", findings[0]["evidence"])
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["resolved_url"], "ftp://files.example.com/public")
```

- [ ] **Step 3: Run error-case tests**

Run:

```bash
python3 -m unittest \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_missing_location_reports_follow_error \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_exceeding_max_redirects_reports_follow_error \
  test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_to_unsupported_scheme_reports_follow_error
```

Expected after Tasks 1 and 3: OK. If the max-redirect test reports chain length 5 instead of 6, keep the Task 1 implementation exactly as written so the unresolved final redirect response is included as evidence.

- [ ] **Step 4: Add a test for fetch failure preserving redirect-chain evidence**

Add this test after the unsupported-scheme test:

```python
    def test_http_80_redirect_target_fetch_failure_reports_follow_error_with_chain(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            if request.full_url == "http://app.example.com:80/":
                return asm.HttpResponse(
                    url=request.full_url,
                    status=302,
                    headers={"Location": "https://app.example.com/"},
                    body=b"",
                )
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("connection refused", findings[0]["evidence"])
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["resolved_url"], "https://app.example.com/")
```

- [ ] **Step 5: Run fetch-failure test**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_http_80_redirect_target_fetch_failure_reports_follow_error_with_chain
```

Expected: OK. This uses the explicit `urllib.error.URLError` handling in `follow_redirects()` and keeps the partial redirect chain in finding details.

- [ ] **Step 6: Commit task 4 in a git checkout**

Run:

```bash
git status --short
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "test: cover redirect follow failure evidence"
```

Expected in this directory: skip this step if `git status` says `fatal: not a git repository`.

---

### Task 5: LLM Handoff for Redirected Final Responses

**Files:**
- Modify: `assess_attack_surface.py:123-153`
- Test: `test_assess_attack_surface.py:300-370`

**Interfaces:**
- Consumes: `content_findings_for_response()` storing `context.response_summaries[endpoint_id]`.
- Produces: When `context.llm_enabled` is true and the redirected final response status is 200, `HttpRedirectChecker.check()` returns no heuristic finding and `LlmSensitiveContentChecker.check()` returns the LLM finding using the final response body.

- [ ] **Step 1: Add redirected LLM test**

Add this test after `test_http_200_https_response_uses_llm_instead_of_review_required_when_enabled`:

```python
    def test_http_redirect_final_response_uses_llm_when_enabled(self):
        llm_calls = []
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}
        responses = {
            "http://app.example.com:80/": asm.HttpResponse(
                url="http://app.example.com:80/",
                status=302,
                headers={"Location": "https://app.example.com/"},
                body=b"",
            ),
            "https://app.example.com/": asm.HttpResponse(
                url="https://app.example.com/",
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Welcome</title><p>Public page</p></html>",
            ),
        }

        def fetcher(request, timeout, context=None):
            return responses[request.full_url]

        def llm_client(prompt):
            llm_calls.append(prompt)
            return {
                "risk_level": "low",
                "reason": "Public redirected landing page",
                "evidence": "这是一个公开页面，没有敏感数据",
                "recommendation": "No action.",
            }

        findings = asm.assess_endpoint(
            endpoint,
            [asm.HttpRedirectChecker(), asm.LlmSensitiveContentChecker()],
            asm.CheckContext(fetcher=fetcher, llm_enabled=True, llm_client=llm_client),
        )

        self.assertEqual([finding["check_id"] for finding in findings], ["llm_sensitive_content"])
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["url"], "https://app.example.com/")
        self.assertIn("Public page", llm_calls[0])
```

- [ ] **Step 2: Run redirected LLM test**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_http_redirect_final_response_uses_llm_when_enabled
```

Expected after Tasks 2 and 3: OK.

- [ ] **Step 3: Verify final response summary is overwritten with redirected target**

Add this assertion before the final `self.assertIn("Public page", llm_calls[0])` in the same test:

```python
        self.assertIn("这是一个公开页面，没有敏感数据", findings[0]["evidence"])
```

- [ ] **Step 4: Run redirected LLM test again**

Run:

```bash
python3 -m unittest test_assess_attack_surface.AssessAttackSurfaceTests.test_http_redirect_final_response_uses_llm_when_enabled
```

Expected: OK.

- [ ] **Step 5: Commit task 5 in a git checkout**

Run:

```bash
git status --short
git add assess_attack_surface.py test_assess_attack_surface.py
git commit -m "test: verify LLM assesses redirected final responses"
```

Expected in this directory: skip this step if `git status` says `fatal: not a git repository`.

---

### Task 6: Full Regression Run

**Files:**
- Modify: no source changes expected
- Test: `test_assess_attack_surface.py`

**Interfaces:**
- Consumes all previous task outputs.
- Produces verified redirect-follow sensitive exposure analysis with existing behavior preserved.

- [ ] **Step 1: Run the full unit test suite**

Run:

```bash
python3 -m unittest test_assess_attack_surface.py
```

Expected: OK.

- [ ] **Step 2: Run the scanner help command**

Run:

```bash
python3 assess_attack_surface.py --help >/tmp/asm-help.txt && grep -E -- '--timeout|--insecure-tls|--enable-llm|--csv-output' /tmp/asm-help.txt
```

Expected output includes all four existing options:

```text
  --timeout TIMEOUT     HTTP timeout in seconds.
  --insecure-tls        Disable TLS certificate verification for response-content triage.
  --enable-llm          Enable OpenAI-compatible LLM content judgment.
  --csv-output CSV_OUTPUT
```

- [ ] **Step 3: Remove temporary help output**

Run:

```bash
rm -f /tmp/asm-help.txt
```

Expected: command exits with status 0.

- [ ] **Step 4: Inspect final diff in a git checkout**

Run:

```bash
git diff -- assess_attack_surface.py test_assess_attack_surface.py docs/superpowers/specs/2026-07-29-redirect-follow-design.md docs/superpowers/plans/2026-07-29-redirect-follow-sensitive-analysis.md
```

Expected: diff only includes redirect-follow helpers, shared response analysis refactor, redirect tests, and spec/plan docs.

- [ ] **Step 5: Commit final verification in a git checkout if previous tasks were not committed**

Run:

```bash
git status --short
git add assess_attack_surface.py test_assess_attack_surface.py docs/superpowers/specs/2026-07-29-redirect-follow-design.md docs/superpowers/plans/2026-07-29-redirect-follow-sensitive-analysis.md
git commit -m "feat: follow redirects for sensitive exposure analysis"
```

Expected in this directory: skip this step if `git status` says `fatal: not a git repository`.
