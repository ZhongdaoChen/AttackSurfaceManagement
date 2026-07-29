# Redirect Follow Sensitive Exposure Analysis Design

## Purpose

When an endpoint returns an HTTP redirect, the scanner must continue following the redirect and analyze the final target for sensitive data exposure. This applies to same-host and cross-host redirects, HTTPS and HTTP targets, and multi-hop redirect chains, with a maximum redirect limit to avoid loops.

## Approved approach

Keep `fetch_url` configured to not automatically follow redirects. The scanner needs each redirect response as evidence, so redirect handling should be explicit in the checker layer rather than hidden inside `urllib`.

Add a small redirect-follow helper that:

- Starts from the current request URL and first response.
- Treats 301, 302, 303, 307, and 308 as redirects.
- Resolves relative `Location` values with `urllib.parse.urljoin`.
- Follows only `http` and `https` URLs.
- Stops after 5 redirects and reports a failure finding if the chain is not resolved.
- Returns the final response plus a `redirect_chain` containing each hop's URL, status, and Location.

## Data flow

`HttpRedirectChecker` should still assess port 80 endpoints. If the HTTP root returns a redirect, it will call the redirect helper and then analyze the final target response with the existing content heuristics. The final response summary should be stored in `context.response_summaries` under the endpoint id so `LlmSensitiveContentChecker` can reuse it when LLM analysis is enabled.

Findings for redirected endpoints should include:

- The original redirect status and Location.
- The complete redirect chain.
- The final URL, status, content type, and title.
- Sensitive-signal details when the final response exposes data.

If the final response is a normal login page or clean 404, the existing low-risk behavior should still apply, but with redirect evidence attached.

## Error handling

Redirect analysis must not silently ignore unresolved redirects. Missing `Location`, unsupported URL schemes, redirect loops or chains beyond the 5-hop limit, and fetch failures should produce a finding that includes the partial redirect chain and a clear recommendation to investigate the redirect target.

TLS behavior should remain consistent with existing HTTPS checks: use certificate validation by default and respect `--insecure-tls` when the user opts into content triage with unverified TLS.

## Testing

Add focused unit tests for:

- HTTP 80 redirecting to HTTPS content with sensitive signals.
- Multi-hop redirects.
- Relative `Location` headers.
- Exceeding the maximum redirect limit.
- Missing `Location` headers.
- LLM-enabled assessment using the final redirected response.

Existing tests for non-redirect HTTP and direct HTTPS content behavior should continue to pass.
