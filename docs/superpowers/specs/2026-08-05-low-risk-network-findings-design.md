# Low Risk Network Findings Design

## Purpose

Adjust selected network/configuration findings to `low` so the output better reflects current triage priorities.

## Behavior changes

- `http_without_https_redirect` changes from `medium` to `low`.
- `https_tls_certificate_error` changes from `medium` to `low`.
- Direct HTTPS connection reset failures should no longer fall through to the generic `https_content_error` / `unknown` path.
- `HttpsContentChecker` should return a specific low-risk finding for connection reset, using `check_id = "https_connection_reset"`.

## Scope

Only direct HTTPS content checks should get the new connection reset finding. Other checker exceptions should continue to be reported as `unknown` by the generic `assess_endpoint()` error handling.

Connection reset detection should cover:

- `ConnectionResetError`
- `urllib.error.URLError` whose `reason` indicates connection reset
- exception text that contains `Connection reset by peer`

## Testing

Update existing tests for HTTP 80 and TLS certificate findings to expect `low`. Add or adjust coverage so a direct HTTPS connection reset produces one `https_connection_reset` finding with `risk_level = "low"` instead of generic unknown.
