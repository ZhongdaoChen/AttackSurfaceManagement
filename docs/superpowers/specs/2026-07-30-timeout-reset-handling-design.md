# Timeout and Connection Reset Handling Design

## Purpose

Network failures should produce more useful scan findings. A connection reset means the remote side closed the connection before content could be reviewed, so it should be treated as low risk rather than unknown. A timeout should get one retry with twice the configured timeout before the scanner gives up.

## Approved approach

Add explicit network-error classification in `assess_attack_surface.py`:

- Connection reset failures become low-risk findings.
- Timeout failures are retried once with `timeout_seconds * 2`.
- If the retry succeeds, normal response analysis continues.
- If the retry also times out, the scanner emits an explicit timeout failure finding.
- TLS certificate validation failures keep the existing medium-risk behavior.

## Timeout retry behavior

The first request uses the configured timeout from `--timeout`. If the request fails with `TimeoutError`, `socket.timeout`, or a `urllib.error.URLError` whose reason indicates a timeout, retry the same request once with double the timeout.

Only timeout failures get the double-time retry. Other network errors are not retried.

## Connection reset behavior

Treat `ConnectionResetError` or a network failure whose reason text contains `connection reset` as low risk. Evidence should say the remote peer reset the connection and no content exposure was observed. The recommendation should suggest later retesting rather than immediate remediation.

This behavior applies to:

- Direct HTTPS content checks.
- HTTP/HTTPS redirect target fetches.
- Generic checker network failures surfaced through `assess_endpoint()`.

## Error handling

Do not add a broad catch-all that hides programming errors. Only classify explicit network failures: `urllib.error.URLError`, `TimeoutError`, `socket.timeout`, `http.client.HTTPException`, `OSError`, and their reason values.

Redirect failures must keep partial `redirect_chain` evidence when a target fetch fails.

## Testing

Add unit coverage for:

- Direct HTTPS `ConnectionResetError` returns a low-risk finding.
- Redirect target `ConnectionResetError` returns a low-risk redirect follow finding with redirect-chain evidence.
- A timeout retries once with double the configured timeout and succeeds.
- A timeout that fails again after the doubled retry returns an explicit timeout finding.

Run the full unit suite after implementation.
