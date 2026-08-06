# Non-Standard Port Content Probe Design

## Purpose

Improve non-standard open port triage by probing HTTP/HTTPS content before assigning the final risk level.

## Behavior

For `portStatus=OPEN` endpoints whose port is not `80` or `443`:

1. Try fetching `https://host:port/`.
2. Try fetching `http://host:port/` if HTTPS did not produce a usable response.
3. If either protocol returns an HTTP response, classify the response content:
   - sensitive heuristic signals or LLM high => `high`
   - LLM low / login page / clean 404 / low-risk network condition => `low`
4. If neither protocol produces a usable response, fall back to the existing non-standard port logic:
   - FDP or `197575089658` subscription/account exception => `low`
   - otherwise => `high`

## LLM handling

When LLM is enabled and a non-standard port returns HTTP 200, the response summary should be stored in `context.response_summaries` and `LlmSensitiveContentChecker` should produce the LLM finding, matching existing 443 behavior.

## Check IDs

Content-derived findings should reuse existing content check IDs such as `https_sensitive_content_heuristic`, `https_login_page`, `https_not_found`, and `llm_sensitive_content`.

Fallback findings keep `check_id = "non_standard_open_port"`.

## Testing

Add tests for:

- Non-standard HTTPS content with sensitive signals returns high.
- Non-standard HTTPS content with LLM low returns low via the LLM checker.
- HTTPS failure followed by HTTP success is classified from HTTP response content.
- Both protocol attempts failing falls back to existing subscription/account logic.
