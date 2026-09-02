#!/usr/bin/env python3
"""Assess exported Wiz application endpoints for attack surface reduction."""

from __future__ import annotations

import argparse
import csv
import datetime
import html
import json
import os
import re
import ssl
import sys
import http.client
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Protocol, TextIO

import upload_to_oss
import rds_writer
import wiz_auth_poc


DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_BODY_LIMIT_BYTES = 64 * 1024
DEFAULT_LLM_BODY_LIMIT_CHARS = 12000
DEFAULT_JS_ASSET_LIMIT_BYTES = 512 * 1024
MAX_JAVASCRIPT_ASSETS = 5
DEFAULT_API_ENDPOINT_LIMIT_BYTES = 64 * 1024
MAX_API_ENDPOINTS = 5
DEFAULT_QWEN_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
DEFAULT_QWEN_MODEL = "qwen-plus"
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
NON_STANDARD_PORT_PROBE_TIMEOUT_SECONDS = 5
RISK_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3}
SIGNAL_RISK_LEVELS = {
    "admin_surface": "medium",
    "directory_listing": "high",
    "default_admin_credential": "high",
    "secret_like_value": "high",
    "error_stack_trace": "high",
    "backup_artifact": "high",
}
LOW_RISK_SUBSCRIPTIONS = {
    "fdp",
    "197575089658",
    "adidas-linked-bam-pro-cn",
    "347233338954",
    "adidas-linked-tbm-cn",
    "482708397438",
    "adidas-linked-bam-dev-cn",
    "347077314801",
    "adidas-linked-bam-int-cn",
    "347221608445",
    "cicdtools-prod",
    "mobileprintjob production",
    "251239237414",
    "connectivity-dev development",
    "014826645533",
    "networkconnectivity",
    "779205442100",
    "adidas-linked-bitbucket-prd-cn",
    "568986100496",
}
SUBSCRIPTION_FIELDS = (
    "subscription",
    "Subscription",
    "subscriptionName",
    "subscriptionId",
    "accountId",
    "cloudAccountId",
)


@dataclass(frozen=True)
class HttpResponse:
    url: str
    status: int
    headers: dict[str, str]
    body: bytes


HttpFetcher = Callable[[urllib.request.Request, int, ssl.SSLContext | None], HttpResponse]
LlmClient = Callable[[str], dict[str, Any]]


@dataclass(frozen=True)
class RedirectResolution:
    final_response: HttpResponse | None
    redirect_chain: list[dict[str, Any]]
    error: str | None = None


@dataclass
class CheckContext:
    fetcher: HttpFetcher | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    body_limit_bytes: int = DEFAULT_BODY_LIMIT_BYTES
    ca_bundle: str | None = None
    insecure_tls: bool = True
    llm_enabled: bool = True
    llm_client: LlmClient | None = None
    response_summaries: dict[str, dict[str, Any]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.fetcher is None:
            self.fetcher = fetch_url
        if self.ca_bundle is None:
            self.ca_bundle = detect_ca_bundle()


class Checker(Protocol):
    check_id: str

    def check(self, endpoint: dict[str, Any], context: CheckContext) -> list[dict[str, Any]]:
        ...


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def fetch_url(
    request: urllib.request.Request,
    timeout: int,
    context: ssl.SSLContext | None = None,
) -> HttpResponse:
    body_limit_bytes = getattr(request, "_asm_body_limit_bytes", DEFAULT_BODY_LIMIT_BYTES)
    return fetch_url_with_body_limit(request, timeout, context, body_limit_bytes)


def fetch_url_with_body_limit(
    request: urllib.request.Request,
    timeout: int,
    context: ssl.SSLContext | None = None,
    body_limit_bytes: int = DEFAULT_BODY_LIMIT_BYTES,
) -> HttpResponse:
    handlers: list[Any] = [NoRedirectHandler]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        response_context = opener.open(request, timeout=timeout)
        with response_context as response:
            body = response.read(body_limit_bytes)
            status = getattr(response, "status", None)
            if status is None:
                status = response.getcode()
            return HttpResponse(
                url=response.geturl(),
                status=status,
                headers={key: value for key, value in response.headers.items()},
                body=body,
            )
    except urllib.error.HTTPError as exc:
        body = exc.read(body_limit_bytes)
        return HttpResponse(
            url=request.full_url,
            status=exc.code,
            headers={key: value for key, value in exc.headers.items()},
            body=body,
        )


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


def fetch_url_for_absolute_url(
    url: str,
    context: CheckContext,
    body_limit_bytes: int | None = None,
) -> HttpResponse:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "asm-checker/1.0",
            "Accept": "text/html,application/json,text/plain,*/*;q=0.8",
        },
        method="GET",
    )
    setattr(request, "_asm_body_limit_bytes", body_limit_bytes or context.body_limit_bytes)
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

        try:
            next_url = urllib.parse.urljoin(current_response.url, location)
            parsed_next_url = urllib.parse.urlparse(next_url)
        except ValueError as exc:
            redirect_chain.append(hop)
            return RedirectResolution(
                final_response=None,
                redirect_chain=redirect_chain,
                error=f"Invalid redirect URL: {exc}",
            )
        hop["resolved_url"] = next_url
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
        except (urllib.error.URLError, ValueError, http.client.HTTPException, OSError) as exc:
            return RedirectResolution(
                final_response=None,
                redirect_chain=redirect_chain,
                error=f"Redirect target fetch failed for {next_url}: {redirect_fetch_error_reason(exc)}",
            )

    if current_response.status in REDIRECT_STATUSES:
        location = header_value(current_response.headers, "Location").strip()
        hop = {
            "url": current_response.url,
            "status": current_response.status,
            "location": location,
        }
        if location:
            try:
                hop["resolved_url"] = urllib.parse.urljoin(current_response.url, location)
            except ValueError:
                pass
        redirect_chain.append(hop)
        return RedirectResolution(
            final_response=None,
            redirect_chain=redirect_chain,
            error=f"Redirect chain exceeded maximum of {max_redirects} redirects.",
        )

    return RedirectResolution(final_response=current_response, redirect_chain=redirect_chain)


def redirect_fetch_error_reason(exc: BaseException) -> str:
    reason = getattr(exc, "reason", None)
    if reason is not None:
        return str(reason)
    return str(exc)


def is_connection_reset_error(exc: BaseException) -> bool:
    if isinstance(exc, ConnectionResetError):
        return True
    reason = getattr(exc, "reason", None)
    if isinstance(reason, ConnectionResetError):
        return True
    return "connection reset by peer" in str(exc).lower()


def subscription_value(endpoint: dict[str, Any]) -> str:
    for field in SUBSCRIPTION_FIELDS:
        value = endpoint.get(field)
        if value is not None and str(value).strip():
            return str(value).strip()
    cloud_account = endpoint.get("cloudAccount")
    if isinstance(cloud_account, dict):
        for field in ("name", "externalId", "id"):
            value = cloud_account.get(field)
            if value is not None and str(value).strip():
                return str(value).strip()
    return ""


def is_low_risk_subscription(endpoint: dict[str, Any]) -> bool:
    value = subscription_value(endpoint)
    return value.lower() in LOW_RISK_SUBSCRIPTIONS


class NonStandardPortChecker:
    check_id = "non_standard_open_port"

    def check(self, endpoint: dict[str, Any], context: CheckContext) -> list[dict[str, Any]]:
        port = endpoint.get("port")
        if endpoint.get("portStatus") != "OPEN" or port in (80, 443):
            return []
        content_findings, probe_errors = non_standard_port_content_findings(endpoint, context)
        if content_findings is not None:
            return content_findings
        return [fallback_non_standard_port_finding(endpoint, port, probe_errors)]


def non_standard_port_content_findings(
    endpoint: dict[str, Any],
    context: CheckContext,
) -> tuple[list[dict[str, Any]] | None, list[dict[str, Any]]]:
    probe_errors = []
    probe_context = CheckContext(
        fetcher=context.fetcher,
        timeout_seconds=NON_STANDARD_PORT_PROBE_TIMEOUT_SECONDS,
        body_limit_bytes=context.body_limit_bytes,
        ca_bundle=context.ca_bundle,
        insecure_tls=context.insecure_tls,
        llm_enabled=context.llm_enabled,
        llm_client=context.llm_client,
        response_summaries=context.response_summaries,
    )
    for scheme in ("https", "http"):
        try:
            response = fetch_endpoint(endpoint, scheme, probe_context)
        except (urllib.error.URLError, ValueError, http.client.HTTPException, OSError, ConnectionResetError) as exc:
            probe_errors.append({"scheme": scheme, "error": redirect_fetch_error_reason(exc)})
            continue
        probe_result = http_probe_result(probe_errors, scheme, response.status)
        return (
            response_content_findings(
                endpoint,
                response,
                context,
                f"Non-standard port {endpoint.get('port')} {scheme.upper()} redirect",
                detail_overrides={
                    "non_standard_port": endpoint.get("port"),
                    "probe_scheme": scheme,
                    "http_probe_result": probe_result,
                    **({"probe_errors": probe_errors} if probe_errors else {}),
                },
            ),
            probe_errors,
        )
    return None, probe_errors


def http_probe_result(probe_errors: list[dict[str, Any]], success_scheme: str | None = None, status: int | None = None) -> str:
    parts = [f"{error['scheme']} failed: {error['error']}" for error in probe_errors]
    if success_scheme is not None and status is not None:
        parts.append(f"{success_scheme} returned HTTP {status}")
    return "; ".join(parts)


def fallback_non_standard_port_finding(endpoint: dict[str, Any], port: Any, probe_errors: list[dict[str, Any]]) -> dict[str, Any]:
    subscription = subscription_value(endpoint)
    low_risk_subscription = is_low_risk_subscription(endpoint)
    risk_level = "low" if low_risk_subscription else "high"
    return finding(
        endpoint,
        NonStandardPortChecker.check_id,
        risk_level,
        f"Open non-standard internet-facing port {port}.",
        (
            "Confirm business need; subscription/account exception lowers priority, but keep the port documented and monitored."
            if low_risk_subscription
            else "Confirm business need; close the port or restrict it with an allowlist, VPN, WAF, or internal load balancer."
        ),
        details={
            "port": port,
            "protocols": endpoint.get("protocols"),
            "http_probe_result": http_probe_result(probe_errors),
            "probe_errors": probe_errors,
            **({"subscription": subscription} if subscription else {}),
        },
    )


class HttpRedirectChecker:
    check_id = "http_redirect"

    def check(self, endpoint: dict[str, Any], context: CheckContext) -> list[dict[str, Any]]:
        if endpoint.get("port") != 80:
            return []
        response = fetch_endpoint(endpoint, "http", context)
        location = header_value(response.headers, "Location")

        if response.status in REDIRECT_STATUSES:
            return redirected_response_findings(endpoint, response, context, "HTTP 80 redirect")

        return [
            finding(
                endpoint,
                "http_without_https_redirect",
                "low",
                f"HTTP 80 returned HTTP {response.status} without a forced HTTPS redirect.",
                "Force HTTP to HTTPS or close port 80 if it is not required.",
                details={"status": response.status, "location": location, "title": extract_title(response.body)},
            )
        ]


def response_content_findings(
    endpoint: dict[str, Any],
    response: HttpResponse,
    context: CheckContext,
    redirect_label: str,
    detail_overrides: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if response.status in REDIRECT_STATUSES:
        return redirected_response_findings(endpoint, response, context, redirect_label, detail_overrides)
    return content_findings_for_response(endpoint, response, context, detail_overrides=detail_overrides)


def redirected_response_findings(
    endpoint: dict[str, Any],
    response: HttpResponse,
    context: CheckContext,
    label: str,
    detail_overrides: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    resolution = follow_redirects(response, context)
    redirect_details = {
        **(detail_overrides or {}),
        "initial_status": response.status,
        "initial_location": header_value(response.headers, "Location"),
        "redirect_chain": resolution.redirect_chain,
    }
    if resolution.error or resolution.final_response is None:
        return [
            finding(
                endpoint,
                "http_redirect_follow_error",
                "medium",
                f"{label} could not be fully analyzed: {resolution.error}",
                "Investigate the redirect chain and verify the final target does not expose sensitive data.",
                details=redirect_details,
            )
        ]

    return content_findings_for_response(
        endpoint,
        resolution.final_response,
        context,
        detail_overrides={**redirect_details, "final_url": resolution.final_response.url},
    )


def content_findings_for_response(
    endpoint: dict[str, Any],
    response: HttpResponse,
    context: CheckContext,
    detail_overrides: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    summary = summarize_response(response, context)
    signals = detect_sensitive_signals(response_detection_text(summary))
    if signals:
        summary["local_signals"] = signals
        summary["local_risk_floor"] = risk_floor_for_signals(signals)
    endpoint_id = str(endpoint.get("id", ""))
    if endpoint_id:
        context.response_summaries[endpoint_id] = summary

    details = summary_without_body(summary)
    if detail_overrides:
        details = {**details, **detail_overrides}

    # When LLM assessment is enabled we skip local heuristics for 200 responses and
    # defer to the LLM checker to produce a single finding.
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

    risk_floor = str(summary.get("local_risk_floor") or "unknown")
    if signals and risk_floor == "high":
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
        if "admin_surface" in signals:
            return [
                finding(
                    endpoint,
                    "https_admin_login_page",
                    "medium",
                    "HTTPS endpoint appears to expose an administrative login page.",
                    "Confirm business need; restrict administrative surfaces with VPN, allowlists, SSO, MFA, and rate limiting.",
                    details={**details, "signals": signals},
                )
            ]
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

    if signals:
        return [
            finding(
                endpoint,
                "https_admin_surface_review",
                "medium",
                f"HTTPS endpoint contains administrative-surface signals: {', '.join(signals)}.",
                "Review whether this administrative surface should be internet-facing; restrict access where possible.",
                details={**details, "signals": signals},
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


class HttpsContentChecker:
    check_id = "https_content"

    def check(self, endpoint: dict[str, Any], context: CheckContext) -> list[dict[str, Any]]:
        if endpoint.get("port") != 443:
            return []
        try:
            response = fetch_endpoint(endpoint, "https", context)
        except (urllib.error.URLError, ConnectionResetError) as exc:
            if is_tls_certificate_error(exc):
                return [
                    finding(
                        endpoint,
                        "https_tls_certificate_error",
                        "low",
                        f"HTTPS certificate validation failed: {exc.reason}",
                        "Fix certificate chain/hostname mismatch. Use --insecure-tls only for follow-up content triage, not as a control.",
                        details={"error": str(exc.reason)},
                    )
                ]
            if is_connection_reset_error(exc):
                reason = redirect_fetch_error_reason(exc)
                return [
                    finding(
                        endpoint,
                        "https_connection_reset",
                        "low",
                        f"HTTPS endpoint reset the connection: {reason}",
                        "Retest later or confirm whether the service intentionally resets unauthenticated root-path requests.",
                        details={"error": reason},
                    )
                ]
            raise
        if response.status in REDIRECT_STATUSES:
            return redirected_response_findings(endpoint, response, context, "HTTPS redirect")
        return response_content_findings(endpoint, response, context, "HTTPS redirect")


class LlmSensitiveContentChecker:
    check_id = "llm_sensitive_content"

    def check(self, endpoint: dict[str, Any], context: CheckContext) -> list[dict[str, Any]]:
        if not context.llm_enabled:
            return []
        if context.llm_client is None:
            raise ValueError("LLM is enabled but no llm_client is configured")
        endpoint_id = str(endpoint.get("id", ""))
        summary = context.response_summaries.get(endpoint_id)
        if not summary:
            return []
        if summary.get("status") != 200:
            return []

        prompt = build_llm_prompt(endpoint, summary)
        result = context.llm_client(prompt)
        llm_risk_level = normalize_risk(result.get("risk_level"))
        risk_level = llm_risk_level
        return [
            finding(
                endpoint,
                self.check_id,
                risk_level,
                str(result.get("evidence") or result.get("reason") or "LLM assessment completed."),
                str(result.get("recommendation") or "Review the endpoint based on the LLM assessment."),
                details={
                    **summary_without_body(summary),
                    "reason": result.get("reason"),
                    "category": result.get("category"),
                    "confidence": normalize_confidence(result.get("confidence")),
                    "llm_risk_level": result.get("risk_level"),
                    "why_not_higher": result.get("why_not_higher"),
                    "why_not_lower": result.get("why_not_lower"),
                },
            )
        ]


class OpenAICompatibleClient:
    def __init__(
        self,
        api_key: str | None = None,
        base_url: str | None = None,
        model: str | None = None,
        fetcher: HttpFetcher | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        load_dotenv()
        self.api_key = (
            api_key
            or os.getenv("LLM_API_KEY", "").strip()
            or os.getenv("DASHSCOPE_API_KEY", "").strip()
            or os.getenv("QWEN_API_KEY", "").strip()
        )
        self.base_url = (base_url or os.getenv("LLM_BASE_URL", "").strip() or DEFAULT_QWEN_BASE_URL).rstrip("/")
        self.model = model or os.getenv("LLM_MODEL", "").strip() or DEFAULT_QWEN_MODEL
        self.fetcher = fetcher or fetch_url
        self.timeout_seconds = timeout_seconds
        self.ca_bundle = detect_ca_bundle()
        missing = []
        if not self.api_key:
            missing.append("LLM_API_KEY or DASHSCOPE_API_KEY or QWEN_API_KEY")
        if missing:
            raise ValueError(f"Missing required LLM environment variables: {', '.join(missing)}")

    def __call__(self, prompt: str) -> dict[str, Any]:
        body = json.dumps(
            {
                "model": self.model,
                "temperature": 0,
                "messages": [
                    {
                        "role": "system",
                        "content": "You assess exposed HTTP responses for sensitive data leakage. Return only JSON.",
                    },
                    {"role": "user", "content": prompt},
                ],
            },
            separators=(",", ":"),
        ).encode("utf-8")
        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        ssl_context = ssl.create_default_context(cafile=self.ca_bundle)
        response = self.fetcher(request, self.timeout_seconds, ssl_context)
        if response.status < 200 or response.status >= 300:
            raise ValueError(f"LLM request failed with HTTP {response.status}: {response.body[:500]!r}")
        payload = json.loads(response.body.decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        return json.loads(content)


def default_checkers(llm_enabled: bool = False) -> list[Checker]:
    checkers: list[Checker] = [
        NonStandardPortChecker(),
        HttpRedirectChecker(),
        HttpsContentChecker(),
    ]
    if llm_enabled:
        checkers.append(LlmSensitiveContentChecker())
    return checkers


def assess_endpoint(endpoint: dict[str, Any], checkers: Iterable[Checker], context: CheckContext) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for checker in checkers:
        try:
            results.extend(checker.check(endpoint, context))
        except Exception as exc:  # noqa: BLE001 - every endpoint should report checker failures and continue.
            results.append(
                finding(
                    endpoint,
                    f"{checker.check_id}_error",
                    "unknown",
                    f"Checker {checker.check_id} failed: {exc}",
                    "Investigate checker/network failure before deciding endpoint risk.",
                    details={"error_type": type(exc).__name__},
                )
            )
    return results


def iter_json_lines(path: str) -> Iterator[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number} is not valid JSON") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number} is not a JSON object")
            yield value


def write_findings(findings: Iterable[dict[str, Any]], output: TextIO) -> int:
    count = 0
    for item in findings:
        output.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
        output.write("\n")
        count += 1
    return count


WIZ_ENDPOINT_URL_PREFIX = "https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%27"
WIZ_ENDPOINT_URL_SUFFIX = "*2cENDPOINT%29%29"
CSV_FIELDNAMES = [
    "endpoint_name",
    "Wiz链接",
    "端口号",
    "cloudPlatform",
    "CloudAccount",
    "TagEmails",
    "http状态码",
    "http response",
    "LLM意见",
    "risk_level",
]
CSV_FLUSH_INTERVAL = 10


class CsvFindingWriter:
    def __init__(self, output: TextIO, flush_interval: int = CSV_FLUSH_INTERVAL) -> None:
        self.output = output
        self.flush_interval = flush_interval
        self.writer = csv.DictWriter(output, fieldnames=CSV_FIELDNAMES)
        self.writer.writeheader()
        self.count = 0

    def write(self, finding_item: dict[str, Any]) -> None:
        self.writer.writerow(csv_row_for_finding(finding_item))
        self.count += 1
        if self.count % self.flush_interval == 0:
            self.output.flush()

    def flush_remaining(self) -> None:
        if self.count == 0 or self.count % self.flush_interval:
            self.output.flush()


def write_findings_csv(findings: Iterable[dict[str, Any]], output: TextIO) -> int:
    writer = CsvFindingWriter(output)
    for item in findings:
        writer.write(item)
    writer.flush_remaining()
    return writer.count


def wiz_endpoint_url(endpoint_id: Any) -> str:
    endpoint_id_text = str(endpoint_id or "").strip()
    if not endpoint_id_text:
        return ""
    return f"{WIZ_ENDPOINT_URL_PREFIX}{endpoint_id_text}{WIZ_ENDPOINT_URL_SUFFIX}"


def csv_row_for_finding(finding_item: dict[str, Any]) -> dict[str, Any]:
    details = finding_item.get("details")
    if not isinstance(details, dict):
        details = {}
    return {
        "endpoint_name": finding_item.get("endpoint_name") or "",
        "Wiz链接": wiz_endpoint_url(finding_item.get("endpoint_id")),
        "端口号": finding_item.get("port") or "",
        "cloudPlatform": finding_item.get("cloudPlatform") or "",
        "CloudAccount": finding_item.get("cloudAccountName") or "",
        "TagEmails": "; ".join(str(email) for email in finding_item.get("tagEmails") or []),
        "http状态码": details.get("http_status") or details.get("status") or "",
        "http response": csv_http_response_summary(finding_item, details),
        "LLM意见": csv_llm_opinion(finding_item, details),
        "risk_level": finding_item.get("risk_level") or "",
    }


def rds_row_for_finding(finding_item: dict[str, Any]) -> dict[str, Any]:
    csv_row = csv_row_for_finding(finding_item)
    return {
        **finding_item,
        "wiz_link": csv_row["Wiz链接"],
        "http_response": csv_row["http response"],
        "llm_opinion": csv_row["LLM意见"],
    }


def csv_http_response_summary(finding_item: dict[str, Any], details: dict[str, Any]) -> str:
    if finding_item.get("check_id") == "llm_sensitive_content":
        return str(finding_item.get("evidence") or details.get("reason") or "")

    probe_result = details.get("http_probe_result")
    if probe_result:
        return str(probe_result)

    summary_parts = []
    title = details.get("title")
    if title:
        summary_parts.append(str(title))
    content_type = details.get("content_type")
    if content_type:
        summary_parts.append(f"content_type={content_type}")
    status = details.get("status") or details.get("http_status")
    if status and not summary_parts:
        summary_parts.append(f"HTTP {status}")
    return "; ".join(summary_parts) or str(finding_item.get("evidence") or "")


def csv_llm_opinion(finding_item: dict[str, Any], details: dict[str, Any]) -> str:
    if finding_item.get("check_id") != "llm_sensitive_content":
        return str(finding_item.get("evidence") or "")
    parts = [str(value) for value in (details.get("reason"), finding_item.get("recommendation")) if value]
    return " ".join(parts) or str(finding_item.get("evidence") or "")


def load_dotenv(path: str | None = None) -> None:
    dotenv_path = path or os.path.join(os.getcwd(), ".env")
    if not os.path.exists(dotenv_path):
        return

    with open(dotenv_path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("export "):
                stripped = stripped[len("export ") :].strip()
            if "=" not in stripped:
                raise ValueError(f"{dotenv_path}:{line_number} is not a KEY=VALUE assignment")
            key, raw_value = stripped.split("=", 1)
            key = key.strip()
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
                raise ValueError(f"{dotenv_path}:{line_number} has invalid environment variable name")
            if key in os.environ:
                continue
            os.environ[key] = parse_dotenv_value(raw_value.strip())


def parse_dotenv_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def fetch_endpoint(endpoint: dict[str, Any], scheme: str, context: CheckContext) -> HttpResponse:
    host = str(endpoint.get("host") or "").strip()
    port = endpoint.get("port")
    if not host or not isinstance(port, int):
        raise ValueError("Endpoint must include host and integer port")
    return fetch_url_for_absolute_url(f"{scheme}://{host}:{port}/", context)


def summarize_response(response: HttpResponse, context: CheckContext | None = None) -> dict[str, Any]:
    body_text = decode_body(response.body)
    summary: dict[str, Any] = {
        "url": response.url,
        "status": response.status,
        "headers": response.headers,
        "content_type": response.headers.get("Content-Type") or response.headers.get("content-type"),
        "title": extract_title(response.body),
        "body_text": body_text[:DEFAULT_LLM_BODY_LIMIT_CHARS],
    }
    if context is not None:
        javascript_assets, javascript_asset_errors = summarize_javascript_assets(response, body_text, context)
        if javascript_assets:
            summary["javascript_assets"] = javascript_assets
        if javascript_asset_errors:
            summary["javascript_asset_errors"] = javascript_asset_errors
        api_endpoints, api_endpoint_errors = summarize_api_endpoints(response, summary, context)
        if api_endpoints:
            summary["api_endpoints"] = api_endpoints
        if api_endpoint_errors:
            summary["api_endpoint_errors"] = api_endpoint_errors
    return summary


def summary_without_body(summary: dict[str, Any]) -> dict[str, Any]:
    result = {key: value for key, value in summary.items() if key != "body_text"}
    javascript_assets = result.get("javascript_assets")
    if isinstance(javascript_assets, list):
        result["javascript_assets"] = [
            {key: value for key, value in asset.items() if key != "body_text"}
            for asset in javascript_assets
            if isinstance(asset, dict)
        ]
    api_endpoints = result.get("api_endpoints")
    if isinstance(api_endpoints, list):
        result["api_endpoints"] = [
            {key: value for key, value in endpoint.items() if key != "body_text"}
            for endpoint in api_endpoints
            if isinstance(endpoint, dict)
        ]
    return result


def summarize_javascript_assets(
    response: HttpResponse,
    body_text: str,
    context: CheckContext,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if not is_html_response(response, body_text):
        return [], []

    assets = []
    errors = []
    for url in javascript_asset_urls(body_text, response.url):
        try:
            asset_response = fetch_url_for_absolute_url(url, context, body_limit_bytes=DEFAULT_JS_ASSET_LIMIT_BYTES)
        except (urllib.error.URLError, ValueError, http.client.HTTPException, OSError, ConnectionResetError) as exc:
            errors.append({"url": url, "error": redirect_fetch_error_reason(exc)})
            continue

        asset_body_text = decode_body(asset_response.body)
        content_type = asset_response.headers.get("Content-Type") or asset_response.headers.get("content-type")
        api_candidate_urls = safe_api_urls_from_texts([asset_body_text], response.url)
        asset_summary = {
            "url": asset_response.url,
            "status": asset_response.status,
            "content_type": content_type,
            "body_text": asset_body_text[:DEFAULT_LLM_BODY_LIMIT_CHARS],
            "sensitive_snippets": sensitive_snippets(asset_body_text),
        }
        if api_candidate_urls:
            asset_summary["api_candidate_urls"] = api_candidate_urls
        assets.append(
            asset_summary
        )
    return assets, errors


def is_html_response(response: HttpResponse, body_text: str) -> bool:
    content_type = response.headers.get("Content-Type") or response.headers.get("content-type") or ""
    return "html" in content_type.lower() or bool(re.search(r"(?is)<html\b|<script\b", body_text[:2048]))


def javascript_asset_urls(body_text: str, base_url: str) -> list[str]:
    base = urllib.parse.urlparse(base_url)
    urls: list[str] = []
    seen: set[str] = set()
    script_src_pattern = re.compile(
        r"""<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))""",
        flags=re.IGNORECASE,
    )
    for match in script_src_pattern.finditer(body_text):
        src = html.unescape(next(group for group in match.groups() if group is not None)).strip()
        if not src:
            continue
        resolved = urllib.parse.urljoin(base_url, src)
        parsed = urllib.parse.urlparse(resolved)
        if parsed.scheme.lower() not in {"http", "https"}:
            continue
        if (parsed.scheme.lower(), parsed.netloc.lower()) != (base.scheme.lower(), base.netloc.lower()):
            continue
        if not parsed.path.lower().endswith(".js"):
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
        if len(urls) >= MAX_JAVASCRIPT_ASSETS:
            break
    return urls


def summarize_api_endpoints(
    response: HttpResponse,
    summary: dict[str, Any],
    context: CheckContext,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    endpoints = []
    errors = []
    for url in api_endpoint_urls(summary, response.url):
        try:
            api_response = fetch_url_for_absolute_url(url, context, body_limit_bytes=DEFAULT_API_ENDPOINT_LIMIT_BYTES)
        except (urllib.error.URLError, ValueError, http.client.HTTPException, OSError, ConnectionResetError) as exc:
            errors.append({"url": url, "error": redirect_fetch_error_reason(exc)})
            continue

        body_text = decode_body(api_response.body)
        content_type = api_response.headers.get("Content-Type") or api_response.headers.get("content-type")
        endpoints.append(
            {
                "url": api_response.url,
                "status": api_response.status,
                "content_type": content_type,
                "body_text": body_text[:DEFAULT_LLM_BODY_LIMIT_CHARS],
                "sensitive_snippets": sensitive_snippets(body_text),
            }
        )
    return endpoints, errors


def api_endpoint_urls(summary: dict[str, Any], base_url: str) -> list[str]:
    texts = [str(summary.get("body_text") or "")]
    urls = []
    seen = set()
    javascript_assets = summary.get("javascript_assets")
    if isinstance(javascript_assets, list):
        for asset in javascript_assets:
            if isinstance(asset, dict):
                texts.append(str(asset.get("body_text") or ""))
                candidates = asset.get("api_candidate_urls")
                if isinstance(candidates, list):
                    for candidate in candidates:
                        candidate_url = str(candidate or "").strip()
                        if candidate_url and candidate_url not in seen:
                            seen.add(candidate_url)
                            urls.append(candidate_url)
                            if len(urls) >= MAX_API_ENDPOINTS:
                                return urls

    for url in safe_api_urls_from_texts(texts, base_url):
        if url in seen:
            continue
        seen.add(url)
        urls.append(url)
        if len(urls) >= MAX_API_ENDPOINTS:
            return urls
    return urls


def safe_api_urls_from_texts(texts: list[str], base_url: str) -> list[str]:
    base = urllib.parse.urlparse(base_url)
    urls: list[str] = []
    seen: set[str] = set()
    path_pattern = re.compile(
        r"""(?:"|'|`)(/(?:api|swagger|swagger-ui|openapi|graphql|actuator|health)[^"'`\s<>{}]*)""",
        flags=re.IGNORECASE,
    )
    absolute_pattern = re.compile(r"""https?://[^\s"'`<>{}]+""", flags=re.IGNORECASE)
    for text in texts:
        candidates = [match.group(1) for match in path_pattern.finditer(text)]
        candidates.extend(match.group(0) for match in absolute_pattern.finditer(text))
        for candidate in candidates:
            resolved = urllib.parse.urljoin(base_url, html.unescape(candidate).strip())
            parsed = urllib.parse.urlparse(resolved)
            if parsed.scheme.lower() not in {"http", "https"}:
                continue
            if (parsed.scheme.lower(), parsed.netloc.lower()) != (base.scheme.lower(), base.netloc.lower()):
                continue
            if not is_safe_readonly_api_path(parsed.path):
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            urls.append(resolved)
            if len(urls) >= MAX_API_ENDPOINTS:
                return urls
    return urls


def is_safe_readonly_api_path(path: str) -> bool:
    lowered = path.lower().rstrip("/") or "/"
    if re.search(r"(delete|remove|update|create|insert|submit|save|upload|action|execute|run|start|stop|restart)", lowered):
        return False
    if lowered in {"/graphql", "/health", "/api/health", "/actuator/info", "/actuator/health"}:
        return True
    if lowered.startswith(("/api/config", "/api/settings", "/api/status", "/api/version", "/api/info")):
        return True
    if lowered.startswith(("/swagger", "/swagger-ui", "/openapi")):
        return True
    if lowered.endswith(("/openapi.json", "/swagger.json", "/api-docs")):
        return True
    return False


def sensitive_snippets(body_text: str, max_snippets: int = 5, context_chars: int = 120) -> list[str]:
    patterns = [
        r"(?i)(?:enter (?:account|user(?:name)?|password)[^`'\"\n\r]{0,80}use admin for first use)",
        r"(?i)(?:use admin for first use)",
        r"(?i)(?:首次使用请输入\s*admin)",
        r"(?i)(?:admin\s*/\s*admin)",
        r"(?i)['\"]?(api[_-]?key|secret|access[_-]?token|private[_-]?key)['\"]?\s*[:=]\s*['\"]?[a-z0-9_\-/.+=]{8,}",
        r"(?i)\bbackup\.(?:zip|tar|tgz|gz|sql)\b",
        r"(?i)traceback \(most recent call last\)|stack trace",
        r"(?i)index of /",
    ]
    snippets = []
    for pattern in patterns:
        for match in re.finditer(pattern, body_text):
            snippet = " ".join(body_text[max(0, match.start() - context_chars) : match.end() + context_chars].split())
            if snippet and snippet not in snippets:
                snippets.append(snippet)
            if len(snippets) >= max_snippets:
                return snippets
    return snippets


def response_detection_text(summary: dict[str, Any]) -> str:
    parts = [
        str(summary.get("url") or ""),
        str(summary.get("title") or ""),
        str(summary.get("body_text") or ""),
    ]
    javascript_assets = summary.get("javascript_assets")
    if isinstance(javascript_assets, list):
        for asset in javascript_assets:
            if not isinstance(asset, dict):
                continue
            parts.append(str(asset.get("body_text") or ""))
            snippets = asset.get("sensitive_snippets")
            if isinstance(snippets, list):
                parts.extend(str(snippet) for snippet in snippets)
    api_endpoints = summary.get("api_endpoints")
    if isinstance(api_endpoints, list):
        for endpoint in api_endpoints:
            if not isinstance(endpoint, dict):
                continue
            parts.append(str(endpoint.get("body_text") or ""))
            snippets = endpoint.get("sensitive_snippets")
            if isinstance(snippets, list):
                parts.extend(str(snippet) for snippet in snippets)
    return "\n".join(part for part in parts if part)


def detect_ca_bundle() -> str | None:
    default_cafile = ssl.get_default_verify_paths().cafile
    if default_cafile and os.path.exists(default_cafile):
        return None
    try:
        import certifi  # type: ignore[import-not-found]
    except ImportError:
        return None
    certifi_cafile = certifi.where()
    if certifi_cafile and os.path.exists(certifi_cafile):
        return certifi_cafile
    return None


def is_tls_certificate_error(exc: urllib.error.URLError) -> bool:
    reason = getattr(exc, "reason", None)
    return isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(reason)


def decode_body(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def extract_title(body: bytes) -> str | None:
    text = decode_body(body)
    match = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    return html.unescape(" ".join(match.group(1).split()))


def detect_sensitive_signals(body_text: str) -> list[str]:
    lowered = body_text.lower()
    signals = []
    if re.search(r"(?i)(admin console|admin portal|admin login|admin dashboard|管理台|管理端|后台|grafana|jenkins|kibana|swagger|openapi|actuator|/admin(?:/|\b))", body_text):
        signals.append("admin_surface")
    if "index of /" in lowered:
        signals.append("directory_listing")
    if re.search(
        r"(?i)(use admin for first use|首次使用请输入\s*admin|admin\s*/\s*admin)",
        body_text,
    ):
        signals.append("default_admin_credential")
    if re.search(r"(?i)['\"]?(api[_-]?key|secret|access[_-]?token|private[_-]?key)['\"]?\s*[:=]\s*['\"]?[a-z0-9_\-/.+=]{8,}", body_text):
        signals.append("secret_like_value")
    if "traceback (most recent call last)" in lowered or "stack trace" in lowered:
        signals.append("error_stack_trace")
    if re.search(r"(?i)\bbackup\.(zip|tar|tgz|gz|sql)\b", body_text):
        signals.append("backup_artifact")
    return signals


def risk_floor_for_signals(signals: list[str]) -> str:
    floor = "unknown"
    for signal in signals:
        floor = higher_risk(floor, SIGNAL_RISK_LEVELS.get(signal, "unknown"))
    return floor


def higher_risk(left: Any, right: Any) -> str:
    normalized_left = normalize_risk(left)
    normalized_right = normalize_risk(right)
    if RISK_RANK[normalized_right] > RISK_RANK[normalized_left]:
        return normalized_right
    return normalized_left


def normalize_confidence(value: Any) -> int | None:
    if value is None:
        return None
    try:
        confidence = int(float(str(value).strip()))
    except ValueError:
        return None
    return max(0, min(10, confidence))


def https_404_review_reasons(endpoint: dict[str, Any], summary: dict[str, Any]) -> list[str]:
    reasons = []
    if endpoint.get("exposureLevel") == "HIGH":
        reasons.append("exposureLevel=HIGH")
    headers = summary.get("headers")
    if not isinstance(headers, dict):
        headers = {}
    server = str(headers.get("Server") or headers.get("server") or "")
    powered_by = str(headers.get("X-Powered-By") or headers.get("x-powered-by") or "")
    body_text = str(summary.get("body_text") or "")
    if re.search(r"/\d+(?:\.\d+)+", server):
        reasons.append(f"Server={server}")
    if powered_by:
        reasons.append(f"X-Powered-By={powered_by}")
    body_match = re.search(r"(?i)(nginx|apache|tomcat|iis|asp\\.net|spring|django|flask|express)/\\d[\\w.:-]*", body_text)
    if body_match:
        reasons.append(f"body_disclosure={body_match.group(0)}")
    keyword_match = re.search(r"(?i)(internal|stack trace|traceback|exception|debug|bucket|path:|root:)", body_text)
    if keyword_match:
        reasons.append(f"body_keyword={keyword_match.group(0)}")
    return reasons


def looks_like_login_page(body_text: str) -> bool:
    lowered = body_text.lower()
    has_password_field = "type='password'" in lowered or 'type="password"' in lowered
    has_login_word = any(word in lowered for word in ("login", "log in", "sign in", "signin"))
    return has_password_field or has_login_word


def build_llm_prompt(endpoint: dict[str, Any], summary: dict[str, Any]) -> str:
    return (
        "Assess whether this internet-facing application endpoint response directly leaks potentially sensitive "
        "content. The response summary may include HTML, directly referenced same-origin JavaScript assets, "
        "safely probed same-origin API endpoints, local_signals, and local_risk_floor. Treat local_signals and "
        "local_risk_floor as deterministic hints, not a mandatory minimum. You may return a lower risk than "
        "local_risk_floor when the context shows the local signal is not actually sensitive, but explain why in "
        "why_not_higher. If it is only a normal user login page, mark risk_level as low. If it is an "
        "administrative login page, mark risk_level as medium unless "
        "default credentials, secrets, or sensitive data are present. Do NOT classify public OAuth/OIDC/SAML "
        "client-side configuration as a secret or high-risk sensitive data by itself. Examples that are NOT "
        "secrets when shown alone include: clientId, tenantId, authority/issuer URL, redirectUri, "
        "postLogoutRedirectUri, scopes, responseType, and discovery metadata. For front-end JavaScript, OAuth "
        "clientId values are expected to be public for SPA/native/public clients. Do NOT treat variable names, "
        "property names, TypeScript/interface names, validation messages, or error strings as exposed secrets "
        "unless they include an assigned credential value. For example, \"apiKey\" should not be defined, "
        "Ce.apiKey, clientId:<uuid>, or redirectUri:<url> are not sensitive leaks by themselves. Only classify "
        "authentication material as high risk when an actual credential or bearer secret is exposed, such as "
        "clientSecret, private key, password, refresh token, access token, ID token, session cookie, API key "
        "value, or another high-entropy secret that can directly authenticate. Return JSON with keys: "
        "risk_level (low|medium|high|unknown), category, confidence (0-10 integer), reason, evidence, "
        "recommendation, why_not_higher, why_not_lower. "
        "If no sensitive content is present, evidence should be a concise Chinese summary such as "
        "'这是一个登录页面，没有敏感数据'. If sensitive content is present, evidence should include the relevant "
        "HTTP/HTML/JavaScript/API response snippet that appears sensitive, not the entire response.\n\n"
        f"Endpoint JSON:\n{json.dumps(endpoint, ensure_ascii=False, separators=(',', ':'))}\n\n"
        f"HTTP response summary and truncated body (not redacted):\n"
        f"{json.dumps(summary, ensure_ascii=False, separators=(',', ':'))}"
    )


def normalize_risk(value: Any) -> str:
    lowered = str(value or "unknown").lower()
    if lowered in {"low", "medium", "high", "unknown"}:
        return lowered
    return "unknown"


def cloud_account_name(endpoint: dict[str, Any]) -> str | None:
    cloud_account = endpoint.get("cloudAccount")
    if not isinstance(cloud_account, dict):
        return None
    value = cloud_account.get("name")
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def tag_emails(endpoint: dict[str, Any]) -> list[str]:
    value = endpoint.get("tagEmails")
    if not isinstance(value, list):
        return []
    return [str(email) for email in value if str(email).strip()]


def cloud_account_id(endpoint: dict[str, Any]) -> str:
    cloud_account = endpoint.get("cloudAccount")
    if not isinstance(cloud_account, dict):
        return ""
    value = cloud_account.get("id")
    if value is None:
        return ""
    return str(value).strip()


def enrich_endpoint_with_tag_emails(
    endpoint: dict[str, Any],
    config: wiz_auth_poc.WizConfig,
    access_token: str,
    cache: dict[str, list[str]],
) -> dict[str, Any]:
    account_id = cloud_account_id(endpoint)
    if not account_id:
        return endpoint
    if account_id not in cache:
        try:
            cache[account_id] = wiz_auth_poc.fetch_cloud_account_tag_emails(config, access_token, account_id)
        except Exception as exc:  # noqa: BLE001 - tag email enrichment must not stop endpoint scanning.
            print(f"CloudAccount tag email lookup failed for {account_id}: {exc}", file=sys.stderr)
            cache[account_id] = []
    return {**endpoint, "tagEmails": cache[account_id]}


def finding(
    endpoint: dict[str, Any],
    check_id: str,
    risk_level: str,
    evidence: str,
    recommendation: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "endpoint_id": endpoint.get("id"),
        "endpoint_name": endpoint.get("name"),
        "host": endpoint.get("host"),
        "port": endpoint.get("port"),
        "cloudPlatform": endpoint.get("cloudPlatform"),
        "cloudAccountName": cloud_account_name(endpoint),
        "tagEmails": tag_emails(endpoint),
        "exposureLevel": endpoint.get("exposureLevel"),
        "check_id": check_id,
        "risk_level": risk_level,
        "evidence": evidence,
        "recommendation": recommendation,
        "details": details or {},
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assess Wiz application endpoints for attack surface reduction.")
    parser.add_argument(
        "--input",
        help="Input Wiz endpoint JSONL file. If omitted, endpoints are fetched from Wiz before scanning.",
    )
    parser.add_argument(
        "--output",
        help="Output findings JSONL file. If omitted, timestamped JSONL and CSV files are created; use '-' for stdout.",
    )
    parser.add_argument("--limit", type=int, default=0, help="Maximum endpoints to assess; 0 means no limit.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT_SECONDS, help="HTTP timeout in seconds.")
    parser.set_defaults(insecure_tls=True, enable_llm=True)
    parser.add_argument(
        "--insecure-tls",
        dest="insecure_tls",
        action="store_true",
        help="Disable TLS certificate verification for response-content triage. Enabled by default.",
    )
    parser.add_argument(
        "--secure-tls",
        dest="insecure_tls",
        action="store_false",
        help="Verify TLS certificates instead of using insecure content triage.",
    )
    parser.add_argument(
        "--enable-llm",
        dest="enable_llm",
        action="store_true",
        help="Enable OpenAI-compatible LLM content judgment. Enabled by default.",
    )
    parser.add_argument(
        "--disable-llm",
        dest="enable_llm",
        action="store_false",
        help="Disable OpenAI-compatible LLM content judgment.",
    )
    parser.add_argument("--csv-output", help="Output findings CSV file in addition to JSONL output.")
    parser.set_defaults(upload_oss=None)
    parser.add_argument(
        "--upload-oss",
        dest="upload_oss",
        action="store_true",
        help="Upload generated output files to OSS after scanning.",
    )
    parser.add_argument(
        "--no-upload-oss",
        dest="upload_oss",
        action="store_false",
        help="Disable OSS upload even when OSS environment variables are configured.",
    )
    parser.set_defaults(write_rds=None)
    parser.add_argument(
        "--write-rds",
        dest="write_rds",
        action="store_true",
        help="Write findings to RDS PostgreSQL after each JSONL/CSV row.",
    )
    parser.add_argument(
        "--no-rds",
        dest="write_rds",
        action="store_false",
        help="Disable RDS writes even when RDS environment variables are configured.",
    )
    return parser


def default_output_paths(now: datetime.datetime) -> tuple[str, str]:
    prefix = now.strftime("%Y%m%d-%H%M%S-asm-findings")
    return f"{prefix}.jsonl", f"{prefix}.csv"


def resolve_output_paths(args: argparse.Namespace, now: datetime.datetime | None = None) -> tuple[str, str | None]:
    if args.output is None:
        return default_output_paths(now or datetime.datetime.now())
    return args.output, args.csv_output


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    load_dotenv()
    llm_client = OpenAICompatibleClient(timeout_seconds=args.timeout) if args.enable_llm else None
    context = CheckContext(
        timeout_seconds=args.timeout,
        insecure_tls=args.insecure_tls,
        llm_enabled=args.enable_llm,
        llm_client=llm_client,
    )
    checkers = default_checkers(llm_enabled=args.enable_llm)

    def iter_input_endpoints() -> Iterator[dict[str, Any]]:
        if args.input:
            yield from iter_json_lines(args.input)
            return
        load_dotenv()
        config = wiz_auth_poc.load_config()
        access_token = wiz_auth_poc.fetch_access_token(config)
        tag_email_cache: dict[str, list[str]] = {}
        for endpoint in wiz_auth_poc.iter_application_endpoints(config, access_token):
            yield enrich_endpoint_with_tag_emails(endpoint, config, access_token, tag_email_cache)

    count = 0
    output_path, csv_output_path = resolve_output_paths(args)
    started_at = datetime.datetime.now(datetime.UTC).isoformat()
    scan_id = os.path.splitext(os.path.basename(output_path))[0] if output_path != "-" else rds_writer.default_scan_id()
    output = sys.stdout if output_path == "-" else open(output_path, "w", encoding="utf-8")
    csv_output = open(csv_output_path, "w", encoding="utf-8", newline="") if csv_output_path else None
    csv_writer = CsvFindingWriter(csv_output) if csv_output is not None else None
    db_writer = (
        rds_writer.open_writer(scan_id, started_at, None if output_path == "-" else output_path, LOW_RISK_SUBSCRIPTIONS)
        if should_write_to_rds(args.write_rds)
        else None
    )
    try:
        for index, endpoint in enumerate(iter_input_endpoints(), start=1):
            if args.limit and index > args.limit:
                break
            endpoint_findings = assess_endpoint(endpoint, checkers, context)
            for item in endpoint_findings:
                output.write(json.dumps(item, ensure_ascii=False, separators=(",", ":")))
                output.write("\n")
                count += 1
                if csv_writer is not None:
                    csv_writer.write(item)
                if db_writer is not None:
                    db_writer.write(rds_row_for_finding(item))
            endpoint_name = endpoint.get("name") or endpoint.get("host") or endpoint.get("id") or "<unknown>"
            print(
                f"Processed endpoint {index}: {endpoint_name} ({len(endpoint_findings)} findings, {count} findings total).",
                file=sys.stderr,
            )
        if csv_writer is not None:
            csv_writer.flush_remaining()
        if db_writer is not None:
            db_writer.finalize()
    finally:
        if output is not sys.stdout:
            output.close()
        if csv_output is not None:
            csv_output.close()
        if db_writer is not None:
            db_writer.close()
    if should_upload_to_oss(args.upload_oss):
        upload_outputs_to_oss(output_path, csv_output_path)
    print(f"Wrote {count} findings.", file=sys.stderr)
    return 0


def should_upload_to_oss(upload_oss_arg: bool | None) -> bool:
    if upload_oss_arg is not None:
        return upload_oss_arg
    load_dotenv()
    return bool(os.getenv("OSS_ENDPOINT", "").strip() and os.getenv("OSS_BUCKET", "").strip())


def should_write_to_rds(write_rds_arg: bool | None) -> bool:
    if write_rds_arg is not None:
        return write_rds_arg
    load_dotenv()
    return rds_writer.rds_configured()


def upload_outputs_to_oss(output_path: str, csv_output_path: str | None) -> None:
    paths = [path for path in (output_path, csv_output_path) if path and path != "-"]
    if not paths:
        return
    missing_paths = [path for path in paths if not os.path.exists(path)]
    if missing_paths:
        raise FileNotFoundError(f"Cannot upload missing output file(s): {', '.join(missing_paths)}")
    upload_to_oss.load_dotenv()
    endpoint = os.getenv("OSS_ENDPOINT", "").strip()
    bucket = os.getenv("OSS_BUCKET", "").strip()
    role_name = os.getenv("OSS_ROLE_NAME", "").strip() or None
    prefix = os.getenv("OSS_PREFIX", upload_to_oss.DEFAULT_OSS_PREFIX)
    missing = []
    if not endpoint:
        missing.append("OSS_ENDPOINT")
    if not bucket:
        missing.append("OSS_BUCKET")
    if missing:
        raise ValueError(f"Missing required OSS environment variables: {', '.join(missing)}")
    credentials = upload_to_oss.fetch_role_credentials(role_name)
    for path in paths:
        print(f"Uploading {path} to OSS.", file=sys.stderr)
        object_key = upload_to_oss.upload_file(path, endpoint, bucket, credentials, prefix)
        print(f"Uploaded {path} to oss://{bucket}/{object_key}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
