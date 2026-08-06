#!/usr/bin/env python3
"""Minimal Wiz OAuth + GraphQL connectivity proof of concept."""

from __future__ import annotations

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable, Iterator, TextIO


DEFAULT_API_URL = "https://api.eu7.app.wiz.io/graphql"
DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_AUDIENCE = "wiz-api"
DEFAULT_TIMEOUT_SECONDS = 30
DEFAULT_PAGE_SIZE = 100
DEFAULT_PROJECT_ID = "242f91dd-f1c6-573f-b8b4-678df5581477"
APPLICATION_ENDPOINTS_QUERY = """
query ListApplicationEndpoints($first: Int!, $after: String, $filterBy: ApplicationEndpointFilters) {
  applicationEndpoints(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      externalId
      name
      host
      port
      protocols
      cloudPlatform
      firstSeen
      updatedAt
      deletedAt
      portStatus
      exposureLevel
      scanSources
      isThirdPartyApplication
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
""".strip()


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


class WizRequestError(Exception):
    """Raised when Wiz authentication or GraphQL verification fails."""


@dataclass(frozen=True)
class WizConfig:
    client_id: str
    client_secret: str
    api_url: str
    auth_url: str
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS
    audience: str = DEFAULT_AUDIENCE
    ca_bundle: str | None = None
    project_id: str = DEFAULT_PROJECT_ID


def load_config() -> WizConfig:
    client_id = os.getenv("WIZ_CLIENT_ID", "").strip()
    client_secret = os.getenv("WIZ_CLIENT_SECRET", "").strip()
    api_url = os.getenv("WIZ_API_URL", DEFAULT_API_URL).strip()
    auth_url = os.getenv("WIZ_AUTH_URL", DEFAULT_AUTH_URL).strip()
    audience = os.getenv("WIZ_API_AUDIENCE", DEFAULT_AUDIENCE).strip()
    timeout_raw = os.getenv("WIZ_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)).strip()
    ca_bundle = os.getenv("WIZ_CA_BUNDLE", "").strip() or _detect_ca_bundle()
    project_id = os.getenv("WIZ_PROJECT_ID", DEFAULT_PROJECT_ID).strip()

    missing = []
    if not client_id:
        missing.append("WIZ_CLIENT_ID")
    if not client_secret:
        missing.append("WIZ_CLIENT_SECRET")
    if not api_url:
        missing.append("WIZ_API_URL")
    if not auth_url:
        missing.append("WIZ_AUTH_URL")
    if not audience:
        missing.append("WIZ_API_AUDIENCE")
    if not project_id:
        missing.append("WIZ_PROJECT_ID")
    if missing:
        raise ConfigError(f"Missing required environment variables: {', '.join(missing)}")

    try:
        timeout_seconds = int(timeout_raw)
    except ValueError as exc:
        raise ConfigError("WIZ_TIMEOUT_SECONDS must be an integer") from exc
    if timeout_seconds <= 0:
        raise ConfigError("WIZ_TIMEOUT_SECONDS must be greater than zero")

    return WizConfig(
        client_id=client_id,
        client_secret=client_secret,
        api_url=api_url,
        auth_url=auth_url,
        timeout_seconds=timeout_seconds,
        audience=audience,
        ca_bundle=ca_bundle,
        project_id=project_id,
    )


def redact_secret(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


def fetch_access_token(config: WizConfig) -> str:
    form = urllib.parse.urlencode(
        {
            "grant_type": "client_credentials",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "audience": config.audience,
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        config.auth_url,
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )

    payload = _open_json(request, config.timeout_seconds, "OAuth token request", config.ca_bundle)
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise WizRequestError("OAuth token response did not include a non-empty access_token")
    return token


def verify_graphql_connectivity(config: WizConfig, access_token: str) -> dict[str, Any]:
    request_body = json.dumps(
        {"query": "query WizConnectivityCheck { __typename }"},
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        config.api_url,
        data=request_body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    payload = _open_json(request, config.timeout_seconds, "GraphQL connectivity check", config.ca_bundle)
    errors = payload.get("errors")
    if errors:
        raise WizRequestError(f"GraphQL returned errors: {json.dumps(errors, ensure_ascii=False)}")
    data = payload.get("data")
    if not isinstance(data, dict) or data.get("__typename") != "Query":
        raise WizRequestError(f"Unexpected GraphQL response: {json.dumps(payload, ensure_ascii=False)}")
    return data


def execute_graphql(
    config: WizConfig,
    access_token: str,
    query: str,
    variables: dict[str, Any] | None = None,
    context: str = "GraphQL request",
) -> dict[str, Any]:
    body: dict[str, Any] = {"query": query}
    if variables is not None:
        body["variables"] = variables
    request_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        config.api_url,
        data=request_body,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )

    payload = _open_json(request, config.timeout_seconds, context, config.ca_bundle)
    errors = payload.get("errors")
    if errors:
        raise WizRequestError(f"GraphQL returned errors: {_format_graphql_errors(errors)}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise WizRequestError(f"{context} returned GraphQL data that is not an object")
    return data


def iter_application_endpoints(
    config: WizConfig,
    access_token: str,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> Iterator[dict[str, Any]]:
    if page_size <= 0:
        raise ConfigError("page_size must be greater than zero")

    after: str | None = None
    while True:
        data = execute_graphql(
            config,
            access_token,
            APPLICATION_ENDPOINTS_QUERY,
            {
                "first": page_size,
                "after": after,
                "filterBy": {"project": [config.project_id]},
            },
            "Application endpoints query",
        )
        connection = data.get("applicationEndpoints")
        if not isinstance(connection, dict):
            raise WizRequestError("Application endpoints response did not include applicationEndpoints")
        nodes = connection.get("nodes")
        if not isinstance(nodes, list):
            raise WizRequestError("Application endpoints response did not include a nodes list")
        for node in nodes:
            if not isinstance(node, dict):
                raise WizRequestError("Application endpoints response included a non-object node")
            if node.get("exposureLevel") == "HIGH":
                yield node

        page_info = connection.get("pageInfo")
        if not isinstance(page_info, dict):
            raise WizRequestError("Application endpoints response did not include pageInfo")
        has_next_page = page_info.get("hasNextPage")
        end_cursor = page_info.get("endCursor")
        if not has_next_page:
            break
        if not isinstance(end_cursor, str) or not end_cursor:
            raise WizRequestError("Application endpoints response had hasNextPage=true without endCursor")
        after = end_cursor


def write_json_lines(endpoints: Iterable[dict[str, Any]], output: TextIO) -> int:
    count = 0
    for endpoint in endpoints:
        output.write(json.dumps(endpoint, ensure_ascii=False, separators=(",", ":")))
        output.write("\n")
        count += 1
    return count


def _open_json(
    request: urllib.request.Request,
    timeout_seconds: int,
    context: str,
    ca_bundle: str | None,
) -> dict[str, Any]:
    ssl_context = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else None
    try:
        if ssl_context is None:
            response_context = urllib.request.urlopen(request, timeout=timeout_seconds)
        else:
            response_context = urllib.request.urlopen(request, timeout=timeout_seconds, context=ssl_context)
        with response_context as response:
            status = getattr(response, "status", 200)
            body = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise WizRequestError(f"{context} failed with HTTP {exc.code}: {_safe_error_body(body)}") from exc
    except urllib.error.URLError as exc:
        raise WizRequestError(f"{context} failed: {exc.reason}") from exc

    if status < 200 or status >= 300:
        raise WizRequestError(f"{context} failed with HTTP {status}: {_safe_error_body(body)}")

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        raise WizRequestError(f"{context} returned non-JSON response: {_safe_error_body(body)}") from exc
    if not isinstance(payload, dict):
        raise WizRequestError(f"{context} returned JSON that is not an object")
    return payload


def _format_graphql_errors(errors: Any) -> str:
    if isinstance(errors, list):
        messages = []
        for error in errors:
            if isinstance(error, dict) and isinstance(error.get("message"), str):
                messages.append(error["message"])
        if messages:
            return _safe_error_body("; ".join(messages))
    return _safe_error_body(json.dumps(errors, ensure_ascii=False))


def _detect_ca_bundle() -> str | None:
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


def _safe_error_body(body: str) -> str:
    compact = " ".join(body.split())
    if len(compact) > 500:
        return f"{compact[:500]}..."
    return compact


def main() -> int:
    try:
        config = load_config()
        list_application_endpoints = len(sys.argv) > 1 and sys.argv[1] == "list-application-endpoints"
        status_output = sys.stderr if list_application_endpoints else sys.stdout
        print(f"Using Wiz API endpoint: {config.api_url}", file=status_output)
        print(f"Using Wiz auth endpoint: {config.auth_url}", file=status_output)
        print(f"Using Wiz client id: {redact_secret(config.client_id)}", file=status_output)
        access_token = fetch_access_token(config)
        print("OAuth authentication succeeded; access token received and not printed.", file=status_output)
        if list_application_endpoints:
            count = write_json_lines(iter_application_endpoints(config, access_token), sys.stdout)
            print(f"Exported {count} application endpoints.", file=sys.stderr)
            return 0
        data = verify_graphql_connectivity(config, access_token)
        print(f"GraphQL connectivity succeeded: __typename={data['__typename']}")
    except (ConfigError, WizRequestError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
