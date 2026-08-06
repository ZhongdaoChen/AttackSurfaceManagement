#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Callable
import urllib.parse
import urllib.error
import urllib.request


METADATA_BASE_URL = "http://100.100.100.200/latest/meta-data/ram/security-credentials"
DEFAULT_OSS_PREFIX = "asm-findings/"
DEFAULT_TIMEOUT_SECONDS = 10


def load_dotenv(path: str | None = None) -> None:
    dotenv_path = path or ".env"
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
            if key in os.environ:
                continue
            os.environ[key] = parse_dotenv_value(raw_value.strip())


def parse_dotenv_value(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def metadata_get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=DEFAULT_TIMEOUT_SECONDS) as response:
        return response.read()


def discover_role_name(fetcher: Callable[[str], bytes] = metadata_get) -> str:
    body = fetcher(f"{METADATA_BASE_URL}/").decode("utf-8")
    role_names = [line.strip() for line in body.splitlines() if line.strip()]
    if not role_names:
        raise ValueError("No ECS RAM role is attached to this instance")
    return role_names[0]


def fetch_role_credentials(
    role_name: str | None = None,
    fetcher: Callable[[str], bytes] | None = None,
) -> dict[str, str]:
    metadata_fetcher = fetcher or metadata_get
    resolved_role_name = role_name or discover_role_name(metadata_fetcher)
    body = metadata_fetcher(f"{METADATA_BASE_URL}/{urllib.parse.quote(resolved_role_name)}")
    payload = json.loads(body.decode("utf-8"))
    required = ("AccessKeyId", "AccessKeySecret", "SecurityToken")
    missing = [key for key in required if not payload.get(key)]
    if missing:
        raise ValueError(f"ECS role credentials missing fields: {', '.join(missing)}")
    return {key: str(payload[key]) for key in required}


def object_key_for_file(path: str | Path, prefix: str) -> str:
    normalized_prefix = prefix.strip("/")
    basename = Path(path).name
    if not normalized_prefix:
        return basename
    return f"{normalized_prefix}/{basename}"


def upload_file(
    path: str | Path,
    endpoint: str,
    bucket: str,
    credentials: dict[str, str],
    prefix: str = DEFAULT_OSS_PREFIX,
    opener: Callable[[urllib.request.Request], Any] | None = None,
) -> str:
    file_path = Path(path)
    body = file_path.read_bytes()
    object_key = object_key_for_file(file_path, prefix)
    request = signed_put_request(
        endpoint=endpoint,
        bucket=bucket,
        object_key=object_key,
        body=body,
        credentials=credentials,
    )
    open_request = opener or (lambda req: urllib.request.urlopen(req, timeout=DEFAULT_TIMEOUT_SECONDS))
    try:
        with open_request(request) as response:
            status = getattr(response, "status", 200)
            if status < 200 or status >= 300:
                raise RuntimeError(f"OSS upload failed for {file_path}: HTTP {status}: {response.read()[:500]!r}")
    except urllib.error.HTTPError as exc:
        body_preview = exc.read()[:1000].decode("utf-8", errors="replace")
        raise RuntimeError(f"OSS upload failed for {file_path}: HTTP {exc.code}: {body_preview}") from exc
    return object_key


def signed_put_request(
    endpoint: str,
    bucket: str,
    object_key: str,
    body: bytes,
    credentials: dict[str, str],
) -> urllib.request.Request:
    endpoint_parts = urllib.parse.urlparse(endpoint)
    if endpoint_parts.scheme not in {"http", "https"} or not endpoint_parts.netloc:
        raise ValueError("OSS_ENDPOINT must include scheme and host, for example https://oss-cn-hangzhou.aliyuncs.com")
    host = f"{bucket}.{endpoint_parts.netloc}"
    encoded_key = "/".join(urllib.parse.quote(part, safe="") for part in object_key.split("/"))
    url = urllib.parse.urlunparse((endpoint_parts.scheme, host, f"/{encoded_key}", "", "", ""))
    now = datetime.datetime.now(datetime.UTC)
    date_time = now.strftime("%Y%m%dT%H%M%SZ")
    date = now.strftime("%Y%m%d")
    region = oss_region_from_endpoint(endpoint_parts.netloc)
    payload_hash = hashlib.sha256(body).hexdigest()
    security_token = credentials["SecurityToken"]
    headers = {
        "host": host,
        "x-oss-content-sha256": payload_hash,
        "x-oss-date": date_time,
        "x-oss-security-token": security_token,
    }
    authorization = oss_v4_authorization(
        method="PUT",
        canonical_uri=f"/{encoded_key}",
        headers=headers,
        payload_hash=payload_hash,
        access_key_id=credentials["AccessKeyId"],
        access_key_secret=credentials["AccessKeySecret"],
        region=region,
        date=date,
        date_time=date_time,
    )
    request_headers = {
        "Authorization": authorization,
        "Content-Length": str(len(body)),
        "x-oss-content-sha256": payload_hash,
        "x-oss-date": date_time,
        "x-oss-security-token": security_token,
    }
    return urllib.request.Request(url, data=body, headers=request_headers, method="PUT")


def oss_region_from_endpoint(host: str) -> str:
    first_label = host.split(".", 1)[0]
    if first_label.startswith("oss-"):
        region = first_label[len("oss-") :]
        if region.endswith("-internal"):
            return region[: -len("-internal")]
        return region
    return first_label


def oss_v4_authorization(
    method: str,
    canonical_uri: str,
    headers: dict[str, str],
    payload_hash: str,
    access_key_id: str,
    access_key_secret: str,
    region: str,
    date: str,
    date_time: str,
) -> str:
    signed_header_names = sorted(headers)
    canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in signed_header_names)
    signed_headers = ";".join(signed_header_names)
    canonical_request = "\n".join(
        [
            method,
            canonical_uri,
            "",
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    scope = f"{date}/{region}/oss/aliyun_v4_request"
    string_to_sign = "\n".join(
        [
            "OSS4-HMAC-SHA256",
            date_time,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = oss_v4_signing_key(access_key_secret, date, region)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return (
        "OSS4-HMAC-SHA256 "
        f"Credential={access_key_id}/{scope},"
        f"AdditionalHeaders={signed_headers},"
        f"Signature={signature}"
    )


def oss_v4_signing_key(access_key_secret: str, date: str, region: str) -> bytes:
    date_key = hmac.new(f"aliyun_v4{access_key_secret}".encode("utf-8"), date.encode("utf-8"), hashlib.sha256).digest()
    region_key = hmac.new(date_key, region.encode("utf-8"), hashlib.sha256).digest()
    service_key = hmac.new(region_key, b"oss", hashlib.sha256).digest()
    return hmac.new(service_key, b"aliyun_v4_request", hashlib.sha256).digest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Upload files to OSS using the ECS instance RAM role.")
    parser.add_argument("files", nargs="+", help="Local files to upload")
    parser.add_argument("--prefix", default=None, help=f"OSS object key prefix. Defaults to {DEFAULT_OSS_PREFIX}")
    args = parser.parse_args(argv)

    load_dotenv()
    endpoint = os.getenv("OSS_ENDPOINT", "").strip()
    bucket = os.getenv("OSS_BUCKET", "").strip()
    role_name = os.getenv("OSS_ROLE_NAME", "").strip() or None
    prefix = args.prefix if args.prefix is not None else os.getenv("OSS_PREFIX", DEFAULT_OSS_PREFIX)
    missing = []
    if not endpoint:
        missing.append("OSS_ENDPOINT")
    if not bucket:
        missing.append("OSS_BUCKET")
    if missing:
        raise ValueError(f"Missing required OSS environment variables: {', '.join(missing)}")

    credentials = fetch_role_credentials(role_name)
    for file_path in args.files:
        object_key = upload_file(file_path, endpoint, bucket, credentials, prefix)
        print(f"Uploaded {file_path} to oss://{bucket}/{object_key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
