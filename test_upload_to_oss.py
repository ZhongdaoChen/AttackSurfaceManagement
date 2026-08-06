import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import urllib.error

import upload_to_oss


class UploadToOssTests(unittest.TestCase):
    def test_load_dotenv_does_not_override_existing_environment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            dotenv_path = Path(temp_dir) / ".env"
            dotenv_path.write_text(
                "OSS_BUCKET=from-file\nOSS_ENDPOINT=https://oss-cn-hangzhou.aliyuncs.com\n",
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"OSS_BUCKET": "existing"}, clear=True):
                upload_to_oss.load_dotenv(str(dotenv_path))

                self.assertEqual(os.environ["OSS_BUCKET"], "existing")
                self.assertEqual(os.environ["OSS_ENDPOINT"], "https://oss-cn-hangzhou.aliyuncs.com")

    def test_discover_role_name_reads_metadata_role_list(self):
        role_name = upload_to_oss.discover_role_name(lambda url: b"asm-oss-role\n")

        self.assertEqual(role_name, "asm-oss-role")

    def test_fetch_role_credentials_reads_ecs_metadata_json(self):
        calls = []

        def fetcher(url):
            calls.append(url)
            return json.dumps(
                {
                    "AccessKeyId": "STS.access",
                    "AccessKeySecret": "secret",
                    "SecurityToken": "token",
                }
            ).encode("utf-8")

        credentials = upload_to_oss.fetch_role_credentials("asm-oss-role", fetcher)

        self.assertEqual(credentials["AccessKeyId"], "STS.access")
        self.assertEqual(credentials["AccessKeySecret"], "secret")
        self.assertEqual(credentials["SecurityToken"], "token")
        self.assertEqual(
            calls,
            ["http://100.100.100.200/latest/meta-data/ram/security-credentials/asm-oss-role"],
        )

    def test_fetch_role_credentials_discovers_role_when_not_provided(self):
        def fetcher(url):
            if url.endswith("/security-credentials/"):
                return b"asm-oss-role\n"
            return json.dumps(
                {
                    "AccessKeyId": "STS.access",
                    "AccessKeySecret": "secret",
                    "SecurityToken": "token",
                }
            ).encode("utf-8")

        credentials = upload_to_oss.fetch_role_credentials(None, fetcher)

        self.assertEqual(credentials["AccessKeyId"], "STS.access")

    def test_object_key_for_file_uses_prefix_and_basename(self):
        key = upload_to_oss.object_key_for_file("/tmp/20260806-140118-asm-findings.csv", "asm-findings/")

        self.assertEqual(key, "asm-findings/20260806-140118-asm-findings.csv")

    def test_oss_region_from_internal_endpoint_removes_internal_suffix(self):
        self.assertEqual(
            upload_to_oss.oss_region_from_endpoint("oss-cn-shanghai-internal.aliyuncs.com"),
            "cn-shanghai",
        )

    def test_upload_file_puts_object_with_security_token(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "result.csv"
            file_path.write_bytes(b"csv-content")
            captured = {}

            class FakeResponse:
                status = 200

                def read(self):
                    return b""

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc, traceback):
                    return False

            def opener(request):
                captured["url"] = request.full_url
                captured["method"] = request.get_method()
                captured["data"] = request.data
                captured["headers"] = dict(request.header_items())
                return FakeResponse()

            key = upload_to_oss.upload_file(
                file_path,
                endpoint="https://oss-cn-hangzhou.aliyuncs.com",
                bucket="asm-bucket",
                credentials={
                    "AccessKeyId": "STS.access",
                    "AccessKeySecret": "secret",
                    "SecurityToken": "token",
                },
                prefix="asm-findings/",
                opener=opener,
            )

        self.assertEqual(key, "asm-findings/result.csv")
        self.assertEqual(captured["url"], "https://asm-bucket.oss-cn-hangzhou.aliyuncs.com/asm-findings/result.csv")
        self.assertEqual(captured["method"], "PUT")
        self.assertEqual(captured["data"], b"csv-content")
        self.assertEqual(captured["headers"]["Content-type"], "application/octet-stream")
        self.assertEqual(captured["headers"]["X-oss-security-token"], "token")
        self.assertEqual(captured["headers"]["X-oss-content-sha256"], "UNSIGNED-PAYLOAD")
        self.assertIn("OSS4-HMAC-SHA256", captured["headers"]["Authorization"])
        self.assertIn("AdditionalHeaders=content-type;host;x-oss-content-sha256;x-oss-date;x-oss-security-token", captured["headers"]["Authorization"])
        self.assertNotIn("SignedHeaders=", captured["headers"]["Authorization"])

    def test_signed_put_request_uses_bucket_in_canonical_uri(self):
        request = upload_to_oss.signed_put_request(
            endpoint="https://oss-cn-shanghai-internal.aliyuncs.com",
            bucket="appsec-asm",
            object_key="asm-findings/result.csv",
            body=b"csv-content",
            credentials={
                "AccessKeyId": "STS.access",
                "AccessKeySecret": "secret",
                "SecurityToken": "token",
            },
        )

        self.assertEqual(
            request.full_url,
            "https://appsec-asm.oss-cn-shanghai-internal.aliyuncs.com/asm-findings/result.csv",
        )
        self.assertIn("cn-shanghai/oss/aliyun_v4_request", request.headers["Authorization"])
        self.assertIn("AdditionalHeaders=content-type;host;x-oss-content-sha256;x-oss-date;x-oss-security-token", request.headers["Authorization"])

    def test_upload_file_reports_oss_error_body(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "result.csv"
            file_path.write_bytes(b"csv-content")

            def opener(request):
                raise urllib.error.HTTPError(
                    request.full_url,
                    400,
                    "Bad Request",
                    {},
                    fp=FakeErrorBody(b"<Error><Code>InvalidArgument</Code></Error>"),
                )

            with self.assertRaisesRegex(RuntimeError, "InvalidArgument"):
                upload_to_oss.upload_file(
                    file_path,
                    endpoint="https://oss-cn-hangzhou.aliyuncs.com",
                    bucket="asm-bucket",
                    credentials={
                        "AccessKeyId": "STS.access",
                        "AccessKeySecret": "secret",
                        "SecurityToken": "token",
                    },
                    opener=opener,
                )


class FakeErrorBody:
    def __init__(self, body):
        self.body = body

    def read(self, size=-1):
        return self.body

    def close(self):
        pass


if __name__ == "__main__":
    unittest.main()
