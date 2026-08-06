import json
import os
import ssl
import sys
import tempfile
import types
import unittest
from io import StringIO
from unittest.mock import patch

import wiz_auth_poc


class FakeHTTPResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body.encode("utf-8")

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class WizAuthPoCTests(unittest.TestCase):
    def test_load_config_reports_all_missing_required_env_vars(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                wiz_auth_poc.ConfigError,
                "WIZ_CLIENT_ID, WIZ_CLIENT_SECRET",
            ):
                wiz_auth_poc.load_config()

    def test_load_config_uses_wiz_defaults_for_known_tenant(self):
        with patch.dict(
            os.environ,
            {
                "WIZ_CLIENT_ID": "client-id",
                "WIZ_CLIENT_SECRET": "client-secret",
            },
            clear=True,
        ):
            config = wiz_auth_poc.load_config()

        self.assertEqual(config.client_id, "client-id")
        self.assertEqual(config.client_secret, "client-secret")
        self.assertEqual(config.api_url, "https://api.eu7.app.wiz.io/graphql")
        self.assertEqual(config.auth_url, "https://auth.app.wiz.io/oauth/token")
        self.assertEqual(config.project_id, "242f91dd-f1c6-573f-b8b4-678df5581477")

    def test_load_config_allows_project_id_override(self):
        with patch.dict(
            os.environ,
            {
                "WIZ_CLIENT_ID": "client-id",
                "WIZ_CLIENT_SECRET": "client-secret",
                "WIZ_PROJECT_ID": "custom-project-id",
            },
            clear=True,
        ):
            config = wiz_auth_poc.load_config()

        self.assertEqual(config.project_id, "custom-project-id")

    def test_fetch_access_token_sends_client_credentials_request(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["body"] = request.data.decode("utf-8")
            captured["timeout"] = timeout
            return FakeHTTPResponse(200, json.dumps({"access_token": "token-123"}))

        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
            timeout_seconds=12,
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            token = wiz_auth_poc.fetch_access_token(config)

        self.assertEqual(token, "token-123")
        self.assertEqual(captured["url"], "https://auth.app.wiz.io/oauth/token")
        self.assertEqual(captured["timeout"], 12)
        self.assertIn("application/x-www-form-urlencoded", captured["headers"]["Content-type"])
        self.assertIn("grant_type=client_credentials", captured["body"])
        self.assertIn("client_id=client-id", captured["body"])
        self.assertIn("client_secret=client-secret", captured["body"])
        self.assertIn("audience=wiz-api", captured["body"])

    def test_fetch_access_token_uses_configured_ca_bundle(self):
        captured = {}
        fake_context = object()

        def fake_urlopen(request, timeout, context):
            captured["context"] = context
            return FakeHTTPResponse(200, json.dumps({"access_token": "token-123"}))

        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
            timeout_seconds=12,
            ca_bundle="/tmp/ca.pem",
        )

        with (
            patch("ssl.create_default_context", return_value=fake_context) as create_context,
            patch("urllib.request.urlopen", fake_urlopen),
        ):
            token = wiz_auth_poc.fetch_access_token(config)

        self.assertEqual(token, "token-123")
        create_context.assert_called_once_with(cafile="/tmp/ca.pem")
        self.assertIs(captured["context"], fake_context)

    def test_load_config_uses_certifi_when_python_has_no_default_cafile(self):
        with tempfile.NamedTemporaryFile() as ca_file:
            fake_certifi = types.SimpleNamespace(where=lambda: ca_file.name)
            fake_paths = types.SimpleNamespace(cafile=None)

            with (
                patch.dict(
                    os.environ,
                    {
                        "WIZ_CLIENT_ID": "client-id",
                        "WIZ_CLIENT_SECRET": "client-secret",
                    },
                    clear=True,
                ),
                patch.object(ssl, "get_default_verify_paths", return_value=fake_paths),
                patch.dict(sys.modules, {"certifi": fake_certifi}),
            ):
                config = wiz_auth_poc.load_config()

        self.assertEqual(config.ca_bundle, ca_file.name)

    def test_verify_graphql_connectivity_sends_bearer_token_query(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeHTTPResponse(200, json.dumps({"data": {"__typename": "Query"}}))

        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
            timeout_seconds=8,
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            result = wiz_auth_poc.verify_graphql_connectivity(config, "token-123")

        self.assertEqual(result, {"__typename": "Query"})
        self.assertEqual(captured["url"], "https://api.eu7.app.wiz.io/graphql")
        self.assertEqual(captured["timeout"], 8)
        self.assertEqual(captured["headers"]["Authorization"], "Bearer token-123")
        self.assertEqual(captured["headers"]["Content-type"], "application/json")
        self.assertEqual(captured["body"], {"query": "query WizConnectivityCheck { __typename }"})

    def test_execute_graphql_sends_query_variables_and_returns_data(self):
        captured = {}

        def fake_urlopen(request, timeout):
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeHTTPResponse(200, json.dumps({"data": {"ok": True}}))

        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
            timeout_seconds=8,
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            data = wiz_auth_poc.execute_graphql(
                config,
                "token-123",
                "query Example($first: Int!) { example(first: $first) { id } }",
                {"first": 100},
                "Example query",
            )

        self.assertEqual(data, {"ok": True})
        self.assertEqual(captured["url"], "https://api.eu7.app.wiz.io/graphql")
        self.assertEqual(captured["timeout"], 8)
        self.assertTrue(captured["headers"]["Authorization"].startswith("Bearer "))
        self.assertEqual(captured["headers"]["Content-type"], "application/json")
        self.assertEqual(
            captured["body"],
            {
                "query": "query Example($first: Int!) { example(first: $first) { id } }",
                "variables": {"first": 100},
            },
        )

    def test_execute_graphql_raises_on_graphql_errors(self):
        def fake_urlopen(request, timeout):
            return FakeHTTPResponse(
                200,
                json.dumps(
                    {
                        "data": None,
                        "errors": [
                            {
                                "message": "access denied",
                                "extensions": {"code": "UNAUTHORIZED"},
                            }
                        ],
                    }
                ),
            )

        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
        )

        with patch("urllib.request.urlopen", fake_urlopen):
            with self.assertRaisesRegex(wiz_auth_poc.WizRequestError, "GraphQL returned errors"):
                wiz_auth_poc.execute_graphql(config, "token-123", "query { forbidden }")

    def test_list_application_endpoints_paginates_until_done(self):
        calls = []

        def fake_execute_graphql(config, access_token, query, variables, context):
            calls.append({"query": query, "variables": variables, "context": context})
            if variables["after"] is None:
                return {
                    "applicationEndpoints": {
                        "nodes": [
                            {
                                "id": "endpoint-1",
                                "name": "first",
                                "host": "one.example.com",
                                "port": 443,
                                "exposureLevel": "HIGH",
                            },
                            {
                                "id": "endpoint-medium",
                                "name": "medium",
                                "host": "medium.example.com",
                                "port": 443,
                                "exposureLevel": "MEDIUM",
                            },
                        ],
                        "pageInfo": {"hasNextPage": True, "endCursor": "cursor-1"},
                    }
                }
            return {
                "applicationEndpoints": {
                    "nodes": [
                        {
                            "id": "endpoint-2",
                            "name": "second",
                            "host": "two.example.com",
                            "port": 8443,
                            "exposureLevel": "HIGH",
                        },
                        {
                            "id": "endpoint-low",
                            "name": "low",
                            "host": "low.example.com",
                            "port": 443,
                            "exposureLevel": "LOW",
                        },
                    ],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }

        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
        )

        with patch.object(wiz_auth_poc, "execute_graphql", fake_execute_graphql):
            endpoints = list(wiz_auth_poc.iter_application_endpoints(config, "token-123", page_size=1))

        self.assertEqual(
            endpoints,
            [
                {
                    "id": "endpoint-1",
                    "name": "first",
                    "host": "one.example.com",
                    "port": 443,
                    "exposureLevel": "HIGH",
                },
                {
                    "id": "endpoint-medium",
                    "name": "medium",
                    "host": "medium.example.com",
                    "port": 443,
                    "exposureLevel": "MEDIUM",
                },
                {
                    "id": "endpoint-2",
                    "name": "second",
                    "host": "two.example.com",
                    "port": 8443,
                    "exposureLevel": "HIGH",
                },
            ],
        )
        self.assertIn("applicationEndpoints", calls[0]["query"])
        self.assertEqual(
            calls[0]["variables"],
            {
                "first": 1,
                "after": None,
                "filterBy": {"project": ["242f91dd-f1c6-573f-b8b4-678df5581477"]},
            },
        )
        self.assertEqual(
            calls[1]["variables"],
            {
                "first": 1,
                "after": "cursor-1",
                "filterBy": {"project": ["242f91dd-f1c6-573f-b8b4-678df5581477"]},
            },
        )
        self.assertEqual(calls[0]["context"], "Application endpoints query")

    def test_list_application_endpoints_filters_by_configured_project(self):
        calls = []

        def fake_execute_graphql(config, access_token, query, variables, context):
            calls.append({"query": query, "variables": variables, "context": context})
            return {
                "applicationEndpoints": {
                    "nodes": [],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }

        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
            project_id="project-123",
        )

        with patch.object(wiz_auth_poc, "execute_graphql", fake_execute_graphql):
            endpoints = list(wiz_auth_poc.iter_application_endpoints(config, "token-123", page_size=10))

        self.assertEqual(endpoints, [])
        self.assertIn("filterBy: $filterBy", calls[0]["query"])
        self.assertEqual(
            calls[0]["variables"],
            {
                "first": 10,
                "after": None,
                "filterBy": {"project": ["project-123"]},
            },
        )

    def test_write_json_lines_outputs_one_endpoint_per_line(self):
        output = StringIO()

        count = wiz_auth_poc.write_json_lines(
            [
                {"id": "endpoint-1", "name": "first"},
                {"id": "endpoint-2", "name": "second"},
            ],
            output,
        )

        self.assertEqual(count, 2)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                '{"id":"endpoint-1","name":"first"}',
                '{"id":"endpoint-2","name":"second"}',
            ],
        )

    def test_main_list_application_endpoints_writes_only_json_lines_to_stdout(self):
        config = wiz_auth_poc.WizConfig(
            client_id="client-id",
            client_secret="client-secret",
            api_url="https://api.eu7.app.wiz.io/graphql",
            auth_url="https://auth.app.wiz.io/oauth/token",
        )
        stdout = StringIO()
        stderr = StringIO()

        with (
            patch.object(wiz_auth_poc, "load_config", return_value=config),
            patch.object(wiz_auth_poc, "fetch_access_token", return_value="token-123"),
            patch.object(
                wiz_auth_poc,
                "iter_application_endpoints",
                return_value=iter([{"id": "endpoint-1", "name": "first"}]),
            ),
            patch.object(sys, "argv", ["wiz_auth_poc.py", "list-application-endpoints"]),
            patch.object(sys, "stdout", stdout),
            patch.object(sys, "stderr", stderr),
        ):
            exit_code = wiz_auth_poc.main()

        self.assertEqual(exit_code, 0)
        self.assertEqual(stdout.getvalue(), '{"id":"endpoint-1","name":"first"}\n')
        self.assertIn("OAuth authentication succeeded", stderr.getvalue())
        self.assertIn("Exported 1 application endpoints.", stderr.getvalue())

    def test_redact_secret_keeps_short_hint_only(self):
        self.assertEqual(wiz_auth_poc.redact_secret("abcdef123456"), "abcd...3456")


if __name__ == "__main__":
    unittest.main()
