import json
import os
import ssl
import sys
import tempfile
import types
import unittest
import csv
import http.client
from io import StringIO
from unittest.mock import patch

import assess_attack_surface as asm
import wiz_auth_poc


class AssessAttackSurfaceTests(unittest.TestCase):
    def test_non_standard_open_port_returns_reduce_finding(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 8080,
            "protocols": ["HTTP"],
            "portStatus": "OPEN",
            "exposureLevel": "MEDIUM",
            "cloudAccount": {"name": "regular-account"},
            "tagEmails": ["owner@example.com", "team@example.com"],
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "non_standard_open_port")
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertEqual(findings[0]["cloudAccountName"], "regular-account")
        self.assertEqual(findings[0]["tagEmails"], ["owner@example.com", "team@example.com"])
        self.assertIn("8080", findings[0]["evidence"])

    def test_non_standard_open_port_without_response_on_non_sensitive_port_is_low_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 9095,
            "protocols": ["OTHER"],
            "portStatus": "OPEN",
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "non_standard_open_port")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertIn("https failed: connection refused", findings[0]["details"]["http_probe_result"])
        self.assertIn("http failed: connection refused", findings[0]["details"]["http_probe_result"])

    def test_standard_ports_do_not_return_non_standard_port_finding(self):
        for port in (80, 443):
            endpoint = {"id": f"endpoint-{port}", "host": "app.example.com", "port": port, "portStatus": "OPEN"}

            findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext())

            self.assertEqual(findings, [])

    def test_non_standard_open_port_for_fdp_subscription_is_low_risk(self):
        endpoint = {
            "id": "4c8a125f-60e5-50ec-bf5e-7dd14ce98056",
            "name": "68.79.15.14:9095",
            "host": "68.79.15.14",
            "port": 9095,
            "protocols": ["OTHER"],
            "portStatus": "OPEN",
            "exposureLevel": "HIGH",
            "subscription": "FDP",
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "non_standard_open_port")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["subscription"], "FDP")

    def test_non_standard_open_port_for_exempt_account_id_is_low_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 9095,
            "protocols": ["OTHER"],
            "portStatus": "OPEN",
            "accountId": "197575089658",
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["subscription"], "197575089658")

    def test_non_standard_open_port_for_cloud_account_fdp_is_low_risk(self):
        endpoint = {
            "id": "113122bd-8e70-588a-a7e1-60bffc255220",
            "name": "140.179.96.192:9095",
            "host": "140.179.96.192",
            "port": 9095,
            "protocols": ["OTHER"],
            "portStatus": "OPEN",
            "cloudAccount": {
                "id": "d6df48ea-c6e5-54f5-808b-72b4c55b74b5",
                "name": "FDP",
                "externalId": "197575089658",
                "cloudProvider": "AWS",
            },
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["subscription"], "FDP")

    def test_non_standard_open_port_for_whitelisted_cloud_account_name_is_low_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "71.131.246.78",
            "port": 9200,
            "protocols": ["HTTPS"],
            "portStatus": "OPEN",
            "cloudAccount": {
                "name": "adidas-linked-bam-pro-cn",
                "externalId": "347233338954",
            },
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["subscription"], "adidas-linked-bam-pro-cn")

    def test_non_standard_open_port_for_cicdtools_prod_is_low_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "cicd-proxy.tools.adidas.com.cn",
            "port": 22,
            "protocols": ["SSH"],
            "portStatus": "OPEN",
            "cloudAccount": {"name": "Cicdtools-prod"},
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["subscription"], "Cicdtools-prod")

    def test_non_standard_open_port_for_odp_china_account_is_low_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 22,
            "protocols": ["SSH"],
            "portStatus": "OPEN",
            "cloudAccount": {"name": "ODP-China-account"},
        }

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError("connection refused")

        findings = asm.NonStandardPortChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["subscription"], "ODP-China-account")

    def test_non_standard_open_port_https_sensitive_content_is_high_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "name": "71.131.246.78:9200",
            "host": "71.131.246.78",
            "port": 9200,
            "protocols": ["HTTPS"],
            "portStatus": "OPEN",
        }

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Index of /</title><h1>Index of /</h1><a href='backup.zip'>backup.zip</a></html>",
            )

        findings = asm.NonStandardPortChecker().check(
            endpoint,
            asm.CheckContext(fetcher=fetcher, llm_enabled=False),
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_sensitive_content_heuristic")
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertEqual(findings[0]["details"]["probe_scheme"], "https")
        self.assertEqual(findings[0]["details"]["http_probe_result"], "https returned HTTP 200")
        self.assertIn("directory_listing", findings[0]["details"]["signals"])

    def test_non_standard_open_port_tries_http_after_https_failure(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 9200,
            "protocols": ["HTTP"],
            "portStatus": "OPEN",
        }
        fetched_urls = []

        def fetcher(request, timeout, context=None):
            fetched_urls.append(request.full_url)
            if request.full_url.startswith("https://"):
                raise asm.urllib.error.URLError("wrong version number")
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Login</title><input type='password'></html>",
            )

        findings = asm.NonStandardPortChecker().check(
            endpoint,
            asm.CheckContext(fetcher=fetcher, llm_enabled=False),
        )

        self.assertEqual(fetched_urls, ["https://app.example.com:9200/", "http://app.example.com:9200/"])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_login_page")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["probe_scheme"], "http")
        self.assertEqual(
            findings[0]["details"]["http_probe_result"],
            "https failed: wrong version number; http returned HTTP 200",
        )

    def test_non_standard_open_port_probe_uses_short_timeout(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 9200,
            "protocols": ["HTTPS"],
            "portStatus": "OPEN",
        }
        captured_timeouts = []

        def fetcher(request, timeout, context=None):
            captured_timeouts.append(timeout)
            raise asm.urllib.error.URLError("timed out")

        findings = asm.NonStandardPortChecker().check(
            endpoint,
            asm.CheckContext(fetcher=fetcher, timeout_seconds=30),
        )

        self.assertEqual(captured_timeouts, [5, 5])
        self.assertEqual(findings[0]["check_id"], "non_standard_open_port")

    def test_non_standard_open_port_uses_llm_for_http_200_content(self):
        llm_calls = []
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 9200,
            "protocols": ["HTTPS"],
            "portStatus": "OPEN",
        }

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Welcome</title><p>Public page</p></html>",
            )

        def llm_client(prompt):
            llm_calls.append(prompt)
            return {
                "risk_level": "low",
                "reason": "Public non-standard port landing page",
                "evidence": "No sensitive content",
                "recommendation": "Keep monitoring.",
            }

        findings = asm.assess_endpoint(
            endpoint,
            [asm.NonStandardPortChecker(), asm.LlmSensitiveContentChecker()],
            asm.CheckContext(fetcher=fetcher, llm_enabled=True, llm_client=llm_client),
        )

        self.assertEqual([finding["check_id"] for finding in findings], ["llm_sensitive_content"])
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(len(llm_calls), 1)

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

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher, llm_enabled=False))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_sensitive_content_heuristic")
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertEqual(findings[0]["details"]["final_url"], "https://app.example.com/")
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["status"], 301)
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["location"], "https://app.example.com/")

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

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher, llm_enabled=False))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_login_page")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["final_url"], "https://app.example.com/login")
        self.assertEqual(len(findings[0]["details"]["redirect_chain"]), 1)

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

    def test_http_80_redirect_to_malformed_location_reports_follow_error(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=302,
                headers={"Location": "http://["},
                body=b"",
            )

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("Invalid redirect URL", findings[0]["evidence"])
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["location"], "http://[")

    def test_http_80_redirect_to_invalid_fetch_url_reports_follow_error(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            if request.full_url == "http://app.example.com:80/":
                return asm.HttpResponse(
                    url=request.full_url,
                    status=302,
                    headers={"Location": "https://exa mple.com/"},
                    body=b"",
                )
            raise http.client.InvalidURL("URL can't contain control characters")

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("Redirect target fetch failed", findings[0]["evidence"])
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["resolved_url"], "https://exa mple.com/")

    def test_http_80_redirect_target_remote_disconnect_reports_follow_error_with_chain(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            if request.full_url == "http://app.example.com:80/":
                return asm.HttpResponse(
                    url=request.full_url,
                    status=302,
                    headers={"Location": "https://app.example.com/"},
                    body=b"",
                )
            raise http.client.RemoteDisconnected("remote end closed connection without response")

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("remote end closed connection", findings[0]["evidence"])
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["resolved_url"], "https://app.example.com/")

    def test_http_80_redirect_target_connection_reset_reports_follow_error_with_chain(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            if request.full_url == "http://app.example.com:80/":
                return asm.HttpResponse(
                    url=request.full_url,
                    status=302,
                    headers={"Location": "https://app.example.com/"},
                    body=b"",
                )
            raise ConnectionResetError("connection reset by peer")

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_redirect_follow_error")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("connection reset by peer", findings[0]["evidence"])
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["resolved_url"], "https://app.example.com/")

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

    def test_http_80_without_https_redirect_is_reduce_candidate(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 80, "protocols": ["HTTP"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Plain HTTP</title></html>",
            )

        findings = asm.HttpRedirectChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "http_without_https_redirect")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertIn("HTTP 200", findings[0]["evidence"])

    def test_https_content_checker_identifies_login_page_as_low_risk(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Sign in</title><form><input type='password'></form></html>",
            )

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher, llm_enabled=False))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_login_page")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["title"], "Sign in")

    def test_https_content_checker_flags_directory_listing(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Index of /</title><h1>Index of /</h1><a href='backup.zip'>backup.zip</a></html>",
            )

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher, llm_enabled=False))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_sensitive_content_heuristic")
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertIn("directory_listing", findings[0]["details"]["signals"])

    def test_https_content_checker_follows_redirect_to_sensitive_content(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}
        responses = {
            "https://app.example.com:443/": asm.HttpResponse(
                url="https://app.example.com:443/",
                status=303,
                headers={"lOcAtIoN": "https://cdn.example.com/public"},
                body=b"",
            ),
            "https://cdn.example.com/public": asm.HttpResponse(
                url="https://cdn.example.com/public",
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Index of /</title><h1>Index of /</h1><a href='backup.zip'>backup.zip</a></html>",
            ),
        }

        def fetcher(request, timeout, context=None):
            return responses[request.full_url]

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher, llm_enabled=False))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_sensitive_content_heuristic")
        self.assertEqual(findings[0]["risk_level"], "high")
        self.assertEqual(findings[0]["details"]["initial_status"], 303)
        self.assertEqual(findings[0]["details"]["initial_location"], "https://cdn.example.com/public")
        self.assertEqual(findings[0]["details"]["final_url"], "https://cdn.example.com/public")
        self.assertEqual(findings[0]["details"]["redirect_chain"][0]["location"], "https://cdn.example.com/public")

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
            asm.CheckContext(llm_enabled=False),
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

    def test_https_content_checker_reports_tls_certificate_error(self):
        endpoint = {"id": "endpoint-1", "host": "lb.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError(
                ssl.SSLCertVerificationError("certificate verify failed: Hostname mismatch")
            )

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_tls_certificate_error")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertIn("Hostname mismatch", findings[0]["evidence"])

    def test_https_content_checker_reports_connection_reset_as_low_risk(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            raise ConnectionResetError("Connection reset by peer")

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_connection_reset")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertIn("Connection reset by peer", findings[0]["evidence"])

    def test_https_content_checker_reports_urlerror_connection_reset_as_low_risk(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            raise asm.urllib.error.URLError(ConnectionResetError("Connection reset by peer"))

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_connection_reset")
        self.assertEqual(findings[0]["risk_level"], "low")

    def test_https_content_checker_marks_clean_404_as_low_risk(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "protocols": ["HTTPS"],
            "exposureLevel": "MEDIUM",
        }

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=404,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>404 Not Found</title></html>",
            )

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_not_found")
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(findings[0]["details"]["status"], 404)

    def test_https_content_checker_keeps_high_exposure_404_as_medium(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "protocols": ["HTTPS"],
            "exposureLevel": "HIGH",
        }

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=404,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>404 Not Found</title></html>",
            )

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_not_found_review")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("exposureLevel=HIGH", findings[0]["evidence"])

    def test_https_content_checker_keeps_informative_404_as_medium(self):
        endpoint = {
            "id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "protocols": ["HTTPS"],
            "exposureLevel": "MEDIUM",
        }

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=404,
                headers={"Content-Type": "text/html", "Server": "nginx/1.14.2"},
                body=b"<html><title>404 Not Found</title></html>",
            )

        findings = asm.HttpsContentChecker().check(endpoint, asm.CheckContext(fetcher=fetcher))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["check_id"], "https_not_found_review")
        self.assertEqual(findings[0]["risk_level"], "medium")
        self.assertIn("Server=nginx/1.14.2", findings[0]["evidence"])

        csv_output = StringIO()
        asm.write_findings_csv(findings, csv_output)
        rows = list(csv.DictReader(StringIO(csv_output.getvalue())))

        self.assertIn("Server=nginx/1.14.2", rows[0]["LLM意见"])

    def test_fetch_endpoint_can_use_insecure_tls_context(self):
        captured = {}
        endpoint = {"id": "endpoint-1", "host": "lb.example.com", "port": 443}

        def fetcher(request, timeout, context=None):
            captured["context"] = context
            return asm.HttpResponse(request.full_url, 200, {}, b"ok")

        context = asm.CheckContext(fetcher=fetcher, insecure_tls=True)

        response = asm.fetch_endpoint(endpoint, "https", context)

        self.assertEqual(response.status, 200)
        self.assertIsNotNone(captured["context"])
        self.assertFalse(captured["context"].check_hostname)

    def test_llm_checker_is_disabled_unless_enabled(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443}
        context = asm.CheckContext(llm_enabled=False, response_summaries={"endpoint-1": {"body_text": "secret"}})

        findings = asm.LlmSensitiveContentChecker().check(endpoint, context)

        self.assertEqual(findings, [])

    def test_llm_checker_sends_unredacted_response_summary_when_enabled(self):
        captured = {}

        def llm_client(prompt):
            captured["prompt"] = prompt
            return {
                "risk_level": "high",
                "reason": "API key exposed",
                "evidence": "api_key=SECRET123",
                "recommendation": "Remove the exposed secret and rotate it.",
            }

        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443}
        context = asm.CheckContext(
            llm_enabled=True,
            llm_client=llm_client,
            response_summaries={
                "endpoint-1": {
                    "url": "https://app.example.com/",
                    "status": 200,
                    "headers": {"Content-Type": "text/plain"},
                    "body_text": "api_key=SECRET123",
                }
            },
        )

        findings = asm.LlmSensitiveContentChecker().check(endpoint, context)

        self.assertIn("api_key=SECRET123", captured["prompt"])
        self.assertEqual(findings[0]["check_id"], "llm_sensitive_content")
        self.assertEqual(findings[0]["risk_level"], "high")

    def test_llm_checker_preserves_http_status_for_csv_output(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443}
        context = asm.CheckContext(
            llm_enabled=True,
            llm_client=lambda prompt: {
                "risk_level": "low",
                "reason": "Login page",
                "evidence": "这是一个登录页面，没有敏感数据",
                "recommendation": "Keep monitoring.",
            },
            response_summaries={
                "endpoint-1": {
                    "url": "https://app.example.com/",
                    "status": 200,
                    "headers": {"Content-Type": "text/html"},
                    "body_text": "<html>login</html>",
                }
            },
        )

        findings = asm.LlmSensitiveContentChecker().check(endpoint, context)
        csv_output = StringIO()
        asm.write_findings_csv(findings, csv_output)
        rows = list(csv.DictReader(StringIO(csv_output.getvalue())))

        self.assertEqual(findings[0]["details"]["status"], 200)
        self.assertEqual(rows[0]["http状态码"], "200")

    def test_http_200_https_response_uses_llm_instead_of_review_required_when_enabled(self):
        llm_calls = []
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Welcome</title><p>Public page</p></html>",
            )

        def llm_client(prompt):
            llm_calls.append(prompt)
            return {
                "risk_level": "low",
                "reason": "Public landing page",
                "evidence": "No sensitive content",
                "recommendation": "No action.",
            }

        context = asm.CheckContext(fetcher=fetcher, llm_enabled=True, llm_client=llm_client)

        findings = asm.assess_endpoint(
            endpoint,
            [asm.HttpsContentChecker(), asm.LlmSensitiveContentChecker()],
            context,
        )

        self.assertEqual([finding["check_id"] for finding in findings], ["llm_sensitive_content"])
        self.assertEqual(findings[0]["risk_level"], "low")
        self.assertEqual(len(llm_calls), 1)

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
        self.assertIn("这是一个公开页面，没有敏感数据", findings[0]["evidence"])

    def test_http_200_https_response_keeps_review_required_when_llm_disabled(self):
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Welcome</title><p>Public page</p></html>",
            )

        findings = asm.assess_endpoint(
            endpoint,
            [asm.HttpsContentChecker(), asm.LlmSensitiveContentChecker()],
            asm.CheckContext(fetcher=fetcher, llm_enabled=False),
        )

        self.assertEqual([finding["check_id"] for finding in findings], ["https_review_required"])

    def test_non_200_https_response_does_not_force_llm_when_enabled(self):
        llm_calls = []
        endpoint = {"id": "endpoint-1", "host": "app.example.com", "port": 443, "protocols": ["HTTPS"]}

        def fetcher(request, timeout, context=None):
            return asm.HttpResponse(
                url=request.full_url,
                status=404,
                headers={"Content-Type": "text/html"},
                body=b"<html><title>Not Found</title></html>",
            )

        def llm_client(prompt):
            llm_calls.append(prompt)
            return {
                "risk_level": "low",
                "reason": "Not found page",
                "evidence": "404",
                "recommendation": "No action.",
            }

        findings = asm.assess_endpoint(
            endpoint,
            [asm.HttpsContentChecker(), asm.LlmSensitiveContentChecker()],
            asm.CheckContext(fetcher=fetcher, llm_enabled=True, llm_client=llm_client),
        )

        self.assertEqual([finding["check_id"] for finding in findings], ["https_not_found"])
        self.assertEqual(llm_calls, [])

    def test_write_findings_outputs_json_lines(self):
        output = StringIO()

        count = asm.write_findings(
            [
                {"endpoint_id": "endpoint-1", "check_id": "check-a", "risk_level": "medium"},
                {"endpoint_id": "endpoint-2", "check_id": "check-b", "risk_level": "low"},
            ],
            output,
        )

        self.assertEqual(count, 2)
        self.assertEqual(
            output.getvalue().splitlines(),
            [
                '{"endpoint_id":"endpoint-1","check_id":"check-a","risk_level":"medium"}',
                '{"endpoint_id":"endpoint-2","check_id":"check-b","risk_level":"low"}',
            ],
        )

    def test_write_findings_csv_outputs_requested_columns_with_llm_summary(self):
        output = StringIO()
        findings = [
            {
                "endpoint_id": "2e7dca40-b6e1-5e11-aa7e-3303642a6ef0",
                "endpoint_name": "https://app.example.com:443",
                "port": 443,
                "cloudPlatform": "AWS",
                "cloudAccountName": "adidas-linked-bam-pro-cn",
                "tagEmails": ["reema.jain@adidas.com", "AAD-AWS-ADIDAS-LINKED-BAM-PRO-CN-Admin@groups.adidas.com"],
                "check_id": "llm_sensitive_content",
                "risk_level": "medium",
                "evidence": "<input name='token' value='secret-token'>",
                "recommendation": "Protect the token.",
                "details": {
                    "http_status": 200,
                    "reason": "LLM found a sensitive token in the login HTML.",
                },
            },
            {
                "endpoint_name": "https://login.example.com:443",
                "port": 443,
                "cloudPlatform": "Alibaba",
                "check_id": "https_login_page",
                "risk_level": "low",
                "evidence": "HTTPS endpoint appears to be a login page rather than direct sensitive content.",
                "recommendation": "Keep authentication enforced.",
                "details": {
                    "status": 200,
                    "title": "Sign in",
                    "content_type": "text/html",
                },
            },
        ]

        count = asm.write_findings_csv(findings, output)

        self.assertEqual(count, 2)
        rows = list(csv.DictReader(StringIO(output.getvalue())))
        self.assertEqual(
            rows[0],
            {
                "endpoint_name": "https://app.example.com:443",
                "Wiz链接": "https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%272e7dca40-b6e1-5e11-aa7e-3303642a6ef0*2cENDPOINT%29%29",
                "端口号": "443",
                "cloudPlatform": "AWS",
                "CloudAccount": "adidas-linked-bam-pro-cn",
                "TagEmails": "reema.jain@adidas.com; AAD-AWS-ADIDAS-LINKED-BAM-PRO-CN-Admin@groups.adidas.com",
                "http状态码": "200",
                "http response": "<input name='token' value='secret-token'>",
                "LLM意见": "LLM found a sensitive token in the login HTML. Protect the token.",
                "risk_level": "medium",
            },
        )
        self.assertEqual(rows[1]["http response"], "Sign in; content_type=text/html")
        self.assertEqual(rows[1]["CloudAccount"], "")
        self.assertEqual(rows[1]["TagEmails"], "")
        self.assertEqual(rows[1]["LLM意见"], "HTTPS endpoint appears to be a login page rather than direct sensitive content.")
        self.assertEqual(rows[1]["Wiz链接"], "")

    def test_write_findings_csv_flushes_every_10_rows(self):
        class FlushTrackingStringIO(StringIO):
            def __init__(self):
                super().__init__()
                self.flush_line_counts = []

            def flush(self):
                self.flush_line_counts.append(len(self.getvalue().splitlines()))
                super().flush()

        output = FlushTrackingStringIO()
        findings = [
            {
                "endpoint_name": f"https://app-{index}.example.com:443",
                "port": 443,
                "cloudPlatform": "AWS",
                "check_id": "https_login_page",
                "risk_level": "low",
                "evidence": "Login page.",
                "recommendation": "Keep authentication enforced.",
                "details": {"status": 200},
            }
            for index in range(11)
        ]

        count = asm.write_findings_csv(findings, output)

        self.assertEqual(count, 11)
        self.assertEqual(output.flush_line_counts, [11, 12])

    def test_write_findings_csv_prefers_http_probe_result_for_response_summary(self):
        output = StringIO()
        findings = [
            {
                "endpoint_name": "app.example.com:9200",
                "port": 9200,
                "cloudPlatform": "AWS",
                "check_id": "non_standard_open_port",
                "risk_level": "low",
                "evidence": "Open non-standard internet-facing port 9200.",
                "recommendation": "Keep monitored.",
                "details": {
                    "http_probe_result": "https failed: timed out; http failed: connection refused",
                },
            }
        ]

        asm.write_findings_csv(findings, output)

        rows = list(csv.DictReader(StringIO(output.getvalue())))
        self.assertEqual(rows[0]["http response"], "https failed: timed out; http failed: connection refused")

    def test_build_llm_prompt_requests_csv_friendly_evidence(self):
        prompt = asm.build_llm_prompt(
            {"id": "endpoint-1", "name": "https://app.example.com:443"},
            {
                "url": "https://app.example.com/",
                "status": 200,
                "headers": {"Content-Type": "text/html"},
                "body_text": "<html>ok</html>",
            },
        )

        self.assertIn("If no sensitive content is present, evidence should be a concise Chinese summary", prompt)
        self.assertIn("If sensitive content is present, evidence should include the relevant HTTP/HTML response snippet", prompt)

    def test_arg_parser_defaults_to_full_scan_operational_settings(self):
        args = asm.build_arg_parser().parse_args([])

        self.assertEqual(args.timeout, 30)
        self.assertTrue(args.insecure_tls)
        self.assertTrue(args.enable_llm)

    def test_arg_parser_allows_disabling_insecure_tls_and_llm(self):
        args = asm.build_arg_parser().parse_args(["--secure-tls", "--disable-llm", "--no-upload-oss"])

        self.assertFalse(args.insecure_tls)
        self.assertFalse(args.enable_llm)

    def test_default_output_paths_use_timestamp_prefix(self):
        now = asm.datetime.datetime(2026, 8, 3, 14, 29, 9)

        json_path, csv_path = asm.default_output_paths(now)

        self.assertEqual(json_path, "20260803-142909-asm-findings.jsonl")
        self.assertEqual(csv_path, "20260803-142909-asm-findings.csv")

    def test_resolve_output_paths_creates_jsonl_and_csv_when_output_omitted(self):
        args = asm.build_arg_parser().parse_args([])
        now = asm.datetime.datetime(2026, 8, 3, 14, 29, 9)

        json_path, csv_path = asm.resolve_output_paths(args, now)

        self.assertEqual(json_path, "20260803-142909-asm-findings.jsonl")
        self.assertEqual(csv_path, "20260803-142909-asm-findings.csv")

    def test_resolve_output_paths_preserves_explicit_output_behavior(self):
        args = asm.build_arg_parser().parse_args(["--output", "-", "--csv-output", "custom.csv"])

        json_path, csv_path = asm.resolve_output_paths(args, asm.datetime.datetime(2026, 8, 3, 14, 29, 9))

        self.assertEqual(json_path, "-")
        self.assertEqual(csv_path, "custom.csv")

    def test_main_writes_json_and_csv_outputs(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.jsonl")
            json_path = os.path.join(temp_dir, "findings.jsonl")
            csv_path = os.path.join(temp_dir, "findings.csv")
            with open(input_path, "w", encoding="utf-8") as input_file:
                input_file.write(
                    json.dumps(
                        {
                            "id": "endpoint-1",
                            "name": "https://app.example.com:443",
                            "host": "app.example.com",
                            "port": 443,
                            "protocols": ["HTTPS"],
                            "cloudPlatform": "AWS",
                        }
                    )
                    + "\n"
                )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(
                    url=request.full_url,
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><title>Welcome</title><p>Public page</p></html>",
                )

            with patch.object(asm, "fetch_url", fetcher):
                exit_code = asm.main(
                    ["--input", input_path, "--output", json_path, "--csv-output", csv_path, "--disable-llm", "--no-upload-oss"]
                )

            with open(json_path, encoding="utf-8") as json_file:
                json_rows = [json.loads(line) for line in json_file if line.strip()]
            with open(csv_path, encoding="utf-8", newline="") as csv_file:
                csv_rows = list(csv.DictReader(csv_file))

        self.assertEqual(exit_code, 0)
        self.assertEqual(len(json_rows), 1)
        self.assertEqual(len(csv_rows), 1)
        self.assertEqual(csv_rows[0]["endpoint_name"], "https://app.example.com:443")
        self.assertEqual(csv_rows[0]["http状态码"], "200")

    def test_main_uploads_outputs_to_oss_when_configured(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.jsonl")
            json_path = os.path.join(temp_dir, "findings.jsonl")
            csv_path = os.path.join(temp_dir, "findings.csv")
            with open(input_path, "w", encoding="utf-8") as input_file:
                input_file.write(
                    json.dumps(
                        {
                            "id": "endpoint-1",
                            "name": "https://app.example.com:443",
                            "host": "app.example.com",
                            "port": 443,
                            "protocols": ["HTTPS"],
                            "cloudPlatform": "AWS",
                        }
                    )
                    + "\n"
                )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(
                    url=request.full_url,
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><title>Welcome</title><p>Public page</p></html>",
                )

            uploaded = []
            status_output = StringIO()
            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.object(asm.upload_to_oss, "load_dotenv") as load_dotenv,
                patch.dict(
                    os.environ,
                    {"OSS_ENDPOINT": "https://oss-cn-shanghai-internal.aliyuncs.com", "OSS_BUCKET": "appsec-asm"},
                    clear=False,
                ),
                patch.object(asm.upload_to_oss, "fetch_role_credentials", return_value={"AccessKeyId": "id", "AccessKeySecret": "secret", "SecurityToken": "token"}) as fetch_credentials,
                patch.object(asm.upload_to_oss, "upload_file", side_effect=lambda path, endpoint, bucket, credentials, prefix: uploaded.append((path, endpoint, bucket, credentials, prefix)) or f"asm-findings/{os.path.basename(path)}"),
                patch.object(sys, "stderr", status_output),
            ):
                exit_code = asm.main(
                    [
                        "--input",
                        input_path,
                        "--output",
                        json_path,
                        "--csv-output",
                        csv_path,
                        "--disable-llm",
                    ]
                )

        self.assertEqual(exit_code, 0)
        load_dotenv.assert_called_once_with()
        fetch_credentials.assert_called_once_with(None)
        self.assertEqual([item[0] for item in uploaded], [json_path, csv_path])
        self.assertEqual({item[1] for item in uploaded}, {"https://oss-cn-shanghai-internal.aliyuncs.com"})
        self.assertEqual({item[2] for item in uploaded}, {"appsec-asm"})
        self.assertIn(f"Uploading {json_path} to OSS.", status_output.getvalue())
        self.assertIn(f"Uploading {csv_path} to OSS.", status_output.getvalue())

    def test_main_skips_oss_upload_when_disabled(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.jsonl")
            json_path = os.path.join(temp_dir, "findings.jsonl")
            csv_path = os.path.join(temp_dir, "findings.csv")
            with open(input_path, "w", encoding="utf-8") as input_file:
                input_file.write(
                    json.dumps(
                        {
                            "id": "endpoint-1",
                            "name": "https://app.example.com:443",
                            "host": "app.example.com",
                            "port": 443,
                            "protocols": ["HTTPS"],
                        }
                    )
                    + "\n"
                )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(request.full_url, 200, {"Content-Type": "text/html"}, b"<html>login</html>")

            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.dict(os.environ, {"OSS_ENDPOINT": "https://oss-cn-shanghai-internal.aliyuncs.com", "OSS_BUCKET": "appsec-asm"}, clear=False),
                patch.object(asm.upload_to_oss, "upload_file") as upload_file,
            ):
                exit_code = asm.main(
                    [
                        "--input",
                        input_path,
                        "--output",
                        json_path,
                        "--csv-output",
                        csv_path,
                        "--disable-llm",
                        "--no-upload-oss",
                    ]
                )

        self.assertEqual(exit_code, 0)
        upload_file.assert_not_called()

    def test_main_skips_oss_upload_when_not_configured(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.jsonl")
            json_path = os.path.join(temp_dir, "findings.jsonl")
            with open(input_path, "w", encoding="utf-8") as input_file:
                input_file.write(
                    json.dumps(
                        {
                            "id": "endpoint-1",
                            "name": "https://app.example.com:443",
                            "host": "app.example.com",
                            "port": 443,
                            "protocols": ["HTTPS"],
                        }
                    )
                    + "\n"
                )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(request.full_url, 200, {"Content-Type": "text/html"}, b"<html>login</html>")

            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.object(asm, "load_dotenv"),
                patch.dict(os.environ, {}, clear=True),
                patch.object(asm.upload_to_oss, "upload_file") as upload_file,
            ):
                exit_code = asm.main(["--input", input_path, "--output", json_path, "--disable-llm"])

        self.assertEqual(exit_code, 0)
        upload_file.assert_not_called()

    def test_upload_outputs_to_oss_requires_existing_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            missing_json_path = os.path.join(temp_dir, "missing.jsonl")
            csv_path = os.path.join(temp_dir, "findings.csv")
            with open(csv_path, "w", encoding="utf-8") as csv_file:
                csv_file.write("header\n")

            with self.assertRaisesRegex(FileNotFoundError, "missing.jsonl"):
                asm.upload_outputs_to_oss(missing_json_path, csv_path)

    def test_main_without_output_creates_timestamped_jsonl_and_csv_files(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.jsonl")
            with open(input_path, "w", encoding="utf-8") as input_file:
                input_file.write(
                    json.dumps(
                        {
                            "id": "endpoint-1",
                            "name": "https://app.example.com:443",
                            "host": "app.example.com",
                            "port": 443,
                            "protocols": ["HTTPS"],
                            "cloudPlatform": "AWS",
                        }
                    )
                    + "\n"
                )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(
                    url=request.full_url,
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><title>Welcome</title><p>Public page</p></html>",
                )

            real_datetime = asm.datetime.datetime

            class FixedDateTime(real_datetime):
                @classmethod
                def now(cls, tz=None):
                    return cls(2026, 8, 3, 14, 29, 9, tzinfo=tz)

            current_dir = os.getcwd()
            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.object(asm.datetime, "datetime", FixedDateTime),
            ):
                os.chdir(temp_dir)
                try:
                    exit_code = asm.main(["--input", input_path, "--disable-llm", "--no-upload-oss"])
                finally:
                    os.chdir(current_dir)

            json_path = os.path.join(temp_dir, "20260803-142909-asm-findings.jsonl")
            csv_path = os.path.join(temp_dir, "20260803-142909-asm-findings.csv")

            self.assertEqual(exit_code, 0)
            self.assertTrue(os.path.exists(json_path))
            self.assertTrue(os.path.exists(csv_path))

    def test_main_logs_each_processed_endpoint(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.jsonl")
            json_path = os.path.join(temp_dir, "findings.jsonl")
            endpoints = [
                {
                    "id": "endpoint-1",
                    "name": "https://app-1.example.com:443",
                    "host": "app-1.example.com",
                    "port": 443,
                    "protocols": ["HTTPS"],
                    "cloudPlatform": "AWS",
                },
                {
                    "id": "endpoint-2",
                    "name": "https://app-2.example.com:443",
                    "host": "app-2.example.com",
                    "port": 443,
                    "protocols": ["HTTPS"],
                    "cloudPlatform": "AWS",
                },
            ]
            with open(input_path, "w", encoding="utf-8") as input_file:
                for endpoint in endpoints:
                    input_file.write(json.dumps(endpoint) + "\n")

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(
                    url=request.full_url,
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><title>Login</title><form><input type='password'></form></html>",
                )

            status_output = StringIO()
            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.object(sys, "stderr", status_output),
            ):
                exit_code = asm.main(["--input", input_path, "--output", json_path, "--disable-llm", "--no-upload-oss"])

        self.assertEqual(exit_code, 0)
        status_lines = status_output.getvalue().splitlines()
        self.assertIn(
            "Processed endpoint 1: https://app-1.example.com:443 (1 findings, 1 findings total).",
            status_lines,
        )
        self.assertIn(
            "Processed endpoint 2: https://app-2.example.com:443 (1 findings, 2 findings total).",
            status_lines,
        )

    def test_main_fetches_latest_wiz_endpoints_by_default(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = os.path.join(temp_dir, "findings.jsonl")
            csv_path = os.path.join(temp_dir, "findings.csv")
            config = wiz_auth_poc.WizConfig(
                client_id="client-id",
                client_secret="client-secret",
                api_url="https://api.example.com/graphql",
                auth_url="https://auth.example.com/oauth/token",
            )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(
                    url=request.full_url,
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><title>Fetched from Wiz</title></html>",
                )

            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.object(asm.wiz_auth_poc, "load_config", return_value=config) as load_config,
                patch.object(asm.wiz_auth_poc, "fetch_access_token", return_value="token-123") as fetch_token,
                patch.object(
                    asm.wiz_auth_poc,
                    "iter_application_endpoints",
                    return_value=iter(
                        [
                            {
                                "id": "endpoint-1",
                                "name": "https://wiz.example.com:443",
                                "host": "wiz.example.com",
                                "port": 443,
                                "protocols": ["HTTPS"],
                                "cloudPlatform": "AWS",
                                "cloudAccount": {"id": "cloud-account-1", "name": "Account One"},
                            }
                        ]
                    ),
                ) as iter_endpoints,
                patch.object(
                    asm.wiz_auth_poc,
                    "fetch_cloud_account_tag_emails",
                    return_value=["owner@example.com", "admin@example.com"],
                ) as fetch_tag_emails,
            ):
                exit_code = asm.main(
                    ["--output", json_path, "--csv-output", csv_path, "--limit", "1", "--disable-llm", "--no-upload-oss"]
                )

            with open(json_path, encoding="utf-8") as json_file:
                json_rows = [json.loads(line) for line in json_file if line.strip()]
            with open(csv_path, encoding="utf-8", newline="") as csv_file:
                csv_rows = list(csv.DictReader(csv_file))

        self.assertEqual(exit_code, 0)
        load_config.assert_called_once_with()
        fetch_token.assert_called_once_with(config)
        iter_endpoints.assert_called_once_with(config, "token-123")
        fetch_tag_emails.assert_called_once_with(config, "token-123", "cloud-account-1")
        self.assertEqual(json_rows[0]["endpoint_name"], "https://wiz.example.com:443")
        self.assertEqual(json_rows[0]["tagEmails"], ["owner@example.com", "admin@example.com"])
        self.assertEqual(csv_rows[0]["TagEmails"], "owner@example.com; admin@example.com")
        self.assertEqual(
            csv_rows[0]["Wiz链接"],
            "https://app.wiz.io/p/secengcnaccounts/inventory/application-endpoints#%7E%28entity%7E%28%7E%27endpoint-1*2cENDPOINT%29%29",
        )

    def test_main_continues_when_cloud_account_tag_email_lookup_times_out(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = os.path.join(temp_dir, "findings.jsonl")
            config = wiz_auth_poc.WizConfig(
                client_id="client-id",
                client_secret="client-secret",
                api_url="https://api.example.com/graphql",
                auth_url="https://auth.example.com/oauth/token",
            )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(
                    url=request.full_url,
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><title>Fetched from Wiz</title></html>",
                )

            status_output = StringIO()
            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.object(asm.wiz_auth_poc, "load_config", return_value=config),
                patch.object(asm.wiz_auth_poc, "fetch_access_token", return_value="token-123"),
                patch.object(
                    asm.wiz_auth_poc,
                    "iter_application_endpoints",
                    return_value=iter(
                        [
                            {
                                "id": "endpoint-1",
                                "name": "https://wiz.example.com:443",
                                "host": "wiz.example.com",
                                "port": 443,
                                "protocols": ["HTTPS"],
                                "cloudPlatform": "AWS",
                                "cloudAccount": {"id": "cloud-account-1", "name": "Account One"},
                            }
                        ]
                    ),
                ),
                patch.object(asm.wiz_auth_poc, "fetch_cloud_account_tag_emails", side_effect=TimeoutError("read timed out")),
                patch.object(sys, "stderr", status_output),
            ):
                exit_code = asm.main(["--output", json_path, "--limit", "1", "--disable-llm", "--no-upload-oss"])

            with open(json_path, encoding="utf-8") as json_file:
                json_rows = [json.loads(line) for line in json_file if line.strip()]

        self.assertEqual(exit_code, 0)
        self.assertEqual(json_rows[0]["tagEmails"], [])
        self.assertIn("CloudAccount tag email lookup failed for cloud-account-1", status_output.getvalue())

    def test_main_uses_explicit_input_without_fetching_wiz(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = os.path.join(temp_dir, "input.jsonl")
            json_path = os.path.join(temp_dir, "findings.jsonl")
            with open(input_path, "w", encoding="utf-8") as input_file:
                input_file.write(
                    json.dumps(
                        {
                            "id": "endpoint-1",
                            "name": "https://local.example.com:443",
                            "host": "local.example.com",
                            "port": 443,
                            "protocols": ["HTTPS"],
                            "cloudPlatform": "AWS",
                        }
                    )
                    + "\n"
                )

            def fetcher(request, timeout, context=None):
                return asm.HttpResponse(
                    url=request.full_url,
                    status=200,
                    headers={"Content-Type": "text/html"},
                    body=b"<html><title>Local input</title></html>",
                )

            with (
                patch.object(asm, "fetch_url", fetcher),
                patch.object(asm.wiz_auth_poc, "load_config") as load_config,
            ):
                exit_code = asm.main(["--input", input_path, "--output", json_path, "--disable-llm", "--no-upload-oss"])

            with open(json_path, encoding="utf-8") as json_file:
                json_rows = [json.loads(line) for line in json_file if line.strip()]

        self.assertEqual(exit_code, 0)
        load_config.assert_not_called()
        self.assertEqual(json_rows[0]["endpoint_name"], "https://local.example.com:443")

    def test_openai_compatible_client_reads_env_and_parses_json(self):
        captured = {}

        def fake_fetcher(request, timeout, context=None):
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "risk_level": "low",
                                            "reason": "Login page",
                                            "evidence": "Password form",
                                            "recommendation": "Keep monitoring.",
                                        }
                                    )
                                }
                            }
                        ]
                    }
                ).encode("utf-8"),
            )

        with patch.dict(
            os.environ,
            {
                "LLM_API_KEY": "llm-key",
                "LLM_BASE_URL": "https://llm.example.com/v1",
                "LLM_MODEL": "model-a",
            },
            clear=True,
        ):
            client = asm.OpenAICompatibleClient(fetcher=fake_fetcher)
            result = client("judge this")

        self.assertEqual(captured["url"], "https://llm.example.com/v1/chat/completions")
        self.assertEqual(captured["headers"]["Authorization"], "Bearer llm-key")
        self.assertEqual(captured["body"]["model"], "model-a")
        self.assertEqual(result["risk_level"], "low")

    def test_openai_compatible_client_loads_dotenv_without_overriding_existing_env(self):
        captured = {}

        def fake_fetcher(request, timeout, context=None):
            captured["url"] = request.full_url
            captured["headers"] = dict(request.header_items())
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "risk_level": "low",
                                            "reason": "Loaded from .env",
                                            "evidence": "Connectivity test",
                                            "recommendation": "No action.",
                                        }
                                    )
                                }
                            }
                        ]
                    }
                ).encode("utf-8"),
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            dotenv_path = os.path.join(temp_dir, ".env")
            with open(dotenv_path, "w", encoding="utf-8") as dotenv:
                dotenv.write("LLM_API_KEY=dotenv-key\n")
                dotenv.write("LLM_BASE_URL=https://dotenv.example.com/v1\n")
                dotenv.write("LLM_MODEL=dotenv-model\n")

            with (
                patch.dict(os.environ, {"LLM_API_KEY": "exported-key"}, clear=True),
                patch.object(os, "getcwd", return_value=temp_dir),
            ):
                client = asm.OpenAICompatibleClient(fetcher=fake_fetcher)
                result = client("judge this")

        self.assertEqual(captured["url"], "https://dotenv.example.com/v1/chat/completions")
        self.assertTrue(captured["headers"]["Authorization"].startswith("Bearer "))
        self.assertEqual(captured["body"]["model"], "dotenv-model")
        self.assertEqual(client.api_key, "exported-key")
        self.assertEqual(result["reason"], "Loaded from .env")

    def test_openai_compatible_client_uses_qwen_defaults_from_dashscope_env(self):
        captured = {}

        def fake_fetcher(request, timeout, context=None):
            captured["url"] = request.full_url
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "risk_level": "low",
                                            "reason": "Qwen default config",
                                            "evidence": "DashScope key used",
                                            "recommendation": "No action.",
                                        }
                                    )
                                }
                            }
                        ]
                    }
                ).encode("utf-8"),
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            dotenv_path = os.path.join(temp_dir, ".env")
            with open(dotenv_path, "w", encoding="utf-8") as dotenv:
                dotenv.write("DASHSCOPE_API_KEY=dashscope-key\n")

            with (
                patch.dict(os.environ, {}, clear=True),
                patch.object(os, "getcwd", return_value=temp_dir),
            ):
                client = asm.OpenAICompatibleClient(fetcher=fake_fetcher)
                result = client("judge this")

        self.assertEqual(captured["url"], "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions")
        self.assertEqual(captured["body"]["model"], "qwen-plus")
        self.assertEqual(client.api_key, "dashscope-key")
        self.assertEqual(result["reason"], "Qwen default config")

    def test_openai_compatible_client_prefers_llm_api_key_over_dashscope_key(self):
        with patch.dict(
            os.environ,
            {
                "LLM_API_KEY": "llm-key",
                "DASHSCOPE_API_KEY": "dashscope-key",
                "LLM_BASE_URL": "https://llm.example.com/v1",
                "LLM_MODEL": "model-a",
            },
            clear=True,
        ):
            client = asm.OpenAICompatibleClient(fetcher=lambda request, timeout, context=None: None)

        self.assertEqual(client.api_key, "llm-key")

    def test_openai_compatible_client_passes_detected_ca_bundle_context(self):
        captured = {}
        fake_context = object()

        def fake_fetcher(request, timeout, context=None):
            captured["context"] = context
            return asm.HttpResponse(
                url=request.full_url,
                status=200,
                headers={"Content-Type": "application/json"},
                body=json.dumps(
                    {
                        "choices": [
                            {
                                "message": {
                                    "content": json.dumps(
                                        {
                                            "risk_level": "low",
                                            "reason": "CA context",
                                            "evidence": "Context passed",
                                            "recommendation": "No action.",
                                        }
                                    )
                                }
                            }
                        ]
                    }
                ).encode("utf-8"),
            )

        with (
            patch.dict(
                os.environ,
                {
                    "LLM_API_KEY": "llm-key",
                    "LLM_BASE_URL": "https://llm.example.com/v1",
                    "LLM_MODEL": "model-a",
                },
                clear=True,
            ),
            patch.object(asm, "detect_ca_bundle", return_value="/tmp/ca.pem"),
            patch.object(ssl, "create_default_context", return_value=fake_context) as create_context,
        ):
            client = asm.OpenAICompatibleClient(fetcher=fake_fetcher)
            result = client("judge this")

        create_context.assert_called_once_with(cafile="/tmp/ca.pem")
        self.assertIs(captured["context"], fake_context)
        self.assertEqual(result["reason"], "CA context")

    def test_detect_ca_bundle_uses_certifi_when_python_has_no_default_cafile(self):
        with tempfile.NamedTemporaryFile() as ca_file:
            fake_certifi = types.SimpleNamespace(where=lambda: ca_file.name)
            fake_paths = types.SimpleNamespace(cafile=None)

            with (
                patch.object(ssl, "get_default_verify_paths", return_value=fake_paths),
                patch.dict("sys.modules", {"certifi": fake_certifi}),
            ):
                ca_bundle = asm.detect_ca_bundle()

        self.assertEqual(ca_bundle, ca_file.name)

    def test_check_context_uses_detected_ca_bundle(self):
        with patch.object(asm, "detect_ca_bundle", return_value="/tmp/ca.pem"):
            context = asm.CheckContext()

        self.assertEqual(context.ca_bundle, "/tmp/ca.pem")

    def test_fetch_url_does_not_pass_context_to_opener_open(self):
        captured = {}

        class FakeResponse:
            status = 200
            headers = {"Content-Type": "text/plain"}

            def geturl(self):
                return "https://app.example.com/"

            def read(self, limit):
                return b"ok"

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, traceback):
                return False

        class FakeOpener:
            def open(self, request, timeout):
                captured["request"] = request
                captured["timeout"] = timeout
                return FakeResponse()

        request = asm.urllib.request.Request("https://app.example.com/")

        with patch.object(asm.urllib.request, "build_opener", return_value=FakeOpener()):
            response = asm.fetch_url(request, 5, context=object())

        self.assertEqual(response.status, 200)
        self.assertEqual(captured["timeout"], 5)


if __name__ == "__main__":
    unittest.main()
