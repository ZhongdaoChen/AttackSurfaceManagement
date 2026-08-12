import json
import os
import unittest
from unittest.mock import patch

import rds_writer


class FakeCursor:
    def __init__(self):
        self.executions = []

    def execute(self, sql, params=None):
        self.executions.append((sql, params))


class FakeConnection:
    def __init__(self):
        self.cursor_obj = FakeCursor()
        self.commits = 0
        self.closed = False

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


class RdsWriterTests(unittest.TestCase):
    def test_configured_from_env_requires_core_variables(self):
        with patch.dict(os.environ, {"RDS_HOST": "h", "RDS_DB": "d", "RDS_USER": "u", "RDS_PASSWORD": "p"}, clear=True):
            self.assertTrue(rds_writer.rds_configured())

        with patch.dict(os.environ, {"RDS_HOST": "h"}, clear=True):
            self.assertFalse(rds_writer.rds_configured())

    def test_whitelisted_uses_subscription_detail(self):
        finding = {"details": {"subscription": "FDP"}}

        self.assertTrue(rds_writer.is_whitelisted_finding(finding, {"fdp"}))

    def test_writer_inserts_scan_and_finding_rows(self):
        connection = FakeConnection()
        finding = {
            "endpoint_id": "endpoint-1",
            "endpoint_name": "https://app.example.com:443",
            "host": "app.example.com",
            "port": 443,
            "cloudPlatform": "AWS",
            "cloudAccountName": "Account One",
            "tagEmails": ["owner@example.com"],
            "exposureLevel": "HIGH",
            "check_id": "llm_sensitive_content",
            "risk_level": "low",
            "evidence": "No sensitive content",
            "recommendation": "Keep monitoring.",
            "wiz_link": "https://app.wiz.io/example",
            "http_response": "No sensitive content",
            "llm_opinion": "No sensitive content Keep monitoring.",
            "details": {"status": 200},
        }

        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T10:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )
        writer.write(finding)
        writer.close()

        self.assertEqual(connection.commits, 2)
        self.assertTrue(connection.closed)
        scan_sql, scan_params = connection.cursor_obj.executions[0]
        finding_sql, finding_params = connection.cursor_obj.executions[1]
        self.assertIn("INSERT INTO asm_scans", scan_sql)
        self.assertEqual(scan_params["scan_id"], "scan-1")
        self.assertIn("INSERT INTO asm_findings", finding_sql)
        self.assertEqual(finding_params["endpoint_id"], "endpoint-1")
        self.assertEqual(finding_params["wiz_link"], "https://app.wiz.io/example")
        self.assertEqual(finding_params["http_response"], "No sensitive content")
        self.assertEqual(finding_params["llm_opinion"], "No sensitive content Keep monitoring.")
        self.assertEqual(finding_params["tag_emails"], ["owner@example.com"])
        self.assertEqual(finding_params["details"], json.dumps({"status": 200}, ensure_ascii=False))
        self.assertEqual(finding_params["raw"], json.dumps(finding, ensure_ascii=False))
        self.assertFalse(finding_params["whitelisted"])


if __name__ == "__main__":
    unittest.main()
