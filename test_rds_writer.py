import json
import os
import unittest
from pathlib import Path
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

    def test_schema_defines_current_findings_table(self):
        schema = Path("schema.sql").read_text(encoding="utf-8")

        self.assertIn("CREATE TABLE IF NOT EXISTS asm_current_findings", schema)
        self.assertIn("finding_key TEXT PRIMARY KEY", schema)
        self.assertIn("first_seen_scan_id TEXT NOT NULL REFERENCES asm_scans(scan_id)", schema)
        self.assertIn("last_seen_scan_id TEXT NOT NULL REFERENCES asm_scans(scan_id)", schema)
        self.assertIn("seen_count INTEGER NOT NULL DEFAULT 1", schema)
        self.assertIn("resolved_at TIMESTAMPTZ", schema)
        self.assertIn("resolved_scan_id TEXT REFERENCES asm_scans(scan_id)", schema)
        self.assertIn("idx_asm_current_findings_active", schema)
        self.assertIn("idx_asm_current_findings_resolved_at", schema)

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

    def test_connect_missing_psycopg_points_to_requirements_install(self):
        def fake_import(name, *args, **kwargs):
            if name == "psycopg":
                raise ImportError("No module named 'psycopg'")
            return original_import(name, *args, **kwargs)

        original_import = __import__

        with patch("builtins.__import__", side_effect=fake_import):
            with self.assertRaisesRegex(RuntimeError, "pip3 install -r requirements.txt"):
                rds_writer.connect()


if __name__ == "__main__":
    unittest.main()
