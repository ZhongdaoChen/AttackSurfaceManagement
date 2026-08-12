import json
import os
import unittest
from pathlib import Path
from unittest.mock import patch
from io import StringIO

import rds_writer


class FakeCursor:
    def __init__(self, rowcounts=None, result_rows=None):
        self.executions = []
        self.rowcounts = list(rowcounts or [])
        self.result_rows = list(result_rows or [])
        self.rowcount = 1

    def execute(self, sql, params=None):
        self.executions.append((sql, params))
        self.rowcount = self.rowcounts.pop(0) if self.rowcounts else 1

    def fetchall(self):
        return self.result_rows


class FakeConnection:
    def __init__(self, rowcounts=None, result_rows=None):
        self.cursor_obj = FakeCursor(rowcounts=rowcounts, result_rows=result_rows)
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

    def test_connection_info_builds_psycopg_style_string_with_required_keys(self):
        # Ensure connection_info produces a space-separated key=value string
        # containing host, port, dbname, user, password and sslmode when env vars are set.
        env = {
            "RDS_HOST": "db.example.local",
            "RDS_DB": "exampledb",
            "RDS_USER": "dbuser",
            "RDS_PASSWORD": "secret-pass",
            # leave RDS_PORT and RDS_SSLMODE unset to exercise defaults
        }
        with patch.dict(os.environ, env, clear=True):
            info = rds_writer.connection_info()

        # Do not print or reveal the password value. Instead assert the
        # presence of the password key and that its value is non-empty.
        self.assertIn("host=db.example.local", info)
        self.assertIn("dbname=exampledb", info)
        self.assertIn("user=dbuser", info)
        self.assertIn("port=5432", info)  # default port
        self.assertIn("sslmode=prefer", info)  # default sslmode
        # password key must be present and have a value
        self.assertIn("password=", info)
        # ensure password= isn't the trailing token with empty value
        # extract password fragment without printing it
        pw_frag = [part for part in info.split() if part.startswith("password=")]
        self.assertTrue(pw_frag)
        self.assertTrue(len(pw_frag[0]) > len("password="))

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

    def test_finding_key_normalizes_missing_identity_fields(self):
        params = {
            "endpoint_id": None,
            "check_id": "non_standard_open_port",
            "host": "app.example.com",
            "port": None,
        }

        self.assertEqual(
            rds_writer.finding_key(params),
            "b06cee14e86c6a218c0ca7e38685382993f39a45102177928aa51091a62d47f6",
        )

    def test_finding_insert_params_include_current_finding_key(self):
        finding = {
            "endpoint_id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
            "details": {"status": 200},
        }

        params = rds_writer.finding_insert_params(finding, "scan-1", {"fdp"})

        self.assertEqual(
            params["finding_key"],
            "b3926d5be171d88300a90e163ae33299566eb55df61039e1cacdadf1c89c74e6",
        )
        self.assertEqual(params["scan_id"], "scan-1")
        self.assertEqual(params["endpoint_id"], "endpoint-1")
        self.assertEqual(params["http_status"], "200")

    def test_finding_insert_params_strip_nul_bytes_from_postgres_text_values(self):
        finding = {
            "endpoint_id": "endpoint-\x001",
            "endpoint_name": "https://app.example.com:443\x00",
            "host": "app.example.com",
            "port": 443,
            "cloudPlatform": "AWS",
            "cloudAccountName": "Account\x00 One",
            "tagEmails": ["owner\x00@example.com"],
            "check_id": "llm_sensitive_content",
            "risk_level": "high",
            "evidence": "secret\x00value",
            "recommendation": "remove\x00secret",
            "http_response": "title\x00text",
            "llm_opinion": "reason\x00text",
            "details": {"status": 200, "title": "bad\x00title", "items": ["a\x00b"]},
        }

        params = rds_writer.finding_insert_params(finding, "scan-1", {"fdp"})

        for key, value in params.items():
            if isinstance(value, str):
                self.assertNotIn("\x00", value, key)
            elif isinstance(value, list):
                for item in value:
                    self.assertNotIn("\x00", item, key)
        self.assertNotIn("\\u0000", params["details"])
        self.assertNotIn("\\u0000", params["raw"])
        self.assertEqual(params["endpoint_id"], "endpoint-1")
        self.assertEqual(params["tag_emails"], ["owner@example.com"])

    def test_writer_upserts_current_finding_after_history_insert(self):
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

        current_sql, current_params = connection.cursor_obj.executions[2]
        self.assertIn("INSERT INTO asm_current_findings", current_sql)
        self.assertIn("ON CONFLICT (finding_key) DO UPDATE", current_sql)
        self.assertIn("seen_count = asm_current_findings.seen_count + 1", current_sql)
        self.assertIn("resolved_at = NULL", current_sql)
        self.assertEqual(current_params["scan_id"], "scan-1")
        self.assertEqual(current_params["started_at"], "2026-08-12T10:00:00+08:00")
        self.assertEqual(current_params["finding_key"], "b3926d5be171d88300a90e163ae33299566eb55df61039e1cacdadf1c89c74e6")

    def test_new_high_risk_findings_queries_current_scan_active_highs(self):
        connection = FakeConnection(result_rows=[{"endpoint_name": "https://app.example.com:9200"}])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        rows = writer.new_high_risk_findings()

        query_sql, query_params = connection.cursor_obj.executions[1]
        self.assertIn("FROM asm_current_findings", query_sql)
        self.assertIn("first_seen_scan_id = %(scan_id)s", query_sql)
        self.assertIn("risk_level = 'high'", query_sql)
        self.assertIn("resolved_at IS NULL", query_sql)
        self.assertEqual(query_params["scan_id"], "scan-1")
        self.assertEqual(rows, [{"endpoint_name": "https://app.example.com:9200"}])

    def test_notify_new_high_risks_skips_when_webhook_url_missing(self):
        connection = FakeConnection(result_rows=[{"endpoint_name": "https://app.example.com:9200"}])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        with patch.dict(os.environ, {}, clear=True), patch.object(rds_writer, "post_teams_webhook") as post:
            writer.notify_new_high_risks()

        post.assert_not_called()

    def test_notify_new_high_risks_posts_card_when_rows_exist(self):
        row = {
            "endpoint_name": "https://app.example.com:9200",
            "wiz_link": "https://app.wiz.io/example",
            "host": "app.example.com",
            "port": 9200,
            "cloud_account_name": "Account One",
            "check_id": "non_standard_open_port",
            "evidence": "Open port.",
            "recommendation": "Close it.",
            "first_seen_scan_id": "scan-1",
            "first_seen_at": "2026-08-12T11:20:00+08:00",
        }
        connection = FakeConnection(result_rows=[row])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        with patch.dict(os.environ, {"TEAMS_WEBHOOK_URL": "https://teams.example/webhook"}, clear=True), patch.object(rds_writer, "post_teams_webhook") as post:
            writer.notify_new_high_risks()

        post.assert_called_once()
        self.assertEqual(post.call_args.args[0], "https://teams.example/webhook")
        self.assertEqual(post.call_args.args[1]["type"], "AdaptiveCard")

    def test_finalize_logs_teams_failure_without_raising(self):
        connection = FakeConnection(result_rows=[{"endpoint_name": "https://app.example.com:9200"}])
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-1",
            started_at="2026-08-12T11:20:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )
        stderr = StringIO()

        with (
            patch.dict(os.environ, {"TEAMS_WEBHOOK_URL": "https://teams.example/webhook"}, clear=True),
            patch.object(rds_writer, "post_teams_webhook", side_effect=RuntimeError("boom")),
            patch("sys.stderr", stderr),
        ):
            writer.finalize()

        self.assertIn("Teams notification failed: RuntimeError: boom", stderr.getvalue())

    def test_writer_skips_current_upsert_when_history_insert_conflicts(self):
        connection = FakeConnection(rowcounts=[1, 0])
        finding = {
            "endpoint_id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
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

        executed_sql = [sql for sql, _params in connection.cursor_obj.executions]
        self.assertEqual(len(executed_sql), 2)
        self.assertIn("INSERT INTO asm_findings", executed_sql[1])
        self.assertNotIn("asm_current_findings", "\n".join(executed_sql))

    def test_finalize_marks_findings_missing_from_current_scan_as_resolved(self):
        connection = FakeConnection()
        writer = rds_writer.RdsFindingWriter(
            connection,
            scan_id="scan-2",
            started_at="2026-08-12T11:00:00+08:00",
            source_file="scan.jsonl",
            low_risk_subscriptions={"fdp"},
        )

        writer.finalize()

        finalize_sql, finalize_params = connection.cursor_obj.executions[1]
        self.assertIn("UPDATE asm_current_findings", finalize_sql)
        self.assertIn("last_seen_scan_id <> %(scan_id)s", finalize_sql)
        self.assertIn("resolved_at IS NULL", finalize_sql)
        self.assertEqual(finalize_params["scan_id"], "scan-2")
        self.assertEqual(finalize_params["resolved_at"], "2026-08-12T11:00:00+08:00")
        self.assertEqual(connection.commits, 2)

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

    def test_build_teams_high_risk_card_uses_top_level_adaptive_card(self):
        findings = [
            {
                "endpoint_name": "https://app.example.com:9200",
                "wiz_link": "https://app.wiz.io/example",
                "host": "app.example.com",
                "port": 9200,
                "cloud_account_name": "Account One",
                "check_id": "non_standard_open_port",
                "evidence": "Open non-standard internet-facing port 9200.",
                "recommendation": "Close or restrict the port.",
                "first_seen_scan_id": "scan-1",
                "first_seen_at": "2026-08-12T11:20:00+08:00",
            }
        ]

        card = rds_writer.build_teams_high_risk_card("scan-1", findings)

        self.assertEqual(card["type"], "AdaptiveCard")
        self.assertEqual(card["version"], "1.4")
        self.assertEqual(card["body"][0]["text"], "ASM 新增 High Risk 告警")
        self.assertIn("本次扫描发现 1 个新增 High Risk endpoint。", card["body"][1]["text"])
        self.assertEqual(card["actions"][0]["type"], "Action.OpenUrl")
        self.assertEqual(card["actions"][0]["url"], "https://app.wiz.io/example")

    def test_build_teams_high_risk_card_limits_and_truncates_findings(self):
        long_text = "x" * 350
        findings = [
            {
                "endpoint_name": f"https://app-{index}.example.com:9200",
                "host": f"app-{index}.example.com",
                "port": 9200,
                "cloud_account_name": "Account One",
                "check_id": "non_standard_open_port",
                "evidence": long_text,
                "recommendation": long_text,
                "first_seen_scan_id": "scan-1",
                "first_seen_at": "2026-08-12T11:20:00+08:00",
            }
            for index in range(11)
        ]

        card = rds_writer.build_teams_high_risk_card("scan-1", findings)

        self.assertIn("仅展示前 10 个", card["body"][1]["text"])
        finding_titles = [block for block in card["body"] if block.get("weight") == "Bolder" and block.get("separator")]
        self.assertEqual(len(finding_titles), 10)
        fact_sets = [block for block in card["body"] if block.get("type") == "FactSet"]
        evidence_fact = fact_sets[1]["facts"][4]
        self.assertEqual(evidence_fact["title"], "Evidence")
        self.assertTrue(evidence_fact["value"].endswith("..."))
        self.assertLessEqual(len(evidence_fact["value"]), 300)


    def test_build_teams_high_risk_card_omits_actions_when_no_wiz_link(self):
        # Case 1: wiz_link present but empty
        findings_empty = [
            {
                "endpoint_name": "https://app.example.com:9200",
                "wiz_link": "",
                "host": "app.example.com",
                "port": 9200,
                "cloud_account_name": "Account One",
                "check_id": "non_standard_open_port",
                "evidence": "Open non-standard internet-facing port 9200.",
                "recommendation": "Close or restrict the port.",
                "first_seen_scan_id": "scan-1",
                "first_seen_at": "2026-08-12T11:20:00+08:00",
            }
        ]

        card_empty = rds_writer.build_teams_high_risk_card("scan-1", findings_empty)
        # When the first displayed finding has no wiz_link (empty), the top-level actions key should be omitted
        self.assertNotIn("actions", card_empty)

        # Case 2: wiz_link key missing entirely
        findings_missing = [
            {
                "endpoint_name": "https://app.example.com:9200",
                "host": "app.example.com",
                "port": 9200,
                "cloud_account_name": "Account One",
                "check_id": "non_standard_open_port",
                "evidence": "Open non-standard internet-facing port 9200.",
                "recommendation": "Close or restrict the port.",
                "first_seen_scan_id": "scan-1",
                "first_seen_at": "2026-08-12T11:20:00+08:00",
            }
        ]

        card_missing = rds_writer.build_teams_high_risk_card("scan-1", findings_missing)
        self.assertNotIn("actions", card_missing)


if __name__ == "__main__":
    unittest.main()
