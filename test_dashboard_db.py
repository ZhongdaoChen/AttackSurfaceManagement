import datetime
import unittest

from asm_dashboard import db


class FakeCursor:
    def __init__(self, rows=None, count=0):
        self.executions = []
        self.rows = list(rows or [])
        self.count = count

    def execute(self, sql, params=None):
        self.executions.append((sql, params or {}))

    def fetchall(self):
        return self.rows

    def fetchone(self):
        if self.executions and "COUNT(*) AS count" in self.executions[-1][0]:
            return {"count": self.count}
        return self.rows[0] if self.rows else None


class FakeConnection:
    def __init__(self, rows=None, count=0):
        self.cursor_obj = FakeCursor(rows=rows, count=count)
        self.commits = 0

    def cursor(self):
        return self.cursor_obj

    def commit(self):
        self.commits += 1


class DashboardDbTests(unittest.TestCase):
    def test_fetch_latest_scan_orders_by_started_at_then_scan_id(self):
        connection = FakeConnection(rows=[{"scan_id": "scan-2", "started_at": "2026-08-14T10:00:00+08:00"}])

        row = db.fetch_latest_scan(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_scans", sql)
        self.assertIn("ORDER BY started_at DESC, scan_id DESC", sql)
        self.assertEqual(params, {})
        self.assertEqual(row["scan_id"], "scan-2")

    def test_fetch_current_findings_excludes_resolved_and_whitelisted_with_filters(self):
        connection = FakeConnection(rows=[{"finding_key": "key-1"}], count=1)
        filters = db.FilterState(
            risk_levels=["high"],
            ports=[443],
            cloud_platforms=["AWS"],
            cloud_accounts=["Account One"],
            check_ids=["llm_sensitive_content"],
            exposure_levels=["HIGH"],
            search="app.example.com",
            first_seen_start=datetime.date(2026, 8, 1),
            first_seen_end=datetime.date(2026, 8, 14),
        )

        result = db.fetch_current_findings(connection, filters, page=2, page_size=200)

        count_sql, count_params = connection.cursor_obj.executions[0]
        data_sql, data_params = connection.cursor_obj.executions[1]
        self.assertIn("resolved_at IS NULL", data_sql)
        self.assertIn("whitelisted = FALSE", data_sql)
        self.assertIn("risk_level = ANY(%(risk_levels)s)", data_sql)
        self.assertIn("port = ANY(%(ports)s)", data_sql)
        self.assertIn("cloud_platform = ANY(%(cloud_platforms)s)", data_sql)
        self.assertIn("cloud_account_name = ANY(%(cloud_accounts)s)", data_sql)
        self.assertIn("check_id = ANY(%(check_ids)s)", data_sql)
        self.assertIn("exposure_level = ANY(%(exposure_levels)s)", data_sql)
        self.assertIn("OFFSET %(offset)s", data_sql)
        self.assertIn("COUNT(*) AS count", count_sql)
        self.assertEqual(count_params["risk_levels"], ["high"])
        self.assertEqual(data_params["offset"], 200)
        self.assertEqual(result.total, 1)
        self.assertEqual(result.rows, [{"finding_key": "key-1"}])

    def test_fetch_historical_findings_uses_scan_started_date_and_includes_whitelisted(self):
        connection = FakeConnection(rows=[{"id": 1, "whitelisted": True}], count=1)

        result = db.fetch_historical_findings(
            connection,
            selected_date=datetime.date(2026, 8, 14),
            filters=db.FilterState(),
            page=1,
            page_size=200,
        )

        data_sql, data_params = connection.cursor_obj.executions[1]
        self.assertIn("JOIN asm_scans s ON s.scan_id = f.scan_id", data_sql)
        self.assertIn("s.started_at >= %(start_date)s", data_sql)
        self.assertIn("s.started_at < %(end_date)s", data_sql)
        self.assertNotIn("f.whitelisted = FALSE", data_sql)
        self.assertEqual(data_params["start_date"], datetime.date(2026, 8, 14))
        self.assertEqual(result.rows, [{"id": 1, "whitelisted": True}])

    def test_fetch_trend_rows_returns_active_high_and_cumulative_mitigated_by_scan(self):
        connection = FakeConnection(
            rows=[
                {
                    "scan_id": "scan-1",
                    "scan_started_at": "2026-08-14",
                    "active_high_count": 2,
                    "mitigated_count": 5,
                }
            ]
        )

        rows = db.fetch_trend_rows(connection)

        sql, params = connection.cursor_obj.executions[0]
        normalized_sql = " ".join(sql.split())
        # Scan window source.
        self.assertIn("FROM asm_scans", sql)
        self.assertIn("WHERE started_at >= %(trend_start)s", sql)
        self.assertIn("active_high_count", sql)
        self.assertIn("mitigated_count", sql)
        # The two metrics are aggregated independently per scan so the per-scan
        # findings join and the current-findings range join never multiply
        # into one row product (which spilled past temp_file_limit).
        self.assertNotIn("COUNT(DISTINCT", sql)
        self.assertIn("JOIN asm_findings active_f ON active_f.scan_id = s.scan_id", sql)
        self.assertIn("active_f.risk_level = 'high'", sql)
        self.assertIn("active_f.whitelisted = FALSE", sql)
        self.assertIn("active_f.whitelisted = TRUE", sql)
        self.assertIn("active_w.whitelist_effective_at > s.started_at", sql)
        self.assertIn("c.first_seen_at <= s.started_at", sql)
        self.assertIn("c.risk_level = 'high'", sql)
        self.assertIn("c.resolved_at <= s.started_at", sql)
        self.assertIn("w.whitelist_effective_at <= s.started_at", sql)
        # Rule effective scan time is derived once per rule, not per row.
        self.assertIn("asm_whitelist_rules r", sql)
        self.assertIn("s.started_at <= r.created_at", sql)
        self.assertIn("GROUP BY r.endpoint_name, COALESCE(r.port, -1)", sql)
        # Whitelist effective sources.
        self.assertIn("dashboard_whitelist_effective", sql)
        self.assertIn("c.whitelisted = TRUE", sql)
        self.assertIn("historical_whitelist_effective", sql)
        self.assertIn("JOIN asm_findings f", sql)
        self.assertIn("f.whitelisted = TRUE", sql)
        self.assertIn(
            "(fr.whitelist_effective_at IS NULL AND ffr.whitelist_effective_at IS NULL)",
            normalized_sql,
        )
        self.assertIn("ws.started_at >= fr.whitelist_effective_at", sql)
        self.assertIn("ws.started_at >= ffr.whitelist_effective_at", sql)
        self.assertIn("resolved_whitelist_effective", sql)
        self.assertIn("JOIN asm_scans rs ON rs.scan_id = c.resolved_scan_id", sql)
        self.assertIn("finding_rule_effective", sql)
        self.assertIn("asm_finding_whitelist_rules frule", sql)
        self.assertIn("frule.finding_key", sql)
        self.assertIn("finding_whitelist_effective", sql)
        self.assertIn("JOIN finding_rule_effective frule_effective", sql)
        self.assertIn("active_w.whitelist_effective_at > s.started_at", sql)
        self.assertIn("whitelist_effective", sql)
        self.assertIn("MIN(whitelist_effective_at)", sql)
        # Final join coalesces missing counts to zero.
        self.assertIn("COALESCE(a.active_high_count, 0)", sql)
        self.assertIn("COALESCE(m.mitigated_count, 0)", sql)
        self.assertIn("ORDER BY s.started_at ASC, s.scan_id ASC", sql)
        self.assertEqual(params, {"trend_start": db.EXPOSURE_TREND_START_DATE})
        self.assertEqual(
            rows,
            [
                {
                    "scan_id": "scan-1",
                    "scan_started_at": "2026-08-14",
                    "active_high_count": 2,
                    "mitigated_count": 5,
                }
            ],
        )

    def test_create_whitelist_rule_inserts_rule_and_backfills_current_and_history(self):
        connection = FakeConnection()

        db.create_whitelist_rule(
            connection,
            endpoint_name="https://app.example.com:443",
            port=443,
            reason="Business accepted",
            operator_name="Alice",
        )

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("INSERT INTO asm_whitelist_rules", executed_sql)
        self.assertIn("UPDATE asm_current_findings", executed_sql)
        self.assertIn("resolved_at = now()", executed_sql)
        self.assertIn("resolved_scan_id = (SELECT scan_id FROM latest_scan)", executed_sql)
        self.assertIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)

    def test_create_finding_whitelist_rule_inserts_rule_and_backfills_only_selected_finding(self):
        connection = FakeConnection()
        row = {
            "finding_key": "finding-key-1",
            "endpoint_id": "endpoint-1",
            "endpoint_name": "https://app.example.com:443",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
            "cloud_account_name": "Account One",
        }

        db.create_finding_whitelist_rule(
            connection,
            row=row,
            reason="Business accepted for this exact finding",
            operator_name="Alice",
        )

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        insert_sql, insert_params = connection.cursor_obj.executions[0]
        current_sql, current_params = connection.cursor_obj.executions[1]
        history_sql, history_params = connection.cursor_obj.executions[2]
        self.assertIn("INSERT INTO asm_finding_whitelist_rules", insert_sql)
        self.assertEqual(insert_params["finding_key"], "finding-key-1")
        self.assertEqual(insert_params["endpoint_name"], "https://app.example.com:443")
        self.assertEqual(insert_params["host"], "app.example.com")
        self.assertEqual(insert_params["port"], 443)
        self.assertEqual(insert_params["check_id"], "llm_sensitive_content")
        self.assertEqual(insert_params["cloud_account_name"], "Account One")
        self.assertIn("UPDATE asm_current_findings", current_sql)
        self.assertIn("WHERE finding_key = %(finding_key)s", current_sql)
        self.assertEqual(current_params["finding_key"], "finding-key-1")
        self.assertIn("UPDATE asm_findings", history_sql)
        self.assertIn("COALESCE(endpoint_id, '') = COALESCE(%(endpoint_id)s, '')", history_sql)
        self.assertIn("COALESCE(check_id, '') = COALESCE(%(check_id)s, '')", history_sql)
        self.assertIn("COALESCE(host, '') = COALESCE(%(host)s, '')", history_sql)
        self.assertIn("COALESCE(port, -1) = COALESCE(%(port)s, -1)", history_sql)
        self.assertNotIn("cloud_account_name = %(cloud_account_name)s", executed_sql)
        self.assertEqual(history_params["endpoint_id"], "endpoint-1")
        self.assertEqual(history_params["check_id"], "llm_sensitive_content")
        self.assertEqual(history_params["host"], "app.example.com")
        self.assertEqual(history_params["port"], 443)
        self.assertEqual(connection.commits, 1)

    def test_create_finding_whitelist_rule_requires_finding_key_reason_and_operator(self):
        connection = FakeConnection()
        valid_row = {
            "finding_key": "finding-key-1",
            "endpoint_id": "endpoint-1",
            "host": "app.example.com",
            "port": 443,
            "check_id": "llm_sensitive_content",
        }

        with self.assertRaisesRegex(ValueError, "finding_key is required"):
            db.create_finding_whitelist_rule(connection, row={**valid_row, "finding_key": " "}, reason="ok", operator_name="Alice")
        with self.assertRaisesRegex(ValueError, "reason is required"):
            db.create_finding_whitelist_rule(connection, row=valid_row, reason=" ", operator_name="Alice")
        with self.assertRaisesRegex(ValueError, "operator_name is required"):
            db.create_finding_whitelist_rule(connection, row=valid_row, reason="ok", operator_name=" ")
        self.assertEqual(connection.cursor_obj.executions, [])
        self.assertEqual(connection.commits, 0)

    def test_fetch_whitelist_rules_orders_active_first(self):
        connection = FakeConnection(rows=[{"id": 1, "active": True}])

        rows = db.fetch_whitelist_rules(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_whitelist_rules", sql)
        self.assertIn("ORDER BY active DESC, created_at DESC, id DESC", sql)
        self.assertEqual(params, {})
        self.assertEqual(rows, [{"id": 1, "active": True}])

    def test_fetch_finding_whitelist_rules_orders_active_first(self):
        connection = FakeConnection(rows=[{"id": 1, "finding_key": "finding-key-1", "active": True}])

        rows = db.fetch_finding_whitelist_rules(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_finding_whitelist_rules", sql)
        self.assertIn("ORDER BY active DESC, created_at DESC, id DESC", sql)
        self.assertEqual(params, {})
        self.assertEqual(rows, [{"id": 1, "finding_key": "finding-key-1", "active": True}])

    def test_deactivate_whitelist_rule_only_updates_rule_metadata(self):
        connection = FakeConnection()

        db.deactivate_whitelist_rule(connection, rule_id=7, operator_name="Alice", reason="Expired exception")

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("UPDATE asm_whitelist_rules", executed_sql)
        self.assertNotIn("UPDATE asm_current_findings", executed_sql)
        self.assertNotIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)

    def test_deactivate_finding_whitelist_rule_only_updates_rule_metadata(self):
        connection = FakeConnection()

        db.deactivate_finding_whitelist_rule(connection, rule_id=7, operator_name="Alice", reason="Expired exception")

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("UPDATE asm_finding_whitelist_rules", executed_sql)
        self.assertNotIn("UPDATE asm_current_findings", executed_sql)
        self.assertNotIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)


if __name__ == "__main__":
    unittest.main()
