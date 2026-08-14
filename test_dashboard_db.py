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
        self.assertIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)

    def test_fetch_whitelist_rules_orders_active_first(self):
        connection = FakeConnection(rows=[{"id": 1, "active": True}])

        rows = db.fetch_whitelist_rules(connection)

        sql, params = connection.cursor_obj.executions[0]
        self.assertIn("FROM asm_whitelist_rules", sql)
        self.assertIn("ORDER BY active DESC, created_at DESC, id DESC", sql)
        self.assertEqual(params, {})
        self.assertEqual(rows, [{"id": 1, "active": True}])

    def test_deactivate_whitelist_rule_only_updates_rule_metadata(self):
        connection = FakeConnection()

        db.deactivate_whitelist_rule(connection, rule_id=7, operator_name="Alice", reason="Expired exception")

        executed_sql = "\n".join(sql for sql, _params in connection.cursor_obj.executions)
        self.assertIn("UPDATE asm_whitelist_rules", executed_sql)
        self.assertNotIn("UPDATE asm_current_findings", executed_sql)
        self.assertNotIn("UPDATE asm_findings", executed_sql)
        self.assertEqual(connection.commits, 1)


if __name__ == "__main__":
    unittest.main()
