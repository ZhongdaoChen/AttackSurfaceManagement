import os
import subprocess
import sys
import unittest


class DashboardAppTests(unittest.TestCase):
    def test_app_module_imports(self):
        import asm_dashboard.app as app

        self.assertTrue(callable(app.main))

    def test_table_records_include_expand_raw_endpoint_and_link_urls(self):
        import asm_dashboard.app as app

        row = {
            "endpoint_name": "http://consumer-uat.adidas.com.cn:80/membership/adidas/cn",
            "port": 80,
            "cloud_platform": "AWS",
            "cloud_account_name": "Account One",
            "risk_level": "high",
            "evidence": "Sensitive data exposed",
            "first_seen_at": "2026-08-14T10:00:00+08:00",
            "wiz_link": "https://app.wiz.io/example",
        }

        records = app.table_records([row])

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Expand"], "View")
        self.assertEqual(records[0]["Endpoint Name"], "http://consumer-uat.adidas.com.cn:80/membership/adidas/cn")
        self.assertEqual(records[0]["Endpoint URL"], "http://consumer-uat.adidas.com.cn:80/membership/adidas/cn")
        self.assertEqual(records[0]["Wiz Link"], "https://app.wiz.io/example")
        self.assertNotIn("[", records[0]["Endpoint Name"])

    def test_kpi_labels_include_resolved_this_quarter(self):
        import asm_dashboard.app as app

        labels = [label for label, _key in app.KPI_LABELS]

        self.assertIn("Resolved This Quarter", labels)
        self.assertNotIn("Resolved Latest Scan", labels)

    def test_app_file_path_execution_can_import_dashboard_package(self):
        env = os.environ.copy()
        env.pop("DASHBOARD_PASSWORD", None)
        result = subprocess.run(
            [sys.executable, "asm_dashboard/app.py"],
            check=False,
            cwd=os.path.dirname(__file__) or ".",
            env=env,
            capture_output=True,
            text=True,
        )

        self.assertNotIn("ModuleNotFoundError: No module named 'asm_dashboard'", result.stderr)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
