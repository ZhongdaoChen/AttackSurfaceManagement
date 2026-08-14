import os
import subprocess
import sys
import unittest
from pathlib import Path

import pandas as pd


class DashboardAppTests(unittest.TestCase):
    def test_app_module_imports(self):
        import asm_dashboard.app as app

        self.assertTrue(callable(app.main))

    def test_whitelist_rules_page_does_not_use_streamlit_dataframe(self):
        source = Path("asm_dashboard/app.py").read_text(encoding="utf-8")
        start = source.index("def whitelist_rules_page")
        end = source.index("\n\ndef main", start)
        body = source[start:end]

        self.assertNotIn("st.dataframe", body)

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
            "tag_emails": ["owner@example.com", "security@example.com"],
        }

        records = app.table_records([row])

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["Expand"], "View")
        self.assertEqual(records[0]["Endpoint Name"], "http://consumer-uat.adidas.com.cn:80/membership/adidas/cn")
        self.assertEqual(records[0]["Endpoint URL"], "http://consumer-uat.adidas.com.cn:80/membership/adidas/cn")
        self.assertEqual(records[0]["Wiz Link"], "https://app.wiz.io/example")
        self.assertEqual(records[0]["Subscription Account Owner"], "owner@example.com, security@example.com")
        self.assertNotIn("[", records[0]["Endpoint Name"])

    def test_subscription_account_owner_handles_missing_tag_emails(self):
        import asm_dashboard.app as app

        self.assertEqual(app.subscription_account_owner({}), "")
        self.assertEqual(app.subscription_account_owner({"tag_emails": "owner@example.com"}), "owner@example.com")

    def test_display_date_only_removes_time(self):
        import asm_dashboard.app as app

        self.assertEqual(app.display_date_only("2026-08-14T10:00:00+08:00"), "2026-08-14")
        self.assertEqual(app.display_date_only("2026-08-14 10:00:00"), "2026-08-14")
        self.assertEqual(app.display_date_only(None), "")

    def test_finding_row_model_uses_expand_button_and_row_detail_key(self):
        import asm_dashboard.app as app

        row = {
            "finding_key": "finding-1",
            "endpoint_name": "https://app.example.com",
            "wiz_link": "https://app.wiz.io/example",
        }

        model = app.finding_row_model(row, page_key="current_page", index=3)

        self.assertEqual(model["expand_key"], "expand_current_page_finding-1")
        self.assertEqual(model["expanded_state_key"], "expanded_current_page")
        self.assertEqual(model["identity"], "finding-1")
        self.assertEqual(model["endpoint_label"], "https://app.example.com")
        self.assertEqual(model["endpoint_url"], "https://app.example.com")
        self.assertEqual(model["wiz_label"], "Wiz Link")
        self.assertEqual(model["wiz_url"], "https://app.wiz.io/example")

    def test_expand_icon_uses_right_and_down_triangles(self):
        import asm_dashboard.app as app

        self.assertEqual(app.expand_icon(expanded=False), "▶")
        self.assertEqual(app.expand_icon(expanded=True), "▼")

    def test_table_scroll_height_targets_about_one_hundred_rows(self):
        import asm_dashboard.app as app

        self.assertGreaterEqual(app.TABLE_SCROLL_HEIGHT, 4800)
        self.assertLessEqual(app.TABLE_SCROLL_HEIGHT, 5600)

    def test_row_detail_json_expands_by_default(self):
        import asm_dashboard.app as app

        self.assertTrue(app.ROW_DETAIL_JSON_EXPANDED)

    def test_kpi_labels_include_resolved_this_quarter(self):
        import asm_dashboard.app as app

        labels = [label for label, _key in app.KPI_LABELS]

        self.assertIn("Active Attack Surface", labels)
        self.assertNotIn("Active Findings", labels)
        self.assertIn("Newly Identified This Month", labels)
        self.assertNotIn("New Latest Scan", labels)
        self.assertIn("Resolved This Quarter", labels)
        self.assertNotIn("Resolved Latest Scan", labels)

    def test_active_high_kpi_style_is_red_and_bold(self):
        import asm_dashboard.app as app

        self.assertEqual(app.KPI_STYLES["active_high"], {"color": "#d62728", "font_weight": "700"})

    def test_exposure_trend_title_and_color(self):
        import asm_dashboard.app as app

        self.assertEqual(app.EXPOSURE_TREND_TITLE, "Exposure Trend")
        self.assertEqual(app.EXPOSURE_TREND_COLORS["High Risk"], "#d62728")
        self.assertEqual(app.EXPOSURE_TREND_COLORS["Mitigated"], "#1f77b4")

    def test_exposure_trend_uses_separate_y_axes(self):
        import asm_dashboard.app as app

        trend = pd.DataFrame(
            [
                {"date": "2026-08-14", "scan_id": "scan-1", "metric": "High Risk", "count": 120},
                {"date": "2026-08-14", "scan_id": "scan-1", "metric": "Mitigated", "count": 3},
            ]
        )

        figure = app.exposure_trend_figure(trend)
        axes = {trace.name: getattr(trace, "yaxis", "y") for trace in figure.data}

        self.assertEqual(axes["Mitigated"], "y")
        self.assertEqual(axes["High Risk"], "y2")
        self.assertEqual(figure.layout.yaxis.title.text, "Mitigated")
        self.assertEqual(figure.layout.yaxis2.title.text, "High Risk")

    def test_chart_section_divider_separates_kpis_from_trends(self):
        import asm_dashboard.app as app

        self.assertIn("border-top", app.CHART_SECTION_DIVIDER_HTML)
        self.assertIn("margin: 2rem 0 1.5rem 0", app.CHART_SECTION_DIVIDER_HTML)
        self.assertIn("width: 100%", app.CHART_SECTION_DIVIDER_HTML)

    def test_evidence_cell_html_clamps_to_two_lines(self):
        import asm_dashboard.app as app

        html = app.evidence_cell_html("line one line two line three")

        self.assertIn("-webkit-line-clamp: 2", html)
        self.assertIn("overflow: hidden", html)
        self.assertIn("line one line two line three", html)

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
