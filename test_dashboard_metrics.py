import datetime
import unittest

from asm_dashboard import metrics


class DashboardMetricsTests(unittest.TestCase):
    def test_current_kpis_counts_ciso_metrics(self):
        rows = [
            {
                "finding_key": "a",
                "risk_level": "high",
                "first_seen_scan_id": "scan-2",
                "check_id": "llm_sensitive_content",
                "port": 443,
            },
            {
                "finding_key": "b",
                "risk_level": "low",
                "first_seen_scan_id": "scan-1",
                "check_id": "non_standard_open_port",
                "port": 9200,
            },
            {
                "finding_key": "c",
                "risk_level": "medium",
                "first_seen_scan_id": "scan-2",
                "check_id": "llm_sensitive_content",
                "port": 8080,
            },
        ]

        result = metrics.current_kpis(rows, latest_scan_id="scan-2", resolved_this_quarter=4)

        self.assertEqual(result["active_findings"], 3)
        self.assertEqual(result["active_high"], 1)
        self.assertEqual(result["new_latest_scan"], 2)
        self.assertEqual(result["resolved_this_quarter"], 4)
        self.assertEqual(result["sensitive_exposure_80_443"], 1)
        self.assertEqual(result["current_non_standard_ports"], 1)

    def test_endpoint_link_returns_markdown_link_only_for_http_urls(self):
        self.assertEqual(
            metrics.endpoint_link("https://app.example.com"),
            "[https://app.example.com](https://app.example.com)",
        )
        self.assertEqual(metrics.endpoint_link("app.example.com"), "app.example.com")
        self.assertEqual(metrics.endpoint_link(None), "")

    def test_markdown_link_escapes_visible_label_without_changing_url(self):
        self.assertEqual(
            metrics.markdown_link("https://app.example.com/path_(test)", "https://app.example.com/path_(test)"),
            "[https://app.example.com/path_\\(test\\)](https://app.example.com/path_(test))",
        )
        self.assertEqual(metrics.markdown_link("Wiz Link", ""), "")

    def test_wiz_link_uses_fixed_visible_text(self):
        self.assertEqual(
            metrics.wiz_link("https://app.wiz.io/example"),
            "[Wiz Link](https://app.wiz.io/example)",
        )
        self.assertEqual(metrics.wiz_link(None), "")

    def test_distribution_counts_top_values(self):
        rows = [{"risk_level": "high"}, {"risk_level": "high"}, {"risk_level": "low"}, {"risk_level": None}]

        frame = metrics.distribution(rows, "risk_level")

        self.assertEqual(frame.to_dict("records"), [{"risk_level": "high", "count": 2}, {"risk_level": "low", "count": 1}])

    def test_trend_frame_builds_high_risk_stock_and_resolved_high_risk_lines(self):
        rows = [
            {
                "first_seen_at": datetime.datetime(2026, 8, 12, 10, 0),
                "resolved_at": None,
                "risk_level": "high",
                "check_id": "llm_sensitive_content",
                "port": 443,
            },
            {
                "first_seen_at": "2026-08-13T12:00:00+08:00",
                "resolved_at": "2026-08-14T12:00:00+08:00",
                "risk_level": "high",
                "check_id": "non_standard_open_port",
                "port": 9200,
            },
            {
                "first_seen_at": "2026-08-13T12:00:00+08:00",
                "resolved_at": "2026-08-14T12:00:00+08:00",
                "risk_level": "low",
                "check_id": "non_standard_open_port",
                "port": 9200,
            },
            {
                "first_seen_at": "2026-08-12T12:00:00+08:00",
                "resolved_at": None,
                "risk_level": "high",
                "check_id": "llm_sensitive_content",
                "port": 443,
                "whitelisted": True,
            },
        ]

        frame = metrics.trend_frame(rows)

        records = sorted(frame.to_dict("records"), key=lambda item: (str(item["date"]), item["metric"]))
        self.assertEqual(
            records,
            [
                {"date": datetime.date(2026, 8, 12), "metric": "High Risk", "count": 1},
                {"date": datetime.date(2026, 8, 12), "metric": "Resolved High Risk", "count": 0},
                {"date": datetime.date(2026, 8, 13), "metric": "High Risk", "count": 2},
                {"date": datetime.date(2026, 8, 13), "metric": "Resolved High Risk", "count": 0},
                {"date": datetime.date(2026, 8, 14), "metric": "High Risk", "count": 1},
                {"date": datetime.date(2026, 8, 14), "metric": "Resolved High Risk", "count": 1},
            ],
        )


if __name__ == "__main__":
    unittest.main()
