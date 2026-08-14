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

        result = metrics.current_kpis(rows, latest_scan_id="scan-2", resolved_latest_scan=4)

        self.assertEqual(result["active_findings"], 3)
        self.assertEqual(result["active_high"], 1)
        self.assertEqual(result["new_latest_scan"], 2)
        self.assertEqual(result["resolved_latest_scan"], 4)
        self.assertEqual(result["sensitive_exposure_80_443"], 1)
        self.assertEqual(result["current_non_standard_ports"], 1)

    def test_endpoint_link_returns_markdown_link_only_for_http_urls(self):
        self.assertEqual(
            metrics.endpoint_link("https://app.example.com"),
            "[https://app.example.com](https://app.example.com)",
        )
        self.assertEqual(metrics.endpoint_link("app.example.com"), "app.example.com")
        self.assertEqual(metrics.endpoint_link(None), "")

    def test_distribution_counts_top_values(self):
        rows = [{"risk_level": "high"}, {"risk_level": "high"}, {"risk_level": "low"}, {"risk_level": None}]

        frame = metrics.distribution(rows, "risk_level")

        self.assertEqual(frame.to_dict("records"), [{"risk_level": "high", "count": 2}, {"risk_level": "low", "count": 1}])

    def test_trend_frame_groups_new_resolved_and_key_security_metrics(self):
        rows = [
            {
                "first_seen_at": datetime.datetime(2026, 8, 13, 10, 0),
                "resolved_at": None,
                "risk_level": "high",
                "check_id": "llm_sensitive_content",
                "port": 443,
            },
            {
                "first_seen_at": "2026-08-13T12:00:00+08:00",
                "resolved_at": "2026-08-14T12:00:00+08:00",
                "risk_level": "low",
                "check_id": "non_standard_open_port",
                "port": 9200,
            },
        ]

        frame = metrics.trend_frame(rows)

        records = sorted(frame.to_dict("records"), key=lambda item: (str(item["date"]), item["metric"]))
        self.assertIn({"date": datetime.date(2026, 8, 13), "metric": "New", "count": 2}, records)
        self.assertIn({"date": datetime.date(2026, 8, 13), "metric": "New High", "count": 1}, records)
        self.assertIn({"date": datetime.date(2026, 8, 13), "metric": "Sensitive Exposure 80/443", "count": 1}, records)
        self.assertIn({"date": datetime.date(2026, 8, 13), "metric": "Non-standard Port", "count": 1}, records)
        self.assertIn({"date": datetime.date(2026, 8, 14), "metric": "Resolved", "count": 1}, records)


if __name__ == "__main__":
    unittest.main()
