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
                "first_seen_at": "2026-08-10T10:00:00+08:00",
                "check_id": "llm_sensitive_content",
                "port": 443,
            },
            {
                "finding_key": "b",
                "risk_level": "low",
                "first_seen_scan_id": "scan-1",
                "first_seen_at": "2026-07-31T10:00:00+08:00",
                "check_id": "non_standard_open_port",
                "port": 9200,
            },
            {
                "finding_key": "low-sensitive-port",
                "risk_level": "low",
                "first_seen_scan_id": "scan-2",
                "first_seen_at": "2026-08-11T10:00:00+08:00",
                "check_id": "llm_sensitive_content",
                "port": 443,
            },
            {
                "finding_key": "c",
                "risk_level": "high",
                "first_seen_scan_id": "scan-2",
                "first_seen_at": "2026-07-20T10:00:00+08:00",
                "check_id": "llm_sensitive_content",
                "port": 8080,
            },
        ]

        result = metrics.current_kpis(
            rows,
            newly_identified_since=datetime.date(2026, 8, 1),
            resolved_this_quarter=4,
        )

        self.assertEqual(result["active_findings"], 4)
        self.assertEqual(result["active_high"], 2)
        self.assertEqual(result["newly_identified_this_month"], 2)
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

    def test_trend_frame_uses_scan_dates_and_high_risk_counts(self):
        rows = [
            {"scan_id": "scan-1", "scan_started_at": datetime.datetime(2026, 8, 12, 10, 0), "high_risk_count": 2},
            {"scan_id": "scan-2", "scan_started_at": "2026-08-13T12:00:00+08:00", "high_risk_count": 5},
        ]

        frame = metrics.trend_frame(rows)

        self.assertEqual(
            frame.to_dict("records"),
            [
                {"date": datetime.date(2026, 8, 12), "scan_id": "scan-1", "metric": "High Risk", "count": 2},
                {"date": datetime.date(2026, 8, 13), "scan_id": "scan-2", "metric": "High Risk", "count": 5},
            ],
        )


if __name__ == "__main__":
    unittest.main()
