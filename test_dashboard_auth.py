import os
import unittest
from unittest.mock import patch

from asm_dashboard import auth


class DashboardAuthTests(unittest.TestCase):
    def test_password_configured_requires_non_empty_env_value(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(auth.password_configured())
        with patch.dict(os.environ, {"DASHBOARD_PASSWORD": "  "}, clear=True):
            self.assertFalse(auth.password_configured())
        with patch.dict(os.environ, {"DASHBOARD_PASSWORD": "secret"}, clear=True):
            self.assertTrue(auth.password_configured())

    def test_password_matches_uses_constant_time_comparison(self):
        with patch.dict(os.environ, {"DASHBOARD_PASSWORD": "secret"}, clear=True):
            self.assertTrue(auth.password_matches("secret"))
            self.assertFalse(auth.password_matches("wrong"))
            self.assertFalse(auth.password_matches(None))


if __name__ == "__main__":
    unittest.main()
