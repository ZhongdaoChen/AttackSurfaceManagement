import unittest


class DashboardAppTests(unittest.TestCase):
    def test_app_module_imports(self):
        import asm_dashboard.app as app

        self.assertTrue(callable(app.main))


if __name__ == "__main__":
    unittest.main()
