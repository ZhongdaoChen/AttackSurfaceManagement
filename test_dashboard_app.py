import os
import subprocess
import sys
import unittest


class DashboardAppTests(unittest.TestCase):
    def test_app_module_imports(self):
        import asm_dashboard.app as app

        self.assertTrue(callable(app.main))

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
