import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import parity_suite


class ParitySuiteFailClosedTests(unittest.TestCase):
    def test_missing_generic_scanner_fails_closed(self):
        with (
            mock.patch.dict(parity_suite.os.environ, {}, clear=True),
            mock.patch.object(parity_suite.shutil, "which", return_value=None),
        ):
            self.assertFalse(parity_suite.scan_project("oracle-py"))

    def test_csharp_native_workspace_is_scan_base_and_bypasses_gitignore(self):
        output = Path("/tmp/native-csharp-test")
        with mock.patch.object(parity_suite, "SONAR_URL", "http://sonar.test"):
            command = parity_suite.csharp_begin_command(
                "/scanner", "oracle-cs", output, "/d:sonar.login=token"
            )

        self.assertIn(f"/d:sonar.projectBaseDir={output}", command)
        self.assertIn("/d:sonar.scm.exclusions.disabled=true", command)
        self.assertIn("/d:sonar.host.url=http://sonar.test", command)

    def test_csharp_failed_native_build_fails_closed_after_scanner_end(self):
        completed = lambda code, output="": mock.Mock(
            returncode=code, stdout=output, stderr=""
        )
        with (
            mock.patch.dict(
                parity_suite.os.environ,
                {"SONAR_DOTNET_SCANNER": "/scanner"},
                clear=True,
            ),
            mock.patch.object(parity_suite.Path, "is_file", return_value=True),
            mock.patch.object(parity_suite.shutil, "which", return_value="/dotnet"),
            mock.patch.object(parity_suite, "oracle_token", return_value="token"),
            mock.patch.object(parity_suite, "sq_api", return_value={"version": "9.9.8"}),
            mock.patch.object(
                parity_suite,
                "generate_solution",
                return_value=(Path("Oracle.slnx"), 1),
            ),
            mock.patch.object(
                parity_suite.subprocess,
                "run",
                side_effect=[completed(0), completed(1, "compiler error"), completed(0)],
            ) as run,
        ):
            self.assertFalse(parity_suite.scan_csharp_project("oracle-cs"))

        self.assertEqual(run.call_count, 3)
        self.assertEqual(run.call_args_list[-1].args[0][1], "end")

    def test_result_tag_keeps_server_artifacts_separate(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(parity_suite, "RESULTS", Path(directory)),
            mock.patch.object(parity_suite, "RESULT_TAG", "frozen-2025_4"),
        ):
            self.assertEqual(
                parity_suite.result_path("oracle-py", "sq").name,
                "oracle-py.frozen-2025_4.sq.json",
            )

    def test_failed_oracle_scan_fails_gate_without_using_stale_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            argv = ["parity_suite.py", "--project", "oracle-py"]
            with (
                mock.patch.object(parity_suite, "RESULTS", results),
                mock.patch.object(parity_suite, "ensure_container"),
                mock.patch.object(parity_suite, "scan_project", return_value=False),
                mock.patch.object(sys, "argv", argv),
                self.assertRaises(SystemExit) as raised,
            ):
                parity_suite.main()

            self.assertEqual(raised.exception.code, 1)
            report = json.loads(
                (results / "parity_divergences.oracle-py.json").read_text()
            )
            self.assertEqual(
                report["invalid_artifacts"], {"oracle-py": "oracle scan failed"}
            )
            self.assertEqual(report["summary"], {})
            self.assertEqual(report["failure_count"], 1)


if __name__ == "__main__":
    unittest.main()
