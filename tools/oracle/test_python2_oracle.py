import json
import subprocess
import sys
import unittest
from pathlib import Path


ORACLE_DIR = Path(__file__).resolve().parent
REPO = ORACLE_DIR.parent.parent
FIXTURES = ORACLE_DIR / "fixtures" / "python2"
sys.path.insert(0, str(ORACLE_DIR))

from parity import compare_reports, failure_count  # noqa: E402


class Python2OracleTests(unittest.TestCase):
    def test_cli_matches_findings_captured_from_two_live_sonarqube_versions(self):
        subprocess.run(
            ["cargo", "build", "-q", "-p", "hoonarqube-cli"],
            cwd=REPO,
            check=True,
        )
        completed = subprocess.run(
            [
                str(REPO / "target" / "debug" / "hoonarqube"),
                "analyze",
                "--format",
                "json",
                str(FIXTURES / "source.py"),
                str(FIXTURES / "good.py"),
            ],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        )
        ours = json.loads(completed.stdout)
        sonar = json.loads((FIXTURES / "sonarqube.json").read_text())
        expected = [
            {
                "key": key,
                "bad": "source.py",
                "good": "good.py",
                "expect_lines_min": 1,
            }
            for key in (
                "python:ExecStatementUsage",
                "python:PrintStatementUsage",
                "python:BackticksUsage",
            )
        ]
        rows = compare_reports(expected, sonar, ours)
        self.assertEqual(failure_count(rows), 0, rows)
        self.assertEqual([row["status"] for row in rows], ["PASS", "PASS", "PASS"])


if __name__ == "__main__":
    unittest.main()
