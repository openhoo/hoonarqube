import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


class PrepareUploadTests(unittest.TestCase):
    def run_cli(self, data):
        with tempfile.TemporaryDirectory() as work:
            report = Path(work) / "report.json"
            report.write_bytes(data)
            return subprocess.run(
                [
                    sys.executable,
                    Path(__file__).with_name("prepare_analysis_upload.py"),
                    "--report",
                    report,
                    "--branch",
                    'feature/"küche"',
                    "--commit",
                    "abc",
                    "--analyzed-at",
                    "2026-11-23T00:00:00Z",
                ],
                capture_output=True,
            )

    def test_keeps_native_bytes_and_escapes_metadata(self):
        report = (
            b'{"schema_version":1,"files":[],"project":{},"a":9.5864661654135330}\n'
        )
        result = self.run_cli(report)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'"report":' + report, result.stdout)
        self.assertEqual(json.loads(result.stdout)["branch"], 'feature/"küche"')

    def test_limit_includes_envelope_and_emits_nothing_on_refusal(self):
        report = b'{"schema_version":1,"files":[],"project":{}}'
        first = self.run_cli(report)
        self.assertEqual(first.returncode, 0, first.stderr)
        limit = 16 * 1024 * 1024
        remaining = limit - len(first.stdout)
        exact = self.run_cli(report + b" " * remaining)
        self.assertEqual(exact.returncode, 0, exact.stderr)
        self.assertEqual(len(exact.stdout), limit)
        beyond = self.run_cli(report + b" " * (remaining + 1))
        self.assertEqual((beyond.returncode, beyond.stdout), (2, b""))
        self.assertIn(b"16 MiB", beyond.stderr)

    def test_malformed_or_nonreport_input_is_not_embedded(self):
        for raw in (b'{},"other":1', b"[]", b'{"report":{}}', b"\xff"):
            with self.subTest(raw=raw):
                result = self.run_cli(raw)
                self.assertEqual((result.returncode, result.stdout), (2, b""))


if __name__ == "__main__":
    unittest.main()
