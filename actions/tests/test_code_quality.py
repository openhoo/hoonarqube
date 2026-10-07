"""Execute the composite action's shell seam with controlled report output.

Run: python3 -m unittest discover -s actions/tests -v
Requires Bash 4+, jq, git and GNU realpath (as on supported Linux runners).
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ACTION = Path(__file__).resolve().parents[1] / "code-quality" / "action.yml"
SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "Hoonarqube", "rules": []}}, "results": []}],
}


def action_script():
    lines = ACTION.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line == "      run: |") + 1
    end = next((i for i in range(start, len(lines)) if lines[i].startswith("    - name:")), len(lines))
    return "\n".join(line[8:] for line in lines[start:end]) + "\n"


def runner_tools_available():
    if not all(shutil.which(tool) for tool in ("bash", "jq", "git", "realpath")):
        return False
    return subprocess.run(["realpath", "--version"], capture_output=True).returncode == 0


@unittest.skipUnless(runner_tools_available(), "Bash, jq, git and GNU realpath are required")
class CodeQualityReportContract(unittest.TestCase):
    def run_action(self, report, paths="src"):
        with tempfile.TemporaryDirectory(prefix="hoonarqube-action-test-") as directory:
            root = Path(directory).resolve()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "src").mkdir()
            report_source = root / "generated.json"
            report_source.write_text(report)
            output = root / "report.sarif"
            output.write_text("previous report")
            executable = root / "analyzer"
            executable.write_text('#!/bin/sh\ncat "$REPORT_SOURCE"\n')
            executable.chmod(0o700)
            env = dict(os.environ, INPUT_EXECUTABLE=str(executable), INPUT_FAIL_ON="none",
                       INPUT_CACHE_DIR="", INPUT_OUTPUT=str(output), INPUT_PATHS=paths,
                       INPUT_UPLOAD="false", GITHUB_OUTPUT=str(root / "outputs"),
                       REPORT_SOURCE=str(report_source))
            result = subprocess.run(["bash", "-c", action_script()], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=15)
            return result, output.read_text(), (root / "outputs").read_text() if (root / "outputs").exists() else ""

    def test_single_sarif_document_is_published(self):
        result, report, outputs = self.run_action(json.dumps(SARIF))
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(report), SARIF)
        self.assertIn("result-count=0", outputs)

    def test_multiple_sarif_documents_do_not_replace_existing_report(self):
        result, report, outputs = self.run_action(json.dumps(SARIF) + "\n" + json.dumps(SARIF))
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertEqual(report, "previous report")
        self.assertEqual(outputs, "")
        self.assertIn("failed SARIF validation", result.stdout)

    def test_invalid_sarif_document_does_not_replace_existing_report(self):
        result, report, outputs = self.run_action("{}")
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        self.assertEqual(report, "previous report")
        self.assertEqual(outputs, "")


if __name__ == "__main__":
    unittest.main()
