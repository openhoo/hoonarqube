"""Execute Generic Issue action validation, path parsing and severity gates."""
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ACTION = Path(__file__).resolve().parents[1] / "analyze" / "action.yml"
SONAR = {
    "rules": [{"id": "python:S100", "name": "Function names", "description": "Naming",
               "engineId": "hoonarqube", "severity": "MAJOR", "type": "CODE_SMELL",
               "cleanCodeAttribute": "CONVENTIONAL",
               "impacts": [{"softwareQuality": "MAINTAINABILITY", "severity": "MEDIUM"}]}],
    "issues": [{"ruleId": "python:S100", "primaryLocation": {
        "message": "Rename function", "filePath": "src/example.py", "textRange": {
            "startLine": 1, "startColumn": 0, "endLine": 1, "endColumn": 3}}}],
}


def action_script():
    lines = ACTION.read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line == "      run: |") + 1
    return "\n".join(line[8:] for line in lines[start:]) + "\n"


@unittest.skipUnless(all(shutil.which(tool) for tool in ("bash", "jq", "git")),
                     "Bash 4+, jq and git required")
class AnalyzeReportContract(unittest.TestCase):
    def run_action(self, report, paths="src", threshold="none", analyzer_status=0):
        with tempfile.TemporaryDirectory(prefix="hoonarqube-analyze-test-") as directory:
            root = Path(directory).resolve()
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            generated = root / "generated.json"
            generated.write_text(report if isinstance(report, str) else json.dumps(report))
            output = root / "report.json"
            output.write_text("previous report")
            executable = root / "analyzer"
            executable.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$ARGUMENTS"\n'
                                  'cat "$REPORT_SOURCE"\nexit "$ANALYZER_STATUS"\n')
            executable.chmod(0o700)
            env = dict(os.environ, INPUT_EXECUTABLE=str(executable), INPUT_FAIL_ON=threshold,
                       INPUT_CACHE_DIR="", INPUT_OUTPUT=str(output), INPUT_PATHS=paths,
                       INPUT_PROFILE="sonar-parity", INPUT_GO_HEADER_FORMAT="",
                       GITHUB_OUTPUT=str(root / "outputs"), REPORT_SOURCE=str(generated),
                       ARGUMENTS=str(root / "arguments"), ANALYZER_STATUS=str(analyzer_status))
            result = subprocess.run(["bash", "-c", action_script()], cwd=root, env=env,
                                    capture_output=True, text=True, timeout=15)
            return (result, output.read_text(),
                    (root / "outputs").read_text() if (root / "outputs").exists() else "",
                    (root / "arguments").read_bytes() if (root / "arguments").exists() else b"")

    def assert_refused(self, report):
        result, output, outputs, _ = self.run_action(report, threshold="major")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(output, "previous report")
        self.assertEqual(outputs, "")
        self.assertIn("failed validation", result.stdout)

    def test_unknown_rule_cannot_bypass_threshold(self):
        report = copy.deepcopy(SONAR)
        report["issues"][0]["ruleId"] = "missing"
        self.assert_refused(report)

    def test_invalid_severity_cannot_bypass_threshold(self):
        report = copy.deepcopy(SONAR)
        report["rules"][0]["severity"] = "UNKNOWN"
        self.assert_refused(report)

    def test_crlf_paths_are_literal_normalized_arguments(self):
        result, _, _, arguments = self.run_action(SONAR, paths="src dir\r\n-leading.py\r\n")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(arguments.splitlines(), [b"analyze", b"--format", b"sonar", b"--",
                                                b"src dir", b"-leading.py"])
        self.assertNotIn(b"\r", arguments)

    def test_valid_report_gates_major_and_preserves_output(self):
        result, output, outputs, _ = self.run_action(SONAR, threshold="major")
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(json.loads(output), SONAR)
        self.assertIn("blocking-findings=1", outputs)

    def test_valid_minor_threshold_does_not_block_info(self):
        report = copy.deepcopy(SONAR)
        report["rules"][0]["severity"] = "INFO"
        result, output, outputs, _ = self.run_action(report, threshold="minor")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(output), report)
        self.assertIn("blocking-findings=0", outputs)

    def test_clean_report_publishes(self):
        result, output, outputs, _ = self.run_action({"rules": [], "issues": []}, threshold="info")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(output), {"rules": [], "issues": []})
        self.assertIn("blocking-findings=0", outputs)

    def test_duplicate_rules_are_refused(self):
        report = copy.deepcopy(SONAR)
        report["rules"] *= 2
        self.assert_refused(report)

    def test_invalid_locations_are_refused(self):
        for field, value in (("filePath", ""), ("message", None), ("textRange", None)):
            with self.subTest(field=field):
                report = copy.deepcopy(SONAR)
                report["issues"][0]["primaryLocation"][field] = value
                self.assert_refused(report)

    def test_invalid_ranges_are_refused(self):
        for field, value in (("startLine", 0), ("startColumn", -1), ("endLine", 0),
                             ("endColumn", 0), ("startLine", 1.5)):
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(SONAR)
                report["issues"][0]["primaryLocation"]["textRange"][field] = value
                if field == "endColumn":
                    report["issues"][0]["primaryLocation"]["textRange"]["startColumn"] = 1
                self.assert_refused(report)

    def test_file_level_and_secondary_locations_remain_supported(self):
        report = copy.deepcopy(SONAR)
        del report["issues"][0]["primaryLocation"]["textRange"]
        report["issues"][0]["secondaryLocations"] = [{"message": "Related", "filePath": "src/other.py"}]
        result, output, _, _ = self.run_action(report)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(output), report)

    def test_invalid_secondary_location_is_refused(self):
        report = copy.deepcopy(SONAR)
        report["issues"][0]["secondaryLocations"] = [{"message": "Related", "filePath": ""}]
        self.assert_refused(report)

    def test_concatenated_documents_are_refused(self):
        self.assert_refused(json.dumps(SONAR) + "\n" + json.dumps(SONAR))

    def test_incomplete_analysis_still_exits_nonzero_with_valid_report(self):
        result, output, outputs, _ = self.run_action(SONAR, analyzer_status=2)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(json.loads(output), SONAR)
        self.assertIn("blocking-findings=0", outputs)

    def test_empty_paths_refuse_before_invocation(self):
        result, output, outputs, arguments = self.run_action(SONAR, paths=" \r\n\t\n")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(output, "previous report")
        self.assertEqual(outputs, "")
        self.assertEqual(arguments, b"")


if __name__ == "__main__":
    unittest.main()
