import json
import tempfile
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

import diff
import parity_suite
from reference_provenance import manifest_digest


class DiffArtifactValidationTests(unittest.TestCase):
    @staticmethod
    def _manifest(kind):
        manifest = {
            "schema_version": 1,
            "project": "oracle-py",
            "kind": kind,
            "repository": {"commit": "0" * 40},
            "inputs": {
                "input_sha256": "current",
                "source_root": "src",
                "expected": "expected",
                "catalog": "catalog",
            },
            "server": {"url": parity_suite.SONAR_URL},
            "profile": {},
            "plugins": [],
            "tools": {
                "scanner_image": "scanner",
                **(
                    {
                        "hoonarqube_executable": {
                            "path": "target/debug/hoonarqube",
                            "size": 1,
                            "sha256": "native",
                        }
                    }
                    if kind == "ours"
                    else {}
                ),
            },
        }
        manifest["manifest_sha256"] = manifest_digest(manifest)
        return manifest

    def test_stale_or_missing_artifact_evidence_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "oracle-py"
            project.mkdir()
            (project / "expected.jsonl").write_text("", encoding="utf-8")
            sonar = project / "sonar.json"
            sonar.write_text(
                '{"schema_version": 2, "project": "oracle-py", "issues": [], '
                '"oracle_evidence": {"project": "oracle-py", "kind": "sq", '
                '"input_sha256": "current"}}',
                encoding="utf-8",
            )
            ours = project / "ours.json"
            ours.write_text(
                '{"schema_version": 2, "project": "oracle-py", "files": [], '
                '"oracle_evidence": {"project": "oracle-py", "kind": "sq", '
                '"input_sha256": "current"}}',
                encoding="utf-8",
            )

            with (
                mock.patch.object(
                    parity_suite, "artifact_input_sha256", return_value="current"
                ),
                self.assertRaisesRegex(ValueError, "stale or mismatched"),
            ):
                diff.main("py", project, sonar, ours)

    def test_valid_sq_and_ours_evidence_reaches_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "oracle-py"
            project.mkdir()
            (project / "expected.jsonl").write_text("", encoding="utf-8")
            sonar = project / "sonar.json"
            ours = project / "ours.json"
            sonar_report = {
                "schema_version": 2,
                "project": "oracle-py",
                "issues": [],
            }
            ours_report = {
                "schema_version": 2,
                "project": "oracle-py",
                "files": [],
            }
            output = project / "diff.json"

            with (
                mock.patch.object(
                    parity_suite, "artifact_input_sha256", return_value="current"
                ) as fingerprint,
                mock.patch.object(diff, "compare_reports", return_value=[]) as compare,
            ):
                parity_suite.attach_artifact_evidence(sonar_report, "oracle-py", "sq")
                parity_suite.attach_artifact_evidence(ours_report, "oracle-py", "ours")
                for report, kind in ((sonar_report, "sq"), (ours_report, "ours")):
                    manifest = self._manifest(kind)
                    report["oracle_provenance"] = manifest
                    report["oracle_evidence"]["provenance_sha256"] = manifest[
                        "manifest_sha256"
                    ]
                sonar.write_text(json.dumps(sonar_report), encoding="utf-8")
                ours.write_text(json.dumps(ours_report), encoding="utf-8")
                self.assertEqual(diff.main("py", project, sonar, ours, output), 0)

            compare.assert_called_once()
            self.assertEqual(
                fingerprint.call_args_list[-2:],
                [
                    mock.call("oracle-py", "sq", project_dir=project.resolve()),
                    mock.call("oracle-py", "ours", project_dir=project.resolve()),
                ],
            )
            self.assertEqual(json.loads(output.read_text(encoding="utf-8")), [])

    def test_stale_sonar_evidence_is_rejected_before_comparison(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "oracle-py"
            project.mkdir()
            (project / "expected.jsonl").write_text("", encoding="utf-8")
            report = project / "report.json"
            report.write_text(
                '{"schema_version": 2, "project": "oracle-py", "issues": [], '
                '"oracle_evidence": {"project": "oracle-py", "kind": "sq", '
                '"input_sha256": "old"}}',
                encoding="utf-8",
            )

            with (
                mock.patch.object(
                    parity_suite, "artifact_input_sha256", return_value="current"
                ),
                self.assertRaisesRegex(ValueError, "stale or mismatched"),
            ):
                diff.main("py", project, report, report)

    def test_parameter_context_mismatch_is_rejected(self):
        from reference_provenance import validate_compatible_manifests

        sonar = {"oracle_provenance": self._manifest("sq")}
        ours = {"oracle_provenance": self._manifest("ours")}
        sonar["oracle_provenance"]["parameters"] = {
            "kind": "sq",
            "scanner_image": "scanner-a",
        }
        ours["oracle_provenance"]["parameters"] = {
            "kind": "ours",
            "scanner_image": "scanner-b",
        }
        with self.assertRaisesRegex(ValueError, "parameters"):
            validate_compatible_manifests(sonar, ours)


if __name__ == "__main__":
    unittest.main()
