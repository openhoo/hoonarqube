"""Controls for real-project evidence: multiplicity, ranges and completeness."""

from collections import Counter
import unittest
import json
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch

from real_project_suite import (
    comparison,
    native_identities,
    sonar_identities,
    normalized_path,
    run,
)
from real_project_suite import verify_reference_scope, verify_reference_files, digest


class ComparisonTests(unittest.TestCase):
    def test_file_metrics_preserve_scope_and_measure_differences(self):
        from real_project_suite import file_metric_comparison

        native = [
            {
                "path": "./a.js",
                "metrics": {"lines": 5, "code_lines": 2, "comment_lines": 1},
            },
            {"path": "extra.js", "metrics": {}},
        ]
        reference = [
            {
                "path": "a.js",
                "measures": [
                    {"metric": "ncloc", "value": "3"},
                    {"metric": "lines", "value": "5"},
                ],
            },
            {"path": "missing.js", "measures": []},
        ]
        result = file_metric_comparison(native, reference)
        self.assertEqual(result["matched_files"], 1)
        self.assertEqual(result["matched_cells"], 1)
        self.assertEqual(result["native_only"], ["extra.js"])
        self.assertEqual(result["reference_only"], ["missing.js"])
        self.assertEqual(result["differences"][0]["path"], "a.js")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            file_metric_comparison(native, reference + [reference[0]])

    def test_metric_comparison_preserves_missing_and_different_measures(self):
        from real_project_suite import metric_comparison

        result = metric_comparison(
            {"files": 2, "lines": 10, "code_lines": 6, "comment_lines": 3},
            [{"metric": "files", "value": "2"}, {"metric": "ncloc", "value": "7"}],
        )
        self.assertEqual(
            result,
            {
                "files": {"native": 2, "reference": 2, "matched": True},
                "ncloc": {"native": 6, "reference": 7, "matched": False},
            },
        )

    def test_offline_replay_rejects_changed_scope_without_rewriting_reference(self):
        row = {
            "name": "p",
            "commit": "abc",
            "project_key": "p",
            "sources": ["src"],
            "exclude": ["tests/**"],
            "language": "js",
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "source.json"
            original = json.dumps(row)
            manifest.write_text(original)
            verify_reference_scope(row, root)
            for field, value in [
                ("commit", "def"),
                ("sources", ["."]),
                ("exclude", []),
                ("project_key", "other"),
            ]:
                with (
                    self.subTest(field=field),
                    self.assertRaisesRegex(ValueError, field),
                ):
                    verify_reference_scope({**row, field: value}, root)
            self.assertEqual(manifest.read_text(), original)

    def test_offline_replay_checks_source_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "a.js"
            source.write_text("const a = [];")
            (root / "reference-source-files.json").write_text(
                json.dumps([{"path": "a.js", "sha256": digest(source)}])
            )
            verify_reference_files(root, root)
            source.write_text("const a = [1];")
            with self.assertRaisesRegex(ValueError, "content mismatch"):
                verify_reference_files(root, root)

    def test_timeout_keeps_partial_streams_and_never_records_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            failure = subprocess.TimeoutExpired(
                ["scanner"], 1800, output=b"partial", stderr=b"failed"
            )
            with (
                patch("real_project_suite.subprocess.run", side_effect=failure),
                self.assertRaisesRegex(RuntimeError, "timed out"),
            ):
                run(["scanner"], root, "scanner", root)
            self.assertEqual((root / "scanner.stdout").read_text(), "partial")
            self.assertEqual((root / "scanner.stderr").read_text(), "failed")
            receipt = json.loads((root / "scanner-execution.json").read_text())
            self.assertEqual(receipt["status"], "timed_out")
            self.assertIsNone(receipt["exit_code"])

    def test_dot_prefix_and_separator_normalization(self):
        self.assertEqual(normalized_path("./lib/./a.js"), "lib/a.js")
        self.assertEqual(normalized_path(".\\lib\\a.js"), "lib/a.js")

    def test_paths_cannot_escape_project(self):
        for path in ("../a.js", "/a.js", "lib/../../a.js"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                normalized_path(path)

    def test_duplicate_findings_are_not_collapsed(self):
        identity = ("javascript:S4158", "lib/a.js", 3, 0, 3, 6)
        result = comparison(Counter({identity: 2}), Counter({identity: 1}))
        self.assertEqual(
            (result["matched"], result["native_only"], result["reference_only"]),
            (1, 1, 0),
        )
        self.assertEqual(result["inventory"][0]["native"], 2)

    def test_column_mismatch_remains_a_difference(self):
        native = Counter({("python:S4790", "a.py", 1, 0, 1, 8): 1})
        reference = Counter({("python:S4790", "a.py", 1, 1, 1, 8): 1})
        result = comparison(native, reference)
        self.assertEqual(result["matched"], 0)
        self.assertEqual(result["native_only"], 1)
        self.assertEqual(result["reference_only"], 1)

    def test_incomplete_native_report_cannot_be_clean(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            native_identities(
                {"schema_version": 1, "files": [], "project": {"complete": False}}
            )

    def test_missing_completeness_is_not_success(self):
        with self.assertRaisesRegex(ValueError, "incomplete"):
            native_identities({"schema_version": 1, "files": [], "project": {}})

    def test_foreign_project_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "foreign"):
            sonar_identities([{"rule": "go:S100", "component": "other:a.go"}], "p")

    def test_file_level_sonar_issue_has_no_fabricated_range(self):
        result = sonar_identities([{"rule": "go:S100", "component": "p:a.go"}], "p")
        self.assertEqual(
            result, Counter({("go:S100", "a.go", None, None, None, None): 1})
        )

    def test_complete_native_retains_exact_range(self):
        report = {
            "schema_version": 1,
            "project": {"complete": True},
            "files": [
                {
                    "path": "a.py",
                    "issues": [
                        {
                            "rule_key": "python:S4790",
                            "range": {
                                "start": {"line": 2, "column": 3},
                                "end": {"line": 2, "column": 9},
                            },
                        }
                    ],
                }
            ],
        }
        self.assertEqual(
            native_identities(report),
            Counter({("python:S4790", "a.py", 2, 3, 2, 9): 1}),
        )


if __name__ == "__main__":
    unittest.main()
