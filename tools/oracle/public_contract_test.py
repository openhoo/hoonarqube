"""The contract must fail when an input or an occurrence moves."""

from copy import deepcopy
import hashlib
from pathlib import Path
import tempfile
import unittest

from public_contract import canonical_sha, compare, git, stage, validate
from public_contract_capture import js_sensor


class ContractTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.tmp = Path(directory.name)
        self.source = self.tmp / "source"
        self.source.mkdir()
        text = "first\r😀abcd\u2028xyz\n"
        (self.source / "sample.js").write_text(text)
        files = {"sample.js": hashlib.sha256(text.encode()).hexdigest()}
        self.case = {
            "repository": "example/project",
            "commit": "1" * 40,
            "tree": "2" * 40,
            "sources": ["sample.js"],
            "exclude": [],
            "files": files,
            "source_inventory_sha256": canonical_sha(files),
            "parameters": {"javascript:S100": {"threshold": "1"}},
            "semantic_context": {"typescript": "missing"},
            "primaries": [["javascript:S100", "sample.js", 2, 2, 2, 4]],
        }
        self.issue = {
            "rule_key": "javascript:S100",
            "message": "example",
            "range": {
                "start": {"line": 2, "column": 1},
                "end": {"line": 2, "column": 3},
            },
        }
        self.report = {
            "files": [
                {"path": "sample.js", "language": "javascript", "issues": [self.issue]}
            ],
            "project": {
                "complete": True,
                "files": [
                    {
                        "path": "sample.js",
                        "status": "complete",
                        "classification": "source",
                    }
                ],
            },
            "parity": {
                "reference": {"profile": "sonar-parity"},
                "scope": {"roots": ["sample.js"], "exclude": []},
                "rule_set_violations": [],
                "semantic_context": self.case["semantic_context"],
                "active_rules": [
                    {
                        "key": "javascript:S100",
                        "parameters": [{"key": "threshold", "default_value": "1"}],
                    }
                ],
            },
        }

    def test_unicode_offsets_and_javascript_line_boundaries(self):
        validate(self.case)
        compare(self.case, self.report, self.source)
        self.issue["range"] = {
            "start": {"line": 3, "column": 0},
            "end": {"line": 3, "column": 2},
        }
        self.case["primaries"][0][2:] = [3, 0, 3, 2]
        compare(self.case, self.report, self.source)

    def test_wrong_commit_tree_and_source_bytes(self):
        git(self.source, "init", "--quiet", "--template=")
        git(self.source, "add", "--", "sample.js")
        git(
            self.source,
            "-c",
            "user.name=fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        )
        self.case["commit"] = git(self.source, "rev-parse", "HEAD").decode().strip()
        self.case["tree"] = (
            git(self.source, "rev-parse", "HEAD^{tree}").decode().strip()
        )
        for field, reason in [
            ("commit", "wrong commit"),
            ("tree", "wrong tree"),
            ("files", "wrong source bytes"),
        ]:
            with self.subTest(field=field):
                case = deepcopy(self.case)
                if field == "files":
                    case[field]["sample.js"] = "0" * 64
                else:
                    case[field] = "0" * 40
                scratch = self.tmp / field
                scratch.mkdir()
                with self.assertRaisesRegex(ValueError, reason):
                    stage(case, scratch, self.source)
        scratch = self.tmp / "correct"
        scratch.mkdir()
        materialized = stage(self.case, scratch, self.source)
        self.assertEqual(
            (materialized / "sample.js").read_bytes(),
            (self.source / "sample.js").read_bytes(),
        )
        self.assertFalse((materialized / ".git").exists())

    def test_scope_includes_only_regular_pinned_documents(self):
        for path in [
            "../outside.js",
            "node_modules/../../outside.js",
            "-config.js",
            "package.json",
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate({**self.case, "files": {path: "0" * 64}})
        with self.assertRaisesRegex(ValueError, "outside analysis roots"):
            validate({**self.case, "sources": ["lib"]})
        with self.assertRaisesRegex(ValueError, "inventory digest"):
            validate({**self.case, "source_inventory_sha256": "0" * 64})

    def test_native_scope_and_number_of_paths(self):
        for field in ["files", "project"]:
            with self.subTest(field=field):
                report = deepcopy(self.report)
                rows = (
                    report["files"] if field == "files" else report["project"]["files"]
                )
                rows.append(rows[0])
                with self.assertRaisesRegex(ValueError, "file inventory mismatch"):
                    compare(self.case, report, self.source)
        self.report["parity"]["scope"]["exclude"] = ["**/*"]
        with self.assertRaisesRegex(ValueError, "wrong effective scope"):
            compare(self.case, self.report, self.source)

    def test_wrong_parameters_and_inactive_rule(self):
        for rules in [
            [],
            [
                {
                    "key": "javascript:S100",
                    "parameters": [{"key": "threshold", "default_value": "2"}],
                }
            ],
        ]:
            with self.subTest(rules=rules):
                self.report["parity"]["active_rules"] = rules
                with self.assertRaisesRegex(ValueError, "rule parameters"):
                    compare(self.case, self.report, self.source)

    def test_shifted_missing_and_duplicate_primaries(self):
        shifted = deepcopy(self.issue)
        shifted["range"]["start"]["column"] = 2
        for issues in [[shifted], [], [self.issue, self.issue]]:
            with self.subTest(issues=issues):
                self.report["files"][0]["issues"] = issues
                with self.assertRaisesRegex(ValueError, "primary mismatch"):
                    compare(self.case, self.report, self.source)

    def test_js_counts_belong_to_actual_sensor(self):
        sensor = "Sensor JavaScript/TypeScript/CSS analysis [javascript]"
        good = f"{sensor}\nINFO 1/1 source file has been analyzed\n{sensor} (done)"
        self.assertEqual(js_sensor(good, 1), 1)
        for log in [
            good + "\n" + good,
            "1/1 source file has been analyzed\n" + good.replace("1/1", "0/1"),
            good + "\nautomatically excluded because they looked like generated code",
        ]:
            with self.subTest(log=log), self.assertRaises(ValueError):
                js_sensor(log, 1)


if __name__ == "__main__":
    unittest.main()
