import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

import rust_clippy
from unittest import mock

REPO = Path(__file__).resolve().parent.parent.parent
PROJECT = REPO / ".oracle/sonar/projects/oracle-rust"


class RustClippyOracleTests(unittest.TestCase):
    @staticmethod
    def _materializer_project(
        directory: str,
        rows: list[dict[str, object]],
        sources: dict[str, str],
    ) -> Path:
        project = Path(directory)
        source_dir = project / "src"
        source_dir.mkdir(parents=True)
        (project / "Cargo.toml").write_text(
            (PROJECT / "Cargo.toml").read_text(), encoding="utf-8"
        )
        (project / "Cargo.lock").write_bytes((PROJECT / "Cargo.lock").read_bytes())
        (project / "expected.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )
        for name, content in sources.items():
            path = source_dir / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        return project

    def test_materializer_compiles_cross_fixture_good_and_native_controls(self):
        rows = [
            {"key": "rust:S106", "bad": "s106_bad.rs", "good": "s106_good.rs"},
            {"key": "rust:S3776", "bad": "s3776_bad.rs", "good": "s3776_good.rs"},
        ]
        sources = {
            name: "fn main() {}\n"
            for name in (
                "s106_bad.rs",
                "s106_good.rs",
                "s3776_bad.rs",
                "s3776_good.rs",
            )
        }
        with tempfile.TemporaryDirectory() as directory:
            project = self._materializer_project(directory, rows, sources)
            rust_clippy.materialize_rust_project(project, rows)

            main = (project / rust_clippy.MATERIALIZED_MAIN).read_text()
            self.assertIn('#[path = "s106_bad.rs"] mod s106_bad;', main)
            self.assertIn('#[path = "s106_good.rs"] mod s106_good;', main)
            self.assertIn('#[path = "s3776_bad.rs"] mod s3776_bad;', main)
            self.assertIn('#[path = "s3776_good.rs"] mod s3776_good;', main)

            inventory = json.loads(
                (project / rust_clippy.MATERIALIZED_INVENTORY).read_text()
            )
            compiled = {
                (row["key"], row["role"], row["path"]) for row in inventory["compiled"]
            }
            self.assertTrue(
                {
                    ("rust:S106", "good", "src/s106_good.rs"),
                    ("rust:S3776", "bad", "src/s3776_bad.rs"),
                    ("rust:S3776", "good", "src/s3776_good.rs"),
                }
                <= compiled
            )

    def test_materializer_preserves_malformed_s2260_and_records_frontend_exclusion(
        self,
    ):
        rows = [{"key": "rust:S2260", "bad": "s2260_bad.rs", "good": "s2260_good.rs"}]
        sources = {
            "s2260_bad.rs": "placeholder\n",
            "s2260_good.rs": "fn main() {}\n",
        }
        malformed = b"fn broken( {\n\nfn main() {}\n"
        with tempfile.TemporaryDirectory() as directory:
            project = self._materializer_project(directory, rows, sources)
            bad = project / "src/s2260_bad.rs"
            bad.write_bytes(malformed)
            lock_before = (project / "Cargo.lock").read_bytes()

            rust_clippy.materialize_rust_project(project, rows)

            self.assertEqual(bad.read_bytes(), malformed)
            self.assertEqual((project / "Cargo.lock").read_bytes(), lock_before)
            main = (project / rust_clippy.MATERIALIZED_MAIN).read_text()
            self.assertNotIn("s2260_bad.rs", main)
            self.assertIn('#[path = "s2260_good.rs"] mod s2260_good;', main)
            inventory = json.loads(
                (project / rust_clippy.MATERIALIZED_INVENTORY).read_text()
            )
            self.assertEqual(
                inventory["excluded"],
                [
                    {
                        "fixture": "s2260_bad.rs",
                        "key": "rust:S2260",
                        "path": "src/s2260_bad.rs",
                        "reason": rust_clippy.FRONTEND_ONLY_REASON,
                        "role": "bad",
                    }
                ],
            )

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_materializer_rejects_missing_escaping_and_symlink_sources(self):
        cases = (
            (
                "missing",
                "s106_good.rs",
                {"s106_bad.rs": "fn main() {}\n"},
                "does not exist",
            ),
            (
                "escape",
                "../outside.rs",
                {"s106_bad.rs": "fn main() {}\n"},
                "escapes source root",
            ),
            (
                "symlink",
                "s106_good.rs",
                {
                    "s106_bad.rs": "fn main() {}\n",
                    "s106_good.rs": "fn main() {}\n",
                    "s106_target.rs": "fn main() {}\n",
                },
                "symlink",
            ),
        )
        for label, good_name, sources, error_text in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                rows = [
                    {
                        "key": "rust:S106",
                        "bad": "s106_bad.rs",
                        "good": good_name,
                    }
                ]
                project = self._materializer_project(directory, rows, sources)
                if label == "symlink":
                    good = project / "src/s106_good.rs"
                    good.unlink()
                    good.symlink_to(project / "src/s106_target.rs")
                with self.assertRaisesRegex(RuntimeError, error_text):
                    rust_clippy.materialize_rust_project(project, rows)

    def test_generate_report_materializes_after_pair_validation(self):
        rows = [{"key": "rust:S106", "bad": "s106_bad.rs", "good": "s106_good.rs"}]
        sources = {
            "s106_bad.rs": "fn main() {}\n",
            "s106_good.rs": "fn main() {}\n",
        }
        with tempfile.TemporaryDirectory() as directory:
            project = self._materializer_project(directory, rows, sources)
            events = []

            def validated(*_args):
                events.append("pair")
                return []

            def materialized(*_args):
                events.append("materialize")

            with (
                mock.patch.object(rust_clippy, "expectations", return_value=rows),
                mock.patch.object(rust_clippy, "validate_mapping"),
                mock.patch.object(
                    rust_clippy,
                    "_validated_fixture_records",
                    side_effect=validated,
                ),
                mock.patch.object(
                    rust_clippy,
                    "materialize_rust_project",
                    side_effect=materialized,
                ),
            ):
                self.assertEqual(
                    rust_clippy.generate_report(project, project / "clippy.json"), 0
                )
            self.assertEqual(events, ["pair", "pair", "materialize"])

    def test_mapping_covers_every_non_native_expectation(self):
        rust_clippy.validate_mapping(PROJECT)
        expected = {str(item["key"]) for item in rust_clippy.expectations(PROJECT)}
        self.assertEqual(
            expected,
            set(rust_clippy.CLIPPY_LINTS) | set(rust_clippy.NATIVE_RULES),
        )

    def test_upstream_exemptions_are_exact_and_exhaustive(self):
        rows = rust_clippy.expectations(PROJECT)
        reasons = {
            str(row["key"]): row["upstream_unverified"]
            for row in rows
            if "upstream_unverified" in row
        }
        self.assertEqual(
            reasons,
            {
                key: boundary["reason"]
                for key, boundary in rust_clippy.UPSTREAM_BOUNDARIES.items()
            },
        )

    def test_plugin_rule_lints_reads_native_mapping_and_rejects_duplicates(self):
        resource = "org/sonar/l10n/rust/rules/clippy/rules.json"
        with tempfile.TemporaryDirectory() as directory:
            plugin = Path(directory) / "plugin.jar"
            with zipfile.ZipFile(plugin, "w") as archive:
                archive.writestr(
                    resource,
                    json.dumps([{"ruleKey": "S1", "lintId": "clippy::one"}]),
                )
            self.assertEqual(
                rust_clippy.plugin_rule_lints(plugin), {"rust:S1": "clippy::one"}
            )

            with zipfile.ZipFile(plugin, "w") as archive:
                archive.writestr(
                    resource,
                    json.dumps(
                        [
                            {"ruleKey": "S1", "lintId": "clippy::one"},
                            {"ruleKey": "S1", "lintId": "clippy::two"},
                        ]
                    ),
                )
            with self.assertRaisesRegex(RuntimeError, "duplicate Clippy mapping"):
                rust_clippy.plugin_rule_lints(plugin)

    def test_rewrite_span_paths_updates_nested_spans(self):
        value = {
            "message": {
                "spans": [{"file_name": "/tmp/source.rs"}],
                "children": [{"spans": [{"file_name": "/tmp/source.rs"}]}],
            }
        }
        rust_clippy.rewrite_span_paths(value, "s106_bad.rs")
        self.assertEqual(value["message"]["spans"][0]["file_name"], "src/s106_bad.rs")
        self.assertEqual(
            value["message"]["children"][0]["spans"][0]["file_name"],
            "src/s106_bad.rs",
        )

    def test_diagnostic_code_rejects_non_diagnostics(self):
        self.assertIsNone(rust_clippy.diagnostic_code({"reason": "build-finished"}))
        self.assertEqual(
            rust_clippy.diagnostic_code(
                {
                    "reason": "compiler-message",
                    "message": {"code": {"code": "clippy::print_stdout"}},
                }
            ),
            "clippy::print_stdout",
        )


if __name__ == "__main__":
    unittest.main()
