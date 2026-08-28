import json
import tempfile
import unittest
from pathlib import Path

import rust_clippy


REPO = Path(__file__).resolve().parent.parent.parent
PROJECT = REPO / ".oracle/sonar/projects/oracle-rust"


class RustClippyOracleTests(unittest.TestCase):
    def test_mapping_covers_every_non_native_expectation(self):
        rust_clippy.validate_mapping(PROJECT)
        expected = {str(item["key"]) for item in rust_clippy.expectations(PROJECT)}
        self.assertEqual(
            expected,
            set(rust_clippy.CLIPPY_LINTS) | set(rust_clippy.NATIVE_RULES),
        )

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
