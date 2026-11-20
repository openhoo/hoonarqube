import hashlib
import tempfile
import unittest
from pathlib import Path

from parity import write_json_atomic
from public_corpus_summary import by_rule, scan_result, utf16_coordinates


class PublicCorpusSummaryTests(unittest.TestCase):
    def test_findings_use_utf16_and_explicit_file_level_ranges(self):
        def issue(line, first, last):
            return {
                "range": {
                    "start": {"line": line, "column": first},
                    "end": {"line": line, "column": last},
                }
            }

        self.assertEqual(utf16_coordinates(issue(1, 1, 3), ["😀éx"]), (1, 2, 1, 4))
        self.assertEqual(
            utf16_coordinates(issue(0, 0, 0), ["x"]), (None, None, None, None)
        )
        with self.assertRaisesRegex(ValueError, "column outside"):
            utf16_coordinates(issue(1, 1, 4), ["😀éx"])

    def test_preserves_duplicate_and_same_rule_different_ranges(self):
        exact = ("a:S1", "source.py", 1, 2, 1, 3)
        moved = ("a:S1", "source.py", 1, 3, 1, 4)
        result = by_rule({exact: 3}, {exact: 1, moved: 1}, lambda _: "active")
        self.assertEqual(
            result["by_class"]["active"],
            {"matched": 1, "native_only": 2, "reference_only": 1},
        )

    def test_successful_compute_task_does_not_mask_parser_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            log = b"12:34:00 WARN Unable to parse file src/x.py\n"
            (folder / "scanner.stdout").write_bytes(log)
            write_json_atomic(
                folder / "scanner-execution.json",
                {
                    "exit_code": 0,
                    "seconds": 1,
                    "stdout_sha256": hashlib.sha256(log).hexdigest(),
                },
            )
            write_json_atomic(
                folder / "compute-engine.json", {"task": {"status": "SUCCESS"}}
            )
            observed = scan_result(folder, {"reference": {"status": "complete"}})
            self.assertEqual(observed["state"], "incomplete")
            self.assertEqual(observed["parse_warning_lines"], 1)


if __name__ == "__main__":
    unittest.main()
