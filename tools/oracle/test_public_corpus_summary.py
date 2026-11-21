import hashlib
import tempfile
import unittest
from pathlib import Path

from parity import write_json_atomic
from public_corpus_summary import by_rule, file_scope, scan_result, utf16_coordinates


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

    def test_indexed_bundle_is_outside_common_analyzer_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            source = folder / "vendor.js"
            source.write_bytes(b"var bundled = 42;\n")
            captured_index = [
                {
                    "path": source.name,
                    "sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                }
            ]
            for label in ("native", "reference"):
                write_json_atomic(folder / f"{label}-source-files.json", captured_index)
            write_json_atomic(
                folder / "indexed-files.json", [{"path": source.name, "language": "js"}]
            )
            log = (
                b"12:34:00 INFO  1/1 source file has been analyzed for the text and secrets analysis\n"
                b"12:34:01 INFO  Sensor JavaScript/TypeScript/CSS analysis [javascript]\n"
                b"12:34:02 INFO  Some of the project files were automatically excluded because they "
                b"looked like generated code. Enable debug logging to see which files were excluded. "
                b"You can disable bundle detection by setting sonar.javascript.detectBundles=false\n"
                b"12:34:02 INFO  0/0 source files have been analyzed\n"
                b"12:34:02 INFO  Hit the cache for 0 out of 1\n"
                b"12:34:02 INFO  Sensor JavaScript/TypeScript/CSS analysis [javascript] (done) | time=1ms\n"
            )
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
            observed = {
                "reference": scan_result(folder, {"reference": {"status": "complete"}})
            }
            native = {"files": [{"path": source.name, "language": "JavaScript"}]}
            _, _, shared = file_scope(
                folder, folder, folder.resolve(), native, observed
            )
            self.assertEqual(observed["reference"]["state"], "complete")
            self.assertEqual(observed["reference"]["compute_status"], "SUCCESS")
            self.assertEqual(
                observed["comparison_state"], "not_compared_reference_sensor_scope"
            )
            self.assertEqual(observed["files"]["indexed_shared"], 1)
            self.assertEqual(
                observed["files"]["reference_sensor_skipped"], [source.name]
            )
            self.assertFalse(shared)


if __name__ == "__main__":
    unittest.main()
