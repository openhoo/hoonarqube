"""Controls for isolation and missing evidence in the fresh public capture."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from parity import read_json, write_json_atomic
from wave4_capture import (
    capture,
    expected_reference,
    reference_scope,
    summarize,
    validate_reference_configuration,
    verify_analysis_task,
    verify_environment,
)
from wave4_prepare import git, inventory, verify_sparse_checkout


class SourceIntegrity(unittest.TestCase):
    def test_checkout_bytes_must_equal_the_pinned_git_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = root / "source.py"
            path.write_bytes(b"hello\n")
            known = {"source.py": "ce013625030ba8dba906f756967f9e9ca394464a"}
            self.assertEqual(inventory(root, known)["source.py"]["bytes"], 6)
            path.write_bytes(b"hell0\n")
            with self.assertRaisesRegex(ValueError, "differ from the Git blob"):
                inventory(root, known)
            with self.assertRaisesRegex(ValueError, "unsafe"):
                inventory(root, {"../source.py": known["source.py"]})

    def test_sparse_checkout_requires_exact_paths_and_pinned_git_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "src/main.go"
            source.parent.mkdir()
            source.write_text("package main\n")
            (root / ".gitignore").write_text("ignored.txt\n")
            git(root, "init", "--quiet", "--template=")
            git(root, "add", "src/main.go", ".gitignore")
            git(
                root,
                "-c",
                "user.name=Wave 4 Test",
                "-c",
                "user.email=wave4@example.invalid",
                "commit",
                "-qm",
                "pin source",
            )
            git(root, "sparse-checkout", "set", "--no-cone", "/src/main.go")
            self.assertFalse((root / ".gitignore").exists())
            commit, tree, blob = (
                git(root, "rev-parse", "HEAD", "HEAD^{tree}", "HEAD:src/main.go")
                .decode()
                .splitlines()
            )
            row = {
                "path": str(root),
                "language": "go",
                "scope_root": "src",
                "commit": commit,
                "tree": tree,
                "sources": ["src/main.go"],
                "source_inventory": inventory(root, {"src/main.go": blob}),
            }
            self.assertEqual(verify_sparse_checkout(row), root)
            with self.assertRaisesRegex(ValueError, "pinned commit and tree"):
                verify_sparse_checkout({**row, "tree": "0" * 40})
            extra = root / "ignored.txt"
            extra.touch()
            with self.assertRaisesRegex(ValueError, "unexpected path.*ignored.txt"):
                verify_sparse_checkout(row)
            extra.unlink()
            source.unlink()
            source.symlink_to(root / ".git/HEAD")
            with self.assertRaisesRegex(ValueError, "unexpected path.*src/main.go"):
                verify_sparse_checkout(row)


class ReferenceProof(unittest.TestCase):
    def test_reference_requires_the_expected_id_and_an_internal_unpublished_container(
        self,
    ):
        private = {
            "Id": "expected",
            "Config": {"Image": capture.SERVER_IMAGE},
            "HostConfig": {},
            "NetworkSettings": {"Networks": {"wave4": {}}},
        }
        validate_reference_configuration(
            private, {"Internal": True}, "expected", "wave4"
        )
        for mutation in [
            {"Privileged": True},
            {"PortBindings": {"9000/tcp": [{"HostPort": "9000"}]}},
            {"PublishAllPorts": True},
        ]:
            with self.assertRaisesRegex(ValueError, "private Community container"):
                validate_reference_configuration(
                    {**private, "HostConfig": mutation},
                    {"Internal": True},
                    "expected",
                    "wave4",
                )
        with self.assertRaisesRegex(ValueError, "private Community container"):
            validate_reference_configuration(
                private, {"Internal": False}, "expected", "wave4"
            )
        with self.assertRaisesRegex(ValueError, "private Community container"):
            validate_reference_configuration(
                private, {"Internal": True}, "wrong", "wave4"
            )

    def test_a_valid_amd64_environment_must_retain_the_same_analyzer_binaries(self):
        expected = expected_reference()
        env = {
            "navigation": {"edition": expected["edition"]},
            "server": {"version": expected["version"], "status": "UP"},
            "plugins": {
                "plugins": [
                    {
                        "key": key,
                        "version": plugin["version"],
                        "hash": plugin["jar_hash"],
                    }
                    for key, plugin in expected["analyzers"].items()
                ]
            },
            "server_image": {
                **expected["server_image"],
                "platform_fingerprint": "amd64 linux sha256:example",
            },
            "scanner_image": expected["scanner_image"],
        }
        verify_environment(env)
        mismatched_plugin = copy.deepcopy(env)
        mismatched_plugin["plugins"]["plugins"][0]["hash"] += "0"
        with self.assertRaisesRegex(ValueError, "differs from the recorded build"):
            verify_environment(mismatched_plugin)
        wrong_platform = copy.deepcopy(env)
        wrong_platform["scanner_image"]["platform_fingerprint"] = (
            "arm64 linux sha256:example"
        )
        with self.assertRaisesRegex(ValueError, "pinned platform"):
            verify_environment(wrong_platform)

    def test_successful_task_from_another_project_does_not_qualify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = {
                "componentKey": "wrong-project",
                "status": "SUCCESS",
                "id": "task-1",
                "analysisId": "analysis-1",
            }
            write_json_atomic(root / "compute-engine.json", {"task": task})
            with self.assertRaisesRegex(ValueError, "fresh project analysis"):
                verify_analysis_task(root, "wave4")
            write_json_atomic(
                root / "compute-engine.json",
                {"task": {**task, "componentKey": "wave4"}},
            )
            self.assertEqual(
                verify_analysis_task(root, "wave4")["analysisId"], "analysis-1"
            )

    def test_text_sensor_count_cannot_hide_missing_language_files(self):
        raw = """
00:00 INFO  Sensor TextAndSecretsSensor [text]
00:00 INFO  7/7 source files have been analyzed
00:00 INFO  Sensor TextAndSecretsSensor [text] (done)
00:00 INFO  Sensor JavaScript/TypeScript/CSS analysis [javascript]
00:00 INFO  6/6 source files have been analyzed
00:00 INFO  Sensor JavaScript/TypeScript/CSS analysis [javascript] (done)
"""
        self.assertEqual(reference_scope(raw, "ts", 7)["state"], "count_differs")
        self.assertEqual(reference_scope(raw, "ts", 6)["state"], "count_matches")
        self.assertEqual(reference_scope(raw, "ruby", 7)["state"], "missing_sensor_log")

    def test_native_only_capture_has_no_paired_denominator_even_with_stale_profiles(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            row = {
                "name": "example",
                "repository": "test/example",
                "project_key": "wave4-example",
                "language": "go",
                "commit": "1" * 40,
                "ref": "1" * 40,
                "tree": "2" * 40,
                "scope_root": "@root",
                "sources": ["source.go"],
                "exclude": [],
                "source_inventory": {"source.go": {"bytes": 42}},
            }
            native = state / "native" / "example"
            native.mkdir(parents=True)
            write_json_atomic(state / "native-build.json", {"source_commit": "C"})
            write_json_atomic(state / "native-catalog.json", [])
            for key in ("profiles", "profiles-end"):
                (state / key).mkdir()
                write_json_atomic(state / key / "effective.json", {"profiles": {}})
            write_json_atomic(native / "source.json", row)
            write_json_atomic(
                native / "progress.json",
                {
                    "native": {"status": "complete", "issue_records": 2},
                    "reference": {"status": "not_run"},
                    "started_at_utc": "now",
                    "ended_at_utc": "now",
                },
            )
            with patch(
                "wave4_capture.comparison.verified_boundaries",
                return_value=(set(), "", {}),
            ):
                counts = summarize(state, [row])
            receipt = read_json(state / "wave4-receipt.json")
            self.assertEqual(counts["comparable_files"], 0)
            self.assertEqual(counts["comparable_primary"], {})
            self.assertEqual(counts["native"], {"complete": 1})
            self.assertEqual(
                receipt["projects"][0]["comparison_state"],
                "not_compared_no_verified_reference",
            )


if __name__ == "__main__":
    unittest.main()
