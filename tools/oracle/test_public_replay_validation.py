"""A new native checkout must keep the pinned source identity and finish its final guard."""

import subprocess
import tempfile
import unittest
from pathlib import Path

from parity import write_json_atomic
import public_corpus_summary as summary


class PublicReplayValidationTests(unittest.TestCase):
    def test_a_complete_native_result_without_checkout_postcheck_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            row = {
                "name": "example",
                "repository": "example/example",
                "ref": "tag",
                "commit": "a",
                "tree": "b",
                "project_key": "x",
                "sources": ["src"],
                "exclude": [],
                "language": "go",
                "path": tmp,
            }
            write_json_atomic(evidence / "source.json", row)
            write_json_atomic(
                evidence / "progress.json",
                {
                    "started_at_utc": "start",
                    "native": {"status": "complete"},
                    "reference": {"status": "not_run"},
                },
            )
            with self.assertRaisesRegex(ValueError, "postcheck"):
                summary.project_metadata(evidence, evidence)

    def test_relocated_checkout_requires_the_same_manifest_and_git_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve() / "clone"
            root.mkdir()

            def git(*args):
                return subprocess.check_output(
                    [
                        "git",
                        "-c",
                        "user.name=Corpus Test",
                        "-c",
                        "user.email=ci@example.invalid",
                        "-c",
                        "commit.gpgsign=false",
                        *args,
                    ],
                    cwd=root,
                    text=True,
                ).strip()

            git("init", "--quiet")
            (root / "source.go").write_text("package test\n")
            git("add", "source.go")
            git("commit", "--quiet", "-m", "fixture")
            original = {
                "name": "test",
                "path": "/original/checkout",
                "commit": git("rev-parse", "HEAD"),
                "tree": git("rev-parse", "HEAD^{tree}"),
                "sources": ["source.go"],
                "repository": "example/example",
                "ref": "tag",
                "project_key": "test",
                "exclude": [],
                "language": "go",
            }
            current = {**original, "path": str(root)}
            reference = Path(tmp) / "reference"
            replay = Path(tmp) / "replay"
            for folder, row in ((reference, original), (replay, current)):
                folder.mkdir()
                write_json_atomic(folder / "source.json", row)
                write_json_atomic(
                    folder / "progress.json",
                    {
                        "started_at_utc": "start",
                        "ended_at_utc": "end",
                        "native": {"status": "not_run"},
                        "reference": {"status": "not_run"},
                    },
                )
            row, result, _, _ = summary.project_metadata(reference, replay)
            self.assertEqual(row, current)
            self.assertNotEqual(
                result["evidence_sha256"]["source.json"],
                result["evidence_sha256"]["native-source-manifest.json"],
            )
            for change in ({"sources": ["other.go"]}, {"commit": "0" * 40}):
                with (
                    self.subTest(change=change),
                    self.assertRaisesRegex(ValueError, "manifest"),
                ):
                    summary.replay_source(original, {**current, **change})
            with self.assertRaisesRegex(ValueError, "tree"):
                summary.replay_source(
                    {**original, "tree": "0" * 40}, {**current, "tree": "0" * 40}
                )
            (root / "generated").write_text("unexpected")
            with self.assertRaisesRegex(ValueError, "checkout"):
                summary.replay_source(original, current)
