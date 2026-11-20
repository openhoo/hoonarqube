import hashlib
import os
import subprocess
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from parity import read_json
from public_corpus_wave2_capture import archive_generated_helpers, capture
from public_corpus_wave2_prepare import GIT_ENV, checkout, plan_rows

ORACLE = Path(__file__).resolve().parent


class WaveTwoTests(unittest.TestCase):
    def test_published_pins_cover_distinct_projects_and_explain_all_omissions(self):
        manifest = read_json(ORACLE / "public-corpus-wave2-projects-20261120.json")
        receipt = read_json(ORACLE / "public-corpus-wave2-qualification-20261120.json")
        first = read_json(ORACLE / "public-corpus-projects-20261120.json")
        prior = {
            row["repository"].casefold() for rows in first.values() for row in rows
        }
        rows = manifest["projects"]
        expected = {row["name"]: row for row in plan_rows()}
        observed = {row["name"]: row for row in rows}
        self.assertEqual(expected.keys(), observed.keys())
        self.assertEqual(len(rows), len({r["repository"].casefold() for r in rows}))
        self.assertTrue(prior.isdisjoint(r["repository"].casefold() for r in rows))
        self.assertEqual(
            Counter(r["language"] for r in rows),
            {k: 6 for k in ("go", "java", "js", "py", "ruby", "rust", "ts")},
        )
        audit = receipt["wave2"]
        excluded = observed.keys() - receipt["projects"].keys()
        self.assertEqual(excluded, {"crossbeam-channel"})
        self.assertEqual(
            audit["preflight"]["crossbeam-channel"]["state"], "scope_rejected"
        )
        self.assertEqual(set(audit["native_validation_blocks"]), {"react-hook-form"})
        self.assertEqual(
            {
                name
                for name, row in audit["preflight"].items()
                if "reference_bridge" in row
            },
            {"gson", "jsoup"},
        )
        for name, row in observed.items():
            with self.subTest(project=name):
                spec = expected[name]
                for field in (
                    "repository",
                    "language",
                    "selection_ref",
                    "exclude",
                    "project_key",
                ):
                    self.assertEqual(row[field], spec[field])
                for field in ("commit", "tree"):
                    self.assertRegex(row[field], r"\A[0-9a-f]{40}\Z")
                if spec["sources"] == ["@go-root"]:
                    self.assertTrue(row["sources"])
                    self.assertTrue(
                        all(
                            Path(f).parent == Path(".")
                            and f.endswith(".go")
                            and not f.endswith("_test.go")
                            for f in row["sources"]
                        )
                    )
                else:
                    self.assertEqual(row["sources"], spec["sources"])
                if name not in excluded:
                    evidence = receipt["projects"][name]["source"]
                    self.assertEqual(evidence["tree"], row["tree"])
                    self.assertEqual(evidence["commit"], row["commit"])

    def test_checkout_fetches_the_exact_pin_and_rejects_a_tracked_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()
            remote = folder / "upstream"
            remote.mkdir()
            state = folder / "replays"
            state.mkdir()

            def git(*args):
                return subprocess.check_output(
                    ["git", "-c", "core.hooksPath=/dev/null", *args],
                    cwd=remote,
                    env={
                        **GIT_ENV,
                        "GIT_AUTHOR_NAME": "Fixture",
                        "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                        "GIT_COMMITTER_NAME": "Fixture",
                        "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
                    },
                    text=True,
                    stderr=subprocess.PIPE,
                ).strip()

            git("init", "--quiet", "--template=")
            source = remote / "src"
            source.mkdir()
            (source / "main.py").write_bytes(b"print('pinned')\n")
            git("add", ".")
            git("commit", "--quiet", "-m", "pinned")
            pinned = {
                "name": "regular",
                "repository": "fixture/public",
                "sources": ["src"],
                "selection_ref": "HEAD",
                "commit": git("rev-parse", "HEAD"),
                "tree": git("rev-parse", "HEAD^{tree}"),
            }
            os.symlink("main.py", source / "link.py")
            git("add", ".")
            git("commit", "--quiet", "-m", "symlink")
            with (
                patch.dict(
                    GIT_ENV,
                    {
                        "GIT_CONFIG_COUNT": "1",
                        "GIT_CONFIG_KEY_0": f"url.{remote.as_uri()}.insteadOf",
                        "GIT_CONFIG_VALUE_0": "https://github.com/fixture/public.git",
                        "GIT_ALLOW_PROTOCOL": "file",
                    },
                ),
                patch("public_corpus_wave2_prepare.require_disk"),
            ):
                result = checkout(state, pinned)
                self.assertEqual(result["commit"], pinned["commit"])
                self.assertEqual(
                    (Path(result["path"]) / "src/main.py").read_bytes(),
                    b"print('pinned')\n",
                )
                with self.assertRaisesRegex(ValueError, "non-regular tracked files"):
                    checkout(
                        state,
                        {
                            **pinned,
                            "name": "symlink",
                            "commit": git("rev-parse", "HEAD"),
                            "tree": git("rev-parse", "HEAD^{tree}"),
                        },
                    )

    def test_helper_written_inside_the_scanned_scope_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp).resolve()
            root = parent / "repo"
            out = parent / "receipt"
            helper = Path(".hoonarqube/semantic/typescript/semantic-helper-v1.cjs")
            payload = b"native helper fixture"
            for scope in ("out-of-scope", "src"):
                target = root / scope / helper
                target.parent.mkdir(parents=True)
                target.write_bytes(payload)
            row = {"name": "fixture", "language": "ts", "sources": ["src"]}
            with (
                patch.object(
                    capture, "ZOD_HELPER_SHA256", hashlib.sha256(payload).hexdigest()
                ),
                self.assertRaisesRegex(ValueError, "unexpected helper"),
            ):
                archive_generated_helpers(row, root, out)
            self.assertEqual(
                (out / "generated/out-of-scope" / helper).read_bytes(), payload
            )
            self.assertEqual((root / "src" / helper).read_bytes(), payload)
