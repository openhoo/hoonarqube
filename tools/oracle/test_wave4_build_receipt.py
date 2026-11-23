"""Prove that a checkout cannot give a stale scanner a new build identity."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from public_locations_capture import capture as export_locations
from wave4_build_receipt import SCANNER, build_scanner, git, verify_receipt
from wave4_capture import native


class ScannerBuild(unittest.TestCase):
    def test_legacy_receipt_is_rejected_before_export_or_running_the_scanner(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "scanner"
            binary.write_text("invalid executable")
            legacy = {
                "source_commit": "a" * 40,
                "source_tree": "b" * 40,
                "compiled_tree": "b" * 40,
            }
            receipt = root / "build.json"
            receipt.write_text(json.dumps(legacy))
            with self.assertRaisesRegex(ValueError, "fresh release"):
                native(SimpleNamespace(binary=binary, build_receipt=receipt), [])
            archive = {
                "reference": {"server": {"version": "26.9.0.129388"}},
                "native": legacy,
            }
            (root / "cohort-receipt.json").write_text(json.dumps(archive))
            with self.assertRaisesRegex(ValueError, "fresh release"):
                export_locations(root, selected_rows=[])

    def test_stale_target_ignored_and_identical_bytes_do_not_transfer_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            repo = root / "repo"
            git(root, "init", "-q", str(repo))
            src = repo / "crates/hoonarqube-cli"
            (src / "src").mkdir(parents=True)
            (repo / "Cargo.toml").write_text(
                '[workspace]\nmembers=["crates/hoonarqube-cli"]\nresolver="2"\n'
            )
            (src / "Cargo.toml").write_text(
                '[package]\nname="hoonarqube-cli"\nversion="0.0.1"\nedition="2021"\n[[bin]]\nname="hoonarqube"\npath="src/main.rs"\n'
            )
            main = src / "src/main.rs"
            main.write_text('fn main(){println!("old");}\n')
            (repo / ".gitignore").write_text("ignored.rs\n")
            subprocess.run(
                ["cargo", "generate-lockfile", "--offline"], cwd=repo, check=True
            )

            def commit():
                git(repo, "add", ".")
                git(
                    repo,
                    "-c",
                    "commit.gpgSign=false",
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "snapshot",
                )
                return git(repo, "rev-parse", "HEAD")

            commit()
            old_dir = root / "old"
            build_scanner(repo, old_dir)
            stale = old_dir / SCANNER
            self.assertEqual(subprocess.check_output([stale], text=True).strip(), "old")
            main.write_text('fn main(){println!("new");}\n')
            new = commit()
            # Neither the caller's tracked edits nor the supplied existing output can
            # replace the committed source used for the new receipt.
            (repo / "ignored.rs").write_text("local ignored input")
            main.write_text('fn main(){println!("uncommitted");}\n')
            with patch.dict(
                os.environ,
                {
                    "CARGO_TARGET_DIR": str(old_dir),
                    "CARGO_BUILD_BUILD_DIR": str(old_dir),
                },
            ):
                new_dir = root / "new"
                build_scanner(repo, new_dir)
            fresh = new_dir / SCANNER
            record = json.loads((new_dir / "build.json").read_bytes())
            self.assertEqual(subprocess.check_output([fresh], text=True).strip(), "new")
            self.assertEqual(
                verify_receipt(repo, record, binary=fresh, expected_commit=new), new
            )
            with self.assertRaisesRegex(ValueError, "scanner bytes differ"):
                verify_receipt(repo, record, binary=stale)
            with self.assertRaisesRegex(ValueError, "fresh release"):
                verify_receipt(
                    repo,
                    {
                        "source_commit": new,
                        "source_tree": record["source_tree"],
                        "compiled_tree": record["source_tree"],
                        "binary_sha256": record["binary_sha256"],
                    },
                )
            with self.assertRaisesRegex(ValueError, "new output directory"):
                build_scanner(repo, stale)
            git(repo, "restore", str(main))
            (repo / "README").write_text("documentation only\n")
            docs = commit()
            with self.assertRaisesRegex(ValueError, "source commit"):
                verify_receipt(repo, record, binary=fresh, expected_commit=docs)
            docs_dir = root / "docs"
            build_scanner(repo, docs_dir)
            docs_record = json.loads((docs_dir / "build.json").read_bytes())
            self.assertEqual(docs_record["binary_sha256"], record["binary_sha256"])
            self.assertEqual(
                verify_receipt(
                    repo, docs_record, binary=docs_dir / SCANNER, expected_commit=docs
                ),
                docs,
            )
            self.assertNotEqual(record["source_tree"], docs_record["source_tree"])
