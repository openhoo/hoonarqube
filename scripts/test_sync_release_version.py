from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("sync_release_version.py")
SPEC = importlib.util.spec_from_file_location("sync_release_version", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class SyncReleaseVersionTest(unittest.TestCase):
    def test_updates_workspace_version_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(
                '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "0.2.0"\n\n'
                '[workspace.dependencies]\nserde = "1.0"\n',
                encoding="utf-8",
            )
            original_root = SYNC.ROOT
            try:
                SYNC.ROOT = Path(directory)
                updated = SYNC.synchronized(path, "0.3.0")
            finally:
                SYNC.ROOT = original_root
            self.assertIn('version = "0.3.0"', updated)
            self.assertIn('serde = "1.0"', updated)

    def test_updates_only_internal_path_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            sibling = Path(directory) / "crates" / "example" / "Cargo.toml"
            sibling.parent.mkdir(parents=True)
            sibling.write_text(
                "[dependencies]\n"
                'hoonarqube-core = { version = "0.2.0", path = "../hoonarqube-core" }\n'
                'hoonarqube-remote = "0.2.0"\n'
                'serde = { version = "1.0", path = "../serde" }\n',
                encoding="utf-8",
            )
            xtask = Path(directory) / "xtask" / "Cargo.toml"
            xtask.parent.mkdir()
            xtask.write_text(
                "[dependencies]\n"
                'hoonarqube-catalog = { version = "0.2.0", path = "../crates/hoonarqube-catalog" }\n',
                encoding="utf-8",
            )

            updated_sibling = SYNC.synchronized(sibling, "0.3.0")
            updated_xtask = SYNC.synchronized(xtask, "0.3.0")

            self.assertIn(
                'hoonarqube-core = { version = "0.3.0", path = "../hoonarqube-core" }',
                updated_sibling,
            )
            self.assertIn(
                'hoonarqube-catalog = { version = "0.3.0", path = "../crates/hoonarqube-catalog" }',
                updated_xtask,
            )
            self.assertIn('hoonarqube-remote = "0.2.0"', updated_sibling)
            self.assertIn(
                'serde = { version = "1.0", path = "../serde" }', updated_sibling
            )

    def test_updates_all_action_defaults_and_documentation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_root = SYNC.ROOT
            try:
                SYNC.ROOT = Path(directory)
                action = SYNC.ROOT / "actions" / "setup" / "action.yml"
                action.parent.mkdir(parents=True)
                action.write_text(
                    'inputs:\n  version:\n    default: "0.2.2"\n  path:\n    default: "."\n',
                    encoding="utf-8",
                )
                code_quality = SYNC.ROOT / "actions" / "code-quality" / "action.yml"
                code_quality.parent.mkdir(parents=True)
                code_quality.write_text(
                    'inputs:\n  version:\n    default: "0.2.2"\n',
                    encoding="utf-8",
                )
                readme = SYNC.ROOT / "actions" / "README.md"
                readme.write_text("with:\n    version: 0.2.2\n", encoding="utf-8")

                self.assertIn('default: "0.2.3"', SYNC.synchronized(action, "0.2.3"))
                self.assertIn(
                    'default: "0.2.3"',
                    SYNC.synchronized(code_quality, "0.2.3"),
                )
                self.assertIn("version: 0.2.3", SYNC.synchronized(readme, "0.2.3"))
            finally:
                SYNC.ROOT = original_root

    def test_keeps_pinned_ci_dogfood_version_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original_root = SYNC.ROOT
            try:
                SYNC.ROOT = Path(directory)
                workflow = SYNC.ROOT / ".github" / "workflows" / "ci.yml"
                workflow.parent.mkdir(parents=True)
                workflow.write_text(
                    "env:\n  HOOVERSION_VERSION: 1.1.1\n"
                    "  HOONARQUBE_DOGFOOD_VERSION: 0.3.1\n",
                    encoding="utf-8",
                )
                updated = SYNC.synchronized(workflow, "0.4.0")
                self.assertEqual(workflow.read_text(encoding="utf-8"), updated)
            finally:
                SYNC.ROOT = original_root


if __name__ == "__main__":
    unittest.main()
