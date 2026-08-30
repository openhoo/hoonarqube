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

    def test_updates_only_internal_path_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.toml"
            path.write_text(
                '[dependencies]\n'
                'hoonarqube-core = { version = "0.2.0", path = "../hoonarqube-core" }\n'
                'hoonarqube-remote = "0.2.0"\n'
                'serde = { version = "1.0", path = "../serde" }\n',
                encoding="utf-8",
            )
            updated = SYNC.synchronized(path, "0.3.0")
            self.assertIn(
                'hoonarqube-core = { version = "0.3.0", path = "../hoonarqube-core" }',
                updated,
            )
            self.assertIn('hoonarqube-remote = "0.2.0"', updated)
            self.assertIn('serde = { version = "1.0", path = "../serde" }', updated)


if __name__ == "__main__":
    unittest.main()
