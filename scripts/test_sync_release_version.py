from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("sync_release_version.py")
SPEC = importlib.util.spec_from_file_location("sync_release_version", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SYNC)


class SyncReleaseVersionTest(unittest.TestCase):
    def test_semver_accepts_prerelease_and_build_metadata_edges(self):
        accepted = (
            "0.0.0",
            "1.2.3-alpha",
            "1.2.3-rc.1+build.7",
            "1.2.3-alpha.1.2",
            "1.2.3+linux.x86-64",
        )
        rejected = (
            "v1.2.3",
            "1.2",
            "1.2.3-",
            "1.2.3-alpha..1",
            "1.2.3-01",
            "1.2.3+",
        )
        for version in accepted:
            with self.subTest(version=version):
                self.assertIsNotNone(SYNC.SEMVER.fullmatch(version))
        for version in rejected:
            with self.subTest(version=version):
                self.assertIsNone(SYNC.SEMVER.fullmatch(version))

    def test_synchronization_rejects_invalid_versions_and_ambiguous_targets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "action.yml"
            path.write_text(
                '    default: "1.2.3"\n    default: "1.2.4"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                SYNC.synchronized(path, "1.2.3")
            with self.assertRaisesRegex(RuntimeError, "valid semantic version"):
                SYNC.synchronized(path, "1.2.3-")

    def test_main_updates_all_manifests_including_multiline_xtask_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "VERSION").write_text("1.2.3-rc.1+build.7\n", encoding="utf-8")
            (root / "Cargo.toml").write_text(
                '[workspace.package]\nversion = "0.2.0"\n', encoding="utf-8"
            )
            example = root / "crates" / "example"
            example.mkdir(parents=True)
            (example / "Cargo.toml").write_text(
                "[dependencies]\n"
                "hoonarqube-core = {\n"
                '    path = "../hoonarqube-core"\n'
                '    version = "0.2.0"\n'
                "}\n",
                encoding="utf-8",
            )
            xtask = root / "xtask"
            xtask.mkdir()
            (xtask / "Cargo.toml").write_text(
                "[dependencies]\n"
                'hoonarqube-core = { path = "../crates/hoonarqube-core", '
                'version = "0.2.0" }\n',
                encoding="utf-8",
            )
            for action_name in ("setup", "analyze", "code-quality"):
                action = root / "actions" / action_name / "action.yml"
                action.parent.mkdir(parents=True, exist_ok=True)
                action.write_text(
                    'inputs:\n  version:\n    default: "0.2.0-rc.1"\n',
                    encoding="utf-8",
                )
            readme = root / "actions" / "README.md"
            readme.parent.mkdir(parents=True, exist_ok=True)
            readme.write_text("    version: 0.2.0+old\n", encoding="utf-8")
            workflow = root / ".github" / "workflows" / "ci.yml"
            workflow.parent.mkdir(parents=True)
            workflow.write_text("HOONARQUBE_DOGFOOD_VERSION: 9.9.9\n", encoding="utf-8")

            original_root = SYNC.ROOT
            original_argv = sys.argv
            try:
                SYNC.ROOT = root
                sys.argv = ["sync_release_version.py"]
                self.assertEqual(SYNC.main(), 0)
            finally:
                SYNC.ROOT = original_root
                sys.argv = original_argv

            expected = "1.2.3-rc.1+build.7"
            self.assertIn(expected, (root / "Cargo.toml").read_text())
            self.assertIn(expected, (example / "Cargo.toml").read_text())
            self.assertIn(expected, (xtask / "Cargo.toml").read_text())
            for action_name in ("setup", "analyze", "code-quality"):
                self.assertIn(
                    expected,
                    (root / "actions" / action_name / "action.yml").read_text(),
                )
            self.assertIn(expected, readme.read_text())
            self.assertEqual(
                workflow.read_text(), "HOONARQUBE_DOGFOOD_VERSION: 9.9.9\n"
            )

            workspace = root / "Cargo.toml"
            workspace.write_text(
                '[workspace.package]\nversion = "9.9.9"\n', encoding="utf-8"
            )
            try:
                SYNC.ROOT = root
                sys.argv = ["sync_release_version.py", "--check"]
                with self.assertRaisesRegex(RuntimeError, "release version drift"):
                    SYNC.main()
            finally:
                SYNC.ROOT = original_root
                sys.argv = original_argv
            self.assertIn('version = "9.9.9"', workspace.read_text())

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
                readme.write_text(
                    "with:\n    version: 0.2.2\n"
                    "another-example:\n    version: 0.2.2-rc.1\n",
                    encoding="utf-8",
                )

                self.assertIn('default: "0.2.3"', SYNC.synchronized(action, "0.2.3"))
                self.assertIn(
                    'default: "0.2.3"',
                    SYNC.synchronized(code_quality, "0.2.3"),
                )
                updated_readme = SYNC.synchronized(readme, "0.2.3")
                self.assertEqual(updated_readme.count("version: 0.2.3"), 2)
                self.assertNotIn("0.2.2", updated_readme)
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
