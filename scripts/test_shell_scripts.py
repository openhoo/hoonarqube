from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALL = ROOT / "actions" / "setup" / "install.sh"
RUN_SCAN = ROOT / "tools" / "oracle" / "run_scan.sh"


class OwnedShellScriptTests(unittest.TestCase):
    def _write_executable(self, path: Path, text: str) -> None:
        path.write_text(textwrap.dedent(text), encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def _release_fixture(
        self,
        root: Path,
        version: str,
        *,
        binary_version: str | None = None,
        checksum: str | None = None,
        duplicate_checksum: bool = False,
        include_binary: bool = True,
    ) -> Path:
        release = root / "release"
        release.mkdir(parents=True)
        stem = f"hoonarqube-{version}-x86_64-unknown-linux-gnu"
        archive_name = f"{stem}.tar.gz"
        if include_binary:
            binary = root / "hoonarqube"
            shown_version = binary_version or version
            self._write_executable(
                binary,
                f"""
                #!/bin/sh
                printf '%s\\n' 'hoonarqube {shown_version}'
                """,
            )
            with tarfile.open(release / archive_name, "w:gz") as archive:
                archive.add(binary, arcname=f"{stem}/hoonarqube")
        else:
            placeholder = root / "placeholder"
            placeholder.write_text("not the binary", encoding="utf-8")
            with tarfile.open(release / archive_name, "w:gz") as archive:
                archive.add(placeholder, arcname=f"{stem}/README")

        digest = hashlib.sha256((release / archive_name).read_bytes()).hexdigest()
        selected = checksum or digest
        rows = [f"{selected}  {archive_name}"]
        if duplicate_checksum:
            rows.append(f"{selected}  {archive_name}")
        (release / "SHA256SUMS").write_text("\n".join(rows) + "\n", encoding="utf-8")
        for name in (
            f"{archive_name}.sigstore.json",
            "SHA256SUMS.sigstore.json",
        ):
            (release / name).write_text("{}\n", encoding="utf-8")
        return release

    def _install(
        self,
        root: Path,
        version: str,
        release: Path,
        *,
        runner_os: str = "Linux",
        runner_arch: str = "X64",
        cosign_status: int = 0,
    ) -> subprocess.CompletedProcess[str]:
        commands = root / "commands"
        commands.mkdir(parents=True)
        self._write_executable(
            commands / "curl",
            """
            #!/bin/sh
            set -eu
            output=''
            url=''
            while [ "$#" -gt 0 ]; do
              case "$1" in
                --output) output="$2"; shift 2 ;;
                *) url="$1"; shift ;;
              esac
            done
            cp "$MOCK_RELEASE/${url##*/}" "$output"
            """,
        )
        cosign_log = root / "cosign.log"
        self._write_executable(
            commands / "cosign",
            """
            #!/bin/sh
            printf '%s\\n' '---' >> "$MOCK_COSIGN_LOG"
            printf '<%s>\\n' "$@" >> "$MOCK_COSIGN_LOG"
            exit "$MOCK_COSIGN_STATUS"
            """,
        )
        temporary = root / "tmp"
        temporary.mkdir()
        github_path = root / "github-path"
        github_output = root / "github-output"
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{commands}{os.pathsep}{environment['PATH']}",
                "INPUT_VERSION": version,
                "RUNNER_OS_VALUE": runner_os,
                "RUNNER_ARCH_VALUE": runner_arch,
                "RUNNER_TEMP": str(temporary),
                "GITHUB_PATH": str(github_path),
                "GITHUB_OUTPUT": str(github_output),
                "MOCK_RELEASE": str(release),
                "MOCK_COSIGN_LOG": str(cosign_log),
                "MOCK_COSIGN_STATUS": str(cosign_status),
            }
        )
        return subprocess.run(
            ["bash", str(INSTALL)],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )

    def test_install_accepts_full_semver_and_publishes_verified_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version = "1.2.3-rc.1.2+build.7"
            release = self._release_fixture(root, version)
            result = self._install(root, version, release)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (root / "github-output").read_text(encoding="utf-8"),
                f"version={version}\n",
            )
            installed = Path((root / "github-path").read_text().strip()) / "hoonarqube"
            self.assertTrue(installed.is_file())
            self.assertTrue(installed.stat().st_mode & stat.S_IXUSR)

            cosign_log = (root / "cosign.log").read_text(encoding="utf-8")
            self.assertEqual(cosign_log.count("---\n"), 2)
            self.assertEqual(cosign_log.count("<verify-blob>\n"), 2)
            self.assertEqual(cosign_log.count("<--bundle>\n"), 2)
            self.assertIn(
                f"{version}-x86_64-unknown-linux-gnu.tar.gz.sigstore.json", cosign_log
            )
            self.assertIn("SHA256SUMS.sigstore.json", cosign_log)
            identity = (
                "https://github.com/openhoo/hoonarqube/"
                ".github/workflows/release.yml@refs/heads/main"
            )
            issuer = "https://token.actions.githubusercontent.com"
            self.assertEqual(cosign_log.count(f"<{identity}>\n"), 2)
            self.assertEqual(cosign_log.count(f"<{issuer}>\n"), 2)

    def test_install_does_not_publish_outputs_after_cosign_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version = "1.2.3"
            release = self._release_fixture(root, version)
            result = self._install(root, version, release, cosign_status=1)

            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / "github-path").exists())
            self.assertFalse((root / "github-output").exists())

    def test_install_rejects_malformed_semver_before_download(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self._install(root, "1.2.3-01", root)

            self.assertEqual(result.returncode, 2)
            self.assertIn("unprefixed semantic version", result.stdout)

    def test_install_rejects_unmapped_runner_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self._install(
                root, "1.2.3", root, runner_os="Linux", runner_arch="ARM64"
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("only for Linux X64", result.stdout)

    def test_install_rejects_duplicate_or_wrong_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version = "1.2.3"
            release = self._release_fixture(root, version, duplicate_checksum=True)
            duplicate = self._install(root, version, release)
            self.assertEqual(duplicate.returncode, 1)
            self.assertIn("no unique digest", duplicate.stdout)

            bad = self._release_fixture(root / "bad", version, checksum="0" * 64)
            mismatch = self._install(root / "bad", version, bad)
            self.assertEqual(mismatch.returncode, 1)
            self.assertIn("Checksum mismatch", mismatch.stdout)

    def test_install_requires_exact_installed_version_and_expected_binary_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            version = "1.2.3"
            release = self._release_fixture(
                root, version, binary_version="1.2.30", include_binary=True
            )
            wrong_version = self._install(root, version, release)
            self.assertNotEqual(wrong_version.returncode, 0)

            missing = self._release_fixture(
                root / "missing", version, include_binary=False
            )
            missing_binary = self._install(root / "missing", version, missing)
            self.assertEqual(missing_binary.returncode, 1)
            self.assertIn("expected path", missing_binary.stdout)

    def test_run_scan_rejects_invalid_project_without_credentials(self):
        environment = os.environ.copy()
        environment.pop("SONAR_ORACLE_TOKEN", None)
        result = subprocess.run(
            ["bash", str(RUN_SCAN), "oracle-invalid"],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("invalid oracle project", result.stderr)

    def test_run_scan_passes_local_token_and_project_arguments_to_scanner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "commands"
            commands.mkdir()
            capture = root / "capture"
            self._write_executable(
                commands / "mock-scanner",
                """
                #!/bin/sh
                printf '%s\\n' "$SONAR_TOKEN" > "$MOCK_CAPTURE.token"
                printf '%s\\n' "$@" > "$MOCK_CAPTURE.args"
                """,
            )
            environment = os.environ.copy()
            environment.update(
                {
                    "PATH": f"{commands}{os.pathsep}{environment['PATH']}",
                    "SONAR_SCANNER": "mock-scanner",
                    "SONAR_ORACLE_TOKEN": "local-token",
                    "MOCK_CAPTURE": str(capture),
                }
            )
            result = subprocess.run(
                ["bash", str(RUN_SCAN), "oracle-py"],
                cwd=ROOT,
                env=environment,
                text=True,
                capture_output=True,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                (root / "capture.token").read_text().strip(), "local-token"
            )
            arguments = (root / "capture.args").read_text()
            self.assertIn("-Dsonar.projectKey=oracle-py", arguments)
            self.assertIn("-Dsonar.host.url=http://127.0.0.1:9000", arguments)
            self.assertIn("-Dsonar.working.directory=", arguments)


if __name__ == "__main__":
    unittest.main()
