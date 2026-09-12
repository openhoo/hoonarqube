from __future__ import annotations

import hashlib
import json
import os
import re
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
ANALYZE_ACTION = ROOT / "actions" / "analyze" / "action.yml"
CODE_QUALITY_ACTION = ROOT / "actions" / "code-quality" / "action.yml"


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

    def _action_run_script(self, action: Path, step_name: str) -> str:
        lines = action.read_text(encoding="utf-8").splitlines()
        marker = f"    - name: {step_name}"
        try:
            step = lines.index(marker)
        except ValueError as error:
            raise AssertionError(f"missing action step {step_name!r}") from error

        run = next(
            (
                index
                for index in range(step + 1, len(lines))
                if lines[index] == "      run: |"
            ),
            None,
        )
        if run is None:
            raise AssertionError(f"step {step_name!r} has no shell run block")

        body: list[str] = []
        for line in lines[run + 1 :]:
            if line and not line.startswith("        "):
                break
            body.append(line[8:] if line else "")
        return "\n".join(body) + "\n"

    def _run_action_argument_case(
        self,
        root: Path,
        *,
        action: Path,
        step_name: str,
        cache_dir: str,
        report: str,
    ) -> list[str]:
        commands = root / "commands"
        commands.mkdir(parents=True)
        arguments = root / "arguments"
        report_fixture = root / "report-fixture"
        runner_temp = root / "runner-temp"
        runner_temp.mkdir()
        self._write_executable(
            commands / "hoonarqube",
            """
            #!/bin/sh
            set -eu
            printf '%s\\n' "$@" > "$MOCK_ARGUMENTS"
            cat "$MOCK_REPORT"
            """,
        )
        report_fixture.write_text(report, encoding="utf-8")

        sentinel = root / "injected"
        source_path = f"src/space path;touch {sentinel}"
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{commands}{os.pathsep}{environment['PATH']}",
                "GITHUB_OUTPUT": str(root / "github-output"),
                "INPUT_CACHE_DIR": cache_dir,
                "INPUT_EXECUTABLE": "",
                "INPUT_FAIL_ON": "none",
                "INPUT_GO_HEADER_FORMAT": "",
                "INPUT_OUTPUT": "report",
                "INPUT_PATHS": source_path,
                "INPUT_PROFILE": "sonar-parity",
                "INPUT_UPLOAD": "false",
                "MOCK_ARGUMENTS": str(arguments),
                "MOCK_REPORT": str(report_fixture),
                "RUNNER_TEMP": str(runner_temp),
            }
        )
        result = subprocess.run(
            ["bash", "-c", self._action_run_script(action, step_name)],
            cwd=root,
            env=environment,
            text=True,
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(sentinel.exists(), result.stderr)
        return arguments.read_text(encoding="utf-8").splitlines()

    def _run_action_report_case(
        self,
        root: Path,
        *,
        action: Path,
        step_name: str,
        report_script: str,
        output: str = "report",
        fail_on: str = "none",
        working_directory: Path | None = None,
        paths: str = "src",
    ) -> subprocess.CompletedProcess[str]:
        commands = root / "commands"
        commands.mkdir(parents=True)
        runner_temp = root / "runner-temp"
        runner_temp.mkdir()
        executable = commands / "hoonarqube"
        self._write_executable(executable, report_script)
        environment = os.environ.copy()
        environment.update(
            {
                "PATH": f"{commands}{os.pathsep}{environment['PATH']}",
                "GITHUB_OUTPUT": str(root / "github-output"),
                "INPUT_CACHE_DIR": "",
                "INPUT_EXECUTABLE": str(executable),
                "INPUT_FAIL_ON": fail_on,
                "INPUT_GO_HEADER_FORMAT": "",
                "INPUT_OUTPUT": output,
                "INPUT_PATHS": paths,
                "INPUT_PROFILE": "sonar-parity",
                "INPUT_UPLOAD": "false",
                "RUNNER_TEMP": str(runner_temp),
            }
        )
        return subprocess.run(
            ["bash", "-c", self._action_run_script(action, step_name)],
            cwd=working_directory or root,
            env=environment,
            text=True,
            capture_output=True,
        )

    def test_analyze_publishes_valid_report_before_propagating_exit_two(self):
        report = (
            '{"rules":[{"id":"R1","severity":"MAJOR"}],'
            '"issues":[{"ruleId":"R1"}]}\n'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = self._run_action_report_case(
                root,
                action=ANALYZE_ACTION,
                step_name="Analyze source",
                fail_on="major",
                report_script=f"""
                #!/bin/sh
                printf '%s' '{report}'
                exit 2
                """,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual((root / "report").read_text(encoding="utf-8"), report)
            output = (root / "github-output").read_text(encoding="utf-8")
            self.assertIn("report=report\n", output)
            self.assertIn("blocking-findings=1\n", output)
            self.assertEqual(list(root.glob(".hoonarqube-analyze.*.json")), [])

    def test_analyze_keeps_existing_report_when_output_is_invalid(self):
        existing = '{"rules":[],"issues":[]}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report"
            report_path.write_text(existing, encoding="utf-8")
            result = self._run_action_report_case(
                root,
                action=ANALYZE_ACTION,
                step_name="Analyze source",
                report_script="""
                #!/bin/sh
                printf '%s\n' '{"rules":[]}'
                exit 2
                """,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(report_path.read_text(encoding="utf-8"), existing)
            self.assertIn("no report was published", result.stdout)
            self.assertEqual(list(root.glob(".hoonarqube-analyze.*.json")), [])

    def test_analyze_rejects_concatenated_json_documents(self):
        existing = '{"rules":[],"issues":[]}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "report"
            report_path.write_text(existing, encoding="utf-8")
            result = self._run_action_report_case(
                root,
                action=ANALYZE_ACTION,
                step_name="Analyze source",
                report_script="""
                #!/bin/sh
                printf '%s\n' '{"rules":[],"issues":[]}'
                printf '%s\n' '{"rules":[],"issues":[]}'
                """,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(report_path.read_text(encoding="utf-8"), existing)
            self.assertIn("no report was published", result.stdout)
            self.assertEqual(list(root.glob(".hoonarqube-analyze.*.json")), [])

    def test_analyze_refuses_symlinked_output_parent(self):
        report = '{"rules":[],"issues":[]}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real"
            real_parent.mkdir()
            (root / "out").symlink_to(real_parent, target_is_directory=True)
            result = self._run_action_report_case(
                root,
                action=ANALYZE_ACTION,
                step_name="Analyze source",
                output="out/report",
                report_script=f"""
                #!/bin/sh
                printf '%s' '{report.rstrip()}'
                """,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((real_parent / "report").exists())
            self.assertIn("must not traverse symlinks", result.stdout)

    def test_code_quality_refuses_symlinked_output_parent(self):
        report = (
            '{"$schema":"https://json.schemastore.org/sarif-2.1.0.json",'
            '"version":"2.1.0","runs":[{"tool":{"driver":'
            '{"name":"Hoonarqube","rules":[]}},"results":[]}]}'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_parent = root / "real"
            real_parent.mkdir()
            (root / "out").symlink_to(real_parent, target_is_directory=True)
            result = self._run_action_report_case(
                root,
                action=CODE_QUALITY_ACTION,
                step_name="Analyze source and write SARIF",
                output="out/report.sarif",
                report_script=f"""
                #!/bin/sh
                printf '%s' '{report}'
                """,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((real_parent / "report.sarif").exists())
            self.assertIn("must not traverse symlinks", result.stdout)

    def test_analyze_cache_dir_is_optional_and_literal(self):
        report = '{"rules":[],"issues":[]}\n'
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for use_cache in (False, True):
                root = parent / ("default" if not use_cache else "cached")
                cache_dir = (
                    f"{root}/cache dir;touch {root}/injected" if use_cache else ""
                )
                with self.subTest(cache_dir=cache_dir):
                    arguments = self._run_action_argument_case(
                        root,
                        action=ANALYZE_ACTION,
                        step_name="Analyze source",
                        cache_dir=cache_dir,
                        report=report,
                    )
                    expected = ["analyze", "--format", "sonar"]
                    if cache_dir:
                        expected += ["--cache-dir", cache_dir]
                    expected += ["--", f"src/space path;touch {root}/injected"]
                    self.assertEqual(arguments, expected)

    def test_code_quality_cache_dir_is_optional_and_literal(self):
        report = (
            '{"$schema":"https://json.schemastore.org/sarif-2.1.0.json",'
            '"version":"2.1.0","runs":[{"tool":{"driver":'
            '{"name":"Hoonarqube","rules":[]}},"results":[]}]}'
        )
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            for use_cache in (False, True):
                root = parent / ("default" if not use_cache else "cached")
                cache_dir = (
                    f"{root}/cache dir;touch {root}/injected" if use_cache else ""
                )
                with self.subTest(cache_dir=cache_dir):
                    arguments = self._run_action_argument_case(
                        root,
                        action=CODE_QUALITY_ACTION,
                        step_name="Analyze source and write SARIF",
                        cache_dir=cache_dir,
                        report=report,
                    )
                    expected = [
                        "analyze",
                        "--profile",
                        "github-code-quality",
                        "--format",
                        "sarif",
                    ]
                    if cache_dir:
                        expected += ["--cache-dir", cache_dir]
                    expected += ["--", f"src/space path;touch {root}/injected"]
                    self.assertEqual(arguments, expected)

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

    def test_documented_actions_exist_at_their_immutable_revisions(self):
        references = re.compile(
            r"uses:\s+openhoo/hoonarqube/(actions/[^@\s]+)@([0-9a-fA-F]{40})(?:\s|$)"
        )
        for documentation in (ROOT / "README.md", ROOT / "actions" / "README.md"):
            for path, revision in references.findall(
                documentation.read_text(encoding="utf-8")
            ):
                with self.subTest(documentation=documentation, action=path):
                    result = subprocess.run(
                        ["git", "cat-file", "-e", f"{revision}:{path}/action.yml"],
                        cwd=ROOT,
                        text=True,
                        capture_output=True,
                    )
                    self.assertEqual(
                        result.returncode,
                        0,
                        f"{documentation}: {path} is absent at {revision}: {result.stderr}",
                    )
    def test_analyze_exports_absolute_report_from_nested_working_directory(self):
        report = '{"rules":[],"issues":[]}\n'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "packages" / "foo"
            nested.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            result = self._run_action_report_case(
                nested,
                action=ANALYZE_ACTION,
                step_name="Analyze source",
                report_script=f"""
                #!/bin/sh
                printf '%s' '{report}'
                """,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output = (nested / "github-output").read_text(encoding="utf-8")
            self.assertIn(f"report={nested / 'report'}\n", output)
            self.assertEqual((nested / "report").read_text(encoding="utf-8"), report)

    def test_code_quality_roots_nested_input_paths_before_sarif_publish(self):
        report = (
            '{"$schema":"https://json.schemastore.org/sarif-2.1.0.json",'
            '"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Hoonarqube",'
            '"rules":[{"id":"R1","name":"R1","shortDescription":{"text":"R1"},'
            '"helpUri":"https://example.test/r1","properties":{"category":"BUG",'
            '"severity":"WARNING","help":"https://example.test/r1"}}]}},'
            '"results":[{"ruleId":"R1","ruleIndex":0,"level":"warning",'
            '"message":{"text":"finding"},"locations":[{"physicalLocation":'
            '{"artifactLocation":{"uri":"packages/foo/finding.py"}}}]}]}]}'
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "packages" / "foo"
            nested.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            arguments = root / "arguments"
            result = self._run_action_report_case(
                root,
                action=CODE_QUALITY_ACTION,
                step_name="Analyze source and write SARIF",
                working_directory=nested,
                paths="finding.py",
                report_script=f"""
                #!/bin/sh
                printf '%s\\n' "$@" > '{arguments}'
                printf '%s' '{report}'
                """,
                output="report.sarif",
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            passed = arguments.read_text(encoding="utf-8").splitlines()
            self.assertEqual(passed[-2:], ["--", "packages/foo/finding.py"])
            published = json.loads(
                (nested / "report.sarif").read_text(encoding="utf-8")
            )
            uri = published["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
                "artifactLocation"
            ]["uri"]
            self.assertEqual(uri, "packages/foo/finding.py")


if __name__ == "__main__":
    unittest.main()
