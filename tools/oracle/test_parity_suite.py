import io
import json
import sys
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import parity_suite


class ParitySuiteFailClosedTests(unittest.TestCase):
    def test_fixture_inventory_includes_jsx_and_tsx_variants(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("one.js", "two.jsx", "ignored.ts"):
                (root / name).touch()

            self.assertEqual(
                parity_suite.fixture_file_names("oracle-js", root),
                ["one.js", "two.jsx"],
            )

    def test_rust_scanner_keeps_native_rule_identity_across_plugin_versions(self):
        command = parity_suite.local_scanner_command("/scanner", "oracle-rust", "/work")

        self.assertIn("-Dsonar.rust.clippy.enabled=true", command)
        self.assertIn("-Dsonar.rust.clippy.enable=true", command)
        self.assertFalse(any("clippyReport.reportPaths" in arg for arg in command))

    def test_podman_scanner_maps_caller_for_private_working_directory(self):
        command = parity_suite.podman_scanner_command(
            "/podman", "oracle-py", Path("/source"), Path("/working")
        )

        self.assertIn("--userns=keep-id", command)
        self.assertIn("/working:/tmp/scannerwork:Z", command)

    def test_rust_podman_scanner_uses_configured_immutable_image(self):
        image = "localhost/hoonarqube-sonar-rust-scanner@sha256:" + "a" * 64
        with (
            mock.patch.dict(
                parity_suite.os.environ,
                {"SONAR_ORACLE_RUST_SCANNER_IMAGE_DIGEST": image},
                clear=True,
            ),
            mock.patch.object(parity_suite.Path, "is_dir", return_value=True),
            mock.patch.object(
                parity_suite, "ensure_rust_scanner_image", return_value=True
            ) as ensure,
        ):
            command = parity_suite.podman_scanner_command(
                "/podman", "oracle-rust", Path("/source"), Path("/working")
            )

        self.assertEqual(command[command.index("-w") + 2], image)
        self.assertIn("RUSTFLAGS", command)
        ensure.assert_called_once_with()

    def test_rust_scanner_retains_denied_diagnostics_without_aborting_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname = "oracle-lint-control"\nversion = "0.0.0"\n'
                'edition = "2024"\n',
                encoding="utf-8",
            )
            source = (
                "fn main() {\n    let _ = std::sync::Mutex::new(1).lock();\n"
                '    println!("retained");\n}\n'
            )
            control = root / "src/main.rs"
            control.write_text(source, encoding="utf-8")
            scanner = root / "scanner"
            scanner.write_text(
                "#!/bin/sh\nexec cargo clippy --offline --quiet --message-format=json "
                "-- -A clippy::all -Wclippy::print_stdout\n",
                encoding="utf-8",
            )
            scanner.chmod(0o755)
            with mock.patch.dict(
                parity_suite.os.environ,
                {
                    "CARGO_TARGET_DIR": str(root / "target"),
                    "CARGO_ENCODED_RUSTFLAGS": "--deny=warnings",
                },
            ):
                result = parity_suite.run_generic_scanner(
                    "oracle-rust", root, root / "work", "", str(scanner), None
                )
            self.assertEqual(result.returncode, 0, result.stderr)
            diagnostics = [
                record["message"]
                for line in result.stdout.splitlines()
                if (record := json.loads(line)).get("reason") == "compiler-message"
            ]
            codes = {
                message["code"]["code"]: message["level"]
                for message in diagnostics
                if message.get("code")
            }
            self.assertEqual(codes.get("let_underscore_lock"), "warning")
            self.assertEqual(codes.get("clippy::print_stdout"), "warning")
            self.assertFalse(
                any(message["level"] == "error" for message in diagnostics)
            )
            self.assertEqual(control.read_text(encoding="utf-8"), source)

    def test_rust_pinned_image_refuses_mutable_tag_fallback(self):
        image = "localhost/hoonarqube-sonar-rust-scanner@sha256:" + "b" * 64

        def run(command, **kwargs):
            if command == ["podman", "image", "exists", image]:
                return mock.Mock(returncode=1, stdout="", stderr="")
            if command == [
                "podman",
                "image",
                "exists",
                parity_suite.RUST_SCANNER_IMAGE,
            ]:
                return mock.Mock(returncode=0, stdout="", stderr="")
            self.fail(f"unexpected image command: {command!r}")

        with (
            mock.patch.dict(
                parity_suite.os.environ,
                {"SONAR_ORACLE_RUST_SCANNER_IMAGE_DIGEST": image},
                clear=True,
            ),
            mock.patch.object(parity_suite.Path, "is_dir", return_value=True),
            mock.patch.object(parity_suite.subprocess, "run", side_effect=run) as probe,
        ):
            self.assertIsNone(
                parity_suite.podman_scanner_command(
                    "/podman", "oracle-rust", Path("/source"), Path("/working")
                )
            )

        self.assertEqual(
            [call.args[0] for call in probe.call_args_list],
            [["podman", "image", "exists", image]],
        )

    def test_empty_oracle_token_fails_closed(self):
        with (
            mock.patch.dict(
                parity_suite.os.environ, {"SONAR_ORACLE_TOKEN": ""}, clear=True
            ),
            self.assertRaisesRegex(RuntimeError, "must not be empty"),
        ):
            parity_suite.oracle_token()

    def test_missing_generic_scanner_fails_closed(self):
        with (
            mock.patch.dict(parity_suite.os.environ, {}, clear=True),
            mock.patch.object(parity_suite.shutil, "which", return_value=None),
        ):
            self.assertFalse(parity_suite.scan_project("oracle-py"))

    def test_search_page_retries_transient_errors_without_retrying_bad_json(self):
        transient_http = urllib.error.HTTPError(
            "https://sonar.test/issues", 503, "busy", {}, io.BytesIO(b"busy")
        )
        transient_network = urllib.error.URLError("offline")
        with (
            mock.patch.object(
                parity_suite,
                "request_json",
                side_effect=[transient_http, transient_network, {"issues": []}],
            ) as request,
            mock.patch.object(parity_suite.time, "sleep") as sleep,
        ):
            self.assertEqual(
                parity_suite._search_page(object(), "issues"), {"issues": []}
            )

        self.assertEqual(request.call_count, 3)
        sleep.assert_has_calls([mock.call(5), mock.call(10)])
        self.assertTrue(transient_http.closed)

        with (
            mock.patch.object(
                parity_suite,
                "request_json",
                side_effect=ValueError("invalid Sonar API JSON"),
            ) as request,
            mock.patch.object(parity_suite.time, "sleep") as sleep,
            self.assertRaisesRegex(ValueError, "invalid Sonar API JSON"),
        ):
            parity_suite._search_page(object(), "issues")
        request.assert_called_once()
        sleep.assert_not_called()

    def test_search_page_decodes_final_http_error_body_and_does_not_retry(self):
        error = urllib.error.HTTPError(
            "https://sonar.test/issues",
            401,
            "unauthorized",
            {},
            io.BytesIO(b'{"errors":[{"msg":"bad component"}]}'),
        )
        output = io.StringIO()
        with (
            mock.patch.object(parity_suite, "request_json", side_effect=error),
            mock.patch.object(parity_suite.time, "sleep") as sleep,
            redirect_stdout(output),
            self.assertRaises(urllib.error.HTTPError),
        ):
            parity_suite._search_page(object(), "issues")

        self.assertIn('401: {"errors":[{"msg":"bad component"}]}', output.getvalue())
        sleep.assert_not_called()
        self.assertTrue(error.closed)

    def test_artifact_evidence_round_trip_is_exact(self):
        report = {"schema_version": 2, "project": "oracle-py", "issues": []}
        with mock.patch.object(
            parity_suite, "artifact_input_sha256", return_value="fingerprint"
        ):
            parity_suite.attach_artifact_evidence(report, "oracle-py", "sq")
            parity_suite.validate_artifact_evidence(report, "oracle-py", "sq")

        self.assertEqual(
            report["oracle_evidence"],
            {
                "project": "oracle-py",
                "kind": "sq",
                "input_sha256": "fingerprint",
            },
        )

    def test_typescript_helper_fingerprints_ignore_cache_but_track_native_source(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory)
            project = repo / "oracle-ts"
            source = project / "src" / "main.ts"
            config = project / "tsconfig.json"
            dependency = project / "package.json"
            other_config = project / ".hoonarqube" / "analysis.json"
            generated_helper = (
                project
                / ".hoonarqube"
                / "semantic"
                / "typescript"
                / "semantic-helper-v1.cjs"
            )
            tracked_helper = (
                repo / "tools" / "semantic" / "typescript" / "semantic-helper.cjs"
            )
            catalog = repo / "catalog" / "rules" / "typescript.json"
            files = {
                source: "export const value = 1;\n",
                config: '{"compilerOptions":{"strict":true}}\n',
                dependency: '{"dependencies":{"typescript":"6.0.3"}}\n',
                other_config: '{"keep":true}\n',
                tracked_helper: "tracked-helper-v1\n",
                catalog: "{}\n",
                repo / "Cargo.toml": "[workspace]\n",
                repo / "Cargo.lock": "# lock\n",
            }
            for path, content in files.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            (repo / "crates").mkdir()

            with mock.patch.object(parity_suite, "REPO", repo):
                baseline = parity_suite.artifact_input_sha256(
                    "oracle-ts", "ours", project_dir=project
                )
                generated_helper.parent.mkdir(parents=True, exist_ok=True)
                generated_helper.write_text("generated-helper-v1\n", encoding="utf-8")
                self.assertEqual(
                    baseline,
                    parity_suite.artifact_input_sha256(
                        "oracle-ts", "ours", project_dir=project
                    ),
                )
                generated_helper.write_text("generated-helper-v2\n", encoding="utf-8")
                self.assertEqual(
                    baseline,
                    parity_suite.artifact_input_sha256(
                        "oracle-ts", "ours", project_dir=project
                    ),
                )

                tracked_helper.write_text("tracked-helper-v2\n", encoding="utf-8")
                self.assertNotEqual(
                    baseline,
                    parity_suite.artifact_input_sha256(
                        "oracle-ts", "ours", project_dir=project
                    ),
                )
                tracked_helper.write_text("tracked-helper-v1\n", encoding="utf-8")
                for path in (source, config, dependency, other_config):
                    original = path.read_text(encoding="utf-8")
                    path.write_text(original + "changed\n", encoding="utf-8")
                    with self.subTest(path=path.relative_to(repo)):
                        self.assertNotEqual(
                            baseline,
                            parity_suite.artifact_input_sha256(
                                "oracle-ts", "ours", project_dir=project
                            ),
                        )
                    path.write_text(original, encoding="utf-8")

                tracked_helper.unlink()
                with self.assertRaisesRegex(ValueError, "oracle input does not exist"):
                    parity_suite.artifact_input_sha256(
                        "oracle-ts", "ours", project_dir=project
                    )

    def test_fixture_inventory_rejects_nested_basename_collisions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").mkdir()
            (root / "two").mkdir()
            (root / "one" / "duplicate.py").touch()
            (root / "two" / "duplicate.py").touch()

            with self.assertRaisesRegex(ValueError, "basename collision"):
                parity_suite.fixture_file_names("oracle-py", root)

    def test_csharp_native_workspace_is_scan_base_and_bypasses_gitignore(self):
        output = Path("/tmp/native-csharp-test")
        with mock.patch.object(parity_suite, "SONAR_URL", "http://sonar.test"):
            command = parity_suite.csharp_begin_command(
                "/scanner", "oracle-cs", output, "/d:sonar.login=token"
            )

        self.assertIn(f"/d:sonar.projectBaseDir={output}", command)
        self.assertIn("/d:sonar.scm.exclusions.disabled=true", command)
        self.assertIn("/d:sonar.host.url=http://sonar.test", command)

    def test_csharp_failed_native_build_fails_closed_after_scanner_end(self):
        def completed(code, output=""):
            return mock.Mock(returncode=code, stdout=output, stderr="")

        with (
            mock.patch.dict(
                parity_suite.os.environ,
                {"SONAR_DOTNET_SCANNER": "/scanner"},
                clear=True,
            ),
            mock.patch.object(parity_suite.Path, "is_file", return_value=True),
            mock.patch.object(parity_suite.shutil, "which", return_value="/dotnet"),
            mock.patch.object(parity_suite, "oracle_token", return_value="token"),
            mock.patch.object(
                parity_suite, "sq_api", return_value={"version": "9.9.8"}
            ),
            mock.patch.object(
                parity_suite,
                "generate_solution",
                return_value=(Path("Oracle.slnx"), 1),
            ),
            mock.patch.object(
                parity_suite.subprocess,
                "run",
                side_effect=[
                    completed(0),
                    completed(1, "compiler error"),
                    completed(0),
                ],
            ) as run,
        ):
            self.assertFalse(parity_suite.scan_csharp_project("oracle-cs"))

        self.assertEqual(run.call_count, 3)
        self.assertEqual(run.call_args_list[-1].args[0][1], "end")

    def test_result_tag_keeps_server_artifacts_separate(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(parity_suite, "RESULTS", Path(directory)),
            mock.patch.object(parity_suite, "RESULT_TAG", "frozen-2025_4"),
        ):
            self.assertEqual(
                parity_suite.result_path("oracle-py", "sq").name,
                "oracle-py.frozen-2025_4.sq.json",
            )

    def test_artifact_evidence_rejects_stale_or_missing_untagged_results(self):
        with (
            mock.patch.object(parity_suite, "RESULT_TAG", ""),
            mock.patch.object(
                parity_suite, "artifact_input_sha256", return_value="current"
            ),
        ):
            with self.assertRaisesRegex(ValueError, "lacks oracle input"):
                parity_suite.validate_artifact_evidence({}, "oracle-py", "sq")
            with self.assertRaisesRegex(ValueError, "stale or mismatched"):
                parity_suite.validate_artifact_evidence(
                    {
                        "oracle_evidence": {
                            "project": "oracle-py",
                            "kind": "sq",
                            "input_sha256": "old",
                        }
                    },
                    "oracle-py",
                    "sq",
                )

    def test_result_tag_cannot_bypass_missing_artifact_evidence(self):
        with (
            mock.patch.object(parity_suite, "RESULT_TAG", "community-26_8"),
            self.assertRaisesRegex(ValueError, "lacks oracle input"),
        ):
            parity_suite.validate_artifact_evidence({}, "oracle-py", "sq")

    def test_result_filename_does_not_mutate_filtered_projects(self):
        projects = ["oracle-py"]
        with mock.patch.object(parity_suite, "RESULT_TAG", "frozen-2025_4"):
            result_name = parity_suite.result_filename(projects)
            report = parity_suite.build_report(projects, {}, {}, set(), {}, {})

        self.assertEqual(result_name, "parity_divergences.oracle-py.frozen-2025_4.json")
        self.assertEqual(projects, ["oracle-py"])
        self.assertEqual(report["projects"], ["oracle-py"])

    def test_standard_issue_fetch_validates_and_reads_every_page(self):
        pages = [
            {
                "issues": [
                    {
                        "key": "first-issue",
                        "rule": "python:S1",
                        "component": "oracle-py:src/one.py",
                        "message": "one",
                    }
                ],
                "paging": {"pageIndex": 1, "pageSize": 1, "total": 2},
            },
            {
                "issues": [
                    {
                        "key": "second-issue",
                        "rule": "python:S2",
                        "component": "oracle-py:src/two.py",
                        "message": "two",
                    }
                ],
                "paging": {"pageIndex": 2, "pageSize": 1, "total": 2},
            },
        ]
        with mock.patch.object(parity_suite, "_issue_page", side_effect=pages) as page:
            issues = parity_suite._fetch_standard_issues("oracle-py")

        self.assertEqual(
            [issue["rule"] for issue in issues], ["python:S1", "python:S2"]
        )
        self.assertEqual([call.args[1] for call in page.call_args_list], [1, 2])

    def test_hotspot_fetch_rejects_missing_items_list(self):
        malformed = {"paging": {"pageIndex": 1, "pageSize": 500, "total": 0}}
        with (
            mock.patch.object(parity_suite, "_hotspot_page", return_value=malformed),
            self.assertRaisesRegex(ValueError, "must contain a hotspots list"),
        ):
            parity_suite._fetch_hotspots("oracle-py")

    def test_paginated_fetch_rejects_repeated_keys_with_stable_totals(self):
        for item_key, hotspot in [("issues", False), ("hotspots", True)]:
            item = {
                "key": "repeated-key",
                "ruleKey" if hotspot else "rule": "python:S1",
                "message": "finding",
                "component": "oracle-py:src/a.py",
            }

            def page_loader(page, *, key=item_key, record=item):
                return {
                    key: [record],
                    "paging": {"pageIndex": page, "pageSize": 1, "total": 2},
                }

            with (
                self.subTest(item_key=item_key),
                self.assertRaisesRegex(ValueError, "duplicate.*key"),
            ):
                parity_suite._fetch_paginated(
                    page_loader, item_key, hotspot=hotspot, expected_project="oracle-py"
                )

    def test_invalid_remote_page_becomes_an_invalid_project_artifact(self):
        with (
            mock.patch.object(parity_suite, "scan_project", return_value=True),
            mock.patch.object(
                parity_suite, "fetch_issues", side_effect=ValueError("truncated page")
            ),
        ):
            rows, issues, error = parity_suite.project_rows("oracle-py", quick=False)

        self.assertIsNone(rows)
        self.assertIsNone(issues)
        self.assertEqual(error, "truncated page")

    def test_full_run_csharp_fetch_allows_approved_project_issues(self):
        with (
            mock.patch.object(parity_suite, "scan_project", return_value=True),
            mock.patch.object(
                parity_suite, "fetch_issues", side_effect=ValueError("truncated page")
            ) as fetch,
        ):
            rows, issues, error = parity_suite.project_rows("oracle-cs", quick=False)

        fetch.assert_called_once_with("oracle-cs", allow_project_issues=True)
        self.assertIsNone(rows)
        self.assertIsNone(issues)
        self.assertEqual(error, "truncated page")

    def test_native_exit2_keeps_incomplete_report_and_exact_execution(self):
        report = {
            "schema_version": 1,
            "files": [
                {
                    "path": "/fixture/s112_bad.py",
                    "issues": [
                        {
                            "rule_key": "python:S112",
                            "message": "generic exception",
                            "range": {
                                "start": {"line": 1, "column": 0},
                                "end": {"line": 1, "column": 4},
                            },
                        }
                    ],
                }
            ],
            "project": {
                "complete": False,
                "warnings": ["assessment: parser failed"],
                "files": [
                    {
                        "path": "src/s112_bad.py",
                        "status": "failed",
                    }
                ],
            },
        }
        completed = mock.Mock(
            returncode=2,
            stdout=json.dumps(report, separators=(",", ":")),
            stderr="parser failed\n",
        )
        context = {"status": "SYNTAX_ONLY", "kind": "python"}
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(parity_suite.subprocess, "run", return_value=completed),
            mock.patch.object(parity_suite, "attach_artifact_evidence"),
            mock.patch.object(parity_suite, "attach_artifact_provenance"),
            mock.patch.object(parity_suite, "validate_artifact_provenance"),
        ):
            output = Path(directory) / "ours.json"
            self.assertEqual(
                parity_suite._execute_ours(
                    "oracle-py",
                    ["/scanner", "analyze", "--format", "json"],
                    output,
                    context,
                ),
                output,
            )
            self.assertEqual(json.loads(output.read_text()), report)

        execution = context["execution"]
        self.assertEqual(execution["status"], "INCOMPLETE")
        self.assertEqual(execution["exit_code"], 2)
        self.assertEqual(execution["stdout"], completed.stdout)
        self.assertEqual(execution["stderr"], completed.stderr)
        self.assertEqual(execution["argv"], ["/scanner", "analyze", "--format", "json"])
        self.assertIs(execution["project_complete"], False)
        self.assertEqual(
            execution["reason"],
            "native project analysis is incomplete: assessment: parser failed",
        )

    def test_failed_empty_native_report_clears_stale_output(self):
        completed = mock.Mock(returncode=1, stdout="", stderr="fatal\n")
        context = {"status": "SYNTAX_ONLY", "kind": "python"}
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(parity_suite.subprocess, "run", return_value=completed),
        ):
            output = Path(directory) / "ours.json"
            output.write_text("stale")
            self.assertIsNone(
                parity_suite._execute_ours(
                    "oracle-py",
                    ["/scanner", "analyze", "--format", "json"],
                    output,
                    context,
                )
            )
            self.assertFalse(output.exists())

        execution = context["execution"]
        self.assertEqual(execution["status"], "INVALID")
        self.assertEqual(execution["exit_code"], 1)
        self.assertEqual(execution["stdout"], "")
        self.assertEqual(execution["stderr"], "fatal\n")
        self.assertIn("invalid report", execution["reason"])

    def test_failed_oracle_scan_fails_gate_without_using_stale_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory)
            argv = ["parity_suite.py", "--project", "oracle-py"]
            with (
                mock.patch.object(parity_suite, "RESULTS", results),
                mock.patch.object(parity_suite, "ensure_container"),
                mock.patch.object(parity_suite, "scan_project", return_value=False),
                mock.patch.object(parity_suite, "ce_rule_availability") as availability,
                mock.patch.object(sys, "argv", argv),
                self.assertRaises(SystemExit) as raised,
            ):
                parity_suite.main()

            self.assertEqual(raised.exception.code, 1)
            availability.assert_not_called()
            report = json.loads(
                (results / "parity_divergences.oracle-py.json").read_text()
            )
            self.assertEqual(
                report["invalid_artifacts"], {"oracle-py": "oracle scan failed"}
            )
            self.assertEqual(report["summary"], {})
            self.assertEqual(report["failure_count"], 1)


if __name__ == "__main__":
    unittest.main()
