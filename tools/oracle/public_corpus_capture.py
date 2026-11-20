#!/usr/bin/env python3
"""Run static public corpus capture in the dedicated local Docker network."""

from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

import real_project_suite as oracle
from parity import read_secret_file, validate_search_page, write_json_atomic

SERVER_IMAGE = (
    "sonarqube@sha256:c0f1160bccfa435db4168c2d7df69af3c3ea7bfeb87395613014048fb33a68c1"
)
SERVER = "hq-corpus-reference-20261120"
NETWORK = "hq-corpus-20261120"
CACHE = "hq-corpus-scanner-cache-20261120"
SCANNER_URL = "http://reference:9000"
ZOD_HELPER = Path("packages/zod/.hoonarqube/semantic/typescript/semantic-helper-v1.cjs")
ZOD_HELPER_SHA256 = "b6a6cbb529c27133402fcdd6a0d043f5d640d75f542246364088653326f98f9f"


def utc():
    return datetime.now(UTC).isoformat()


class DockerSonar(oracle.Sonar):
    def __init__(self, auth):
        self.auth = "Basic " + base64.b64encode(auth.encode()).decode()

    def request(self, path, params=None, post=False):
        local = "http://127.0.0.1:9000" + path
        query = urllib.parse.urlencode(params or {})
        url = local if post or not query else local + "?" + query
        config = [
            f"header = {json.dumps('Authorization: ' + self.auth)}",
            f"url = {json.dumps(url)}",
        ]
        if post:
            config.extend(['request = "POST"', f"data = {json.dumps(query)}"])
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-i",
                SERVER,
                "curl",
                "-sS",
                "--max-time",
                "60",
                "-w",
                "\n%{http_code}",
                "-K",
                "-",
            ],
            input="\n".join(config) + "\n",
            capture_output=True,
            text=True,
            timeout=75,
            check=True,
        )
        body, _, code = result.stdout.rpartition("\n")
        if int(code) >= 400:
            raise urllib.error.HTTPError(
                url, int(code), f"Sonar API {path}", None, None
            )
        return json.loads(body) if body else None

    def pages(self, path, params, field, folder, label):
        records, seen = [], set()
        expected_total = expected_size = None
        for page in range(1, 1001):
            data = self.request(path, {**params, "p": page, "ps": 500})
            write_json_atomic(folder / f"{label}-page-{page}.json", data)
            # Legacy API endpoints, including rules/search, can expose paging
            # under top-level p/ps/total, retaining the same strict validation.
            validation = data
            if "paging" not in data and all(
                key in data for key in ("p", "ps", "total")
            ):
                validation = {
                    **data,
                    "paging": {
                        "pageIndex": data["p"],
                        "pageSize": data["ps"],
                        "total": data["total"],
                    },
                }
            items, expected_total, expected_size, done = validate_search_page(
                validation,
                field,
                page,
                expected_total=expected_total,
                expected_page_size=expected_size,
                seen_keys=seen,
            )
            records.extend(items)
            if done:
                return records
        raise ValueError("pagination limit reached")


def verify_local_reference(state):
    expected_id = (state / "docker/server.id").read_text().strip()
    details = json.loads(subprocess.check_output(["docker", "inspect", SERVER]))[0]
    network = json.loads(
        subprocess.check_output(["docker", "network", "inspect", NETWORK])
    )[0]
    if (
        details["Id"] != expected_id
        or details["Config"]["Image"] != SERVER_IMAGE
        or set(details["NetworkSettings"]["Networks"]) != {NETWORK}
        or network["Internal"] is not True
    ):
        raise ValueError(
            "refuse to bootstrap a server outside this state directory and network"
        )


def verify_checkout(row):
    root = oracle.verify_source(row)

    def git(*args):
        return subprocess.check_output(
            ["git", "-c", "core.hooksPath=/dev/null", *args],
            cwd=root,
            text=True,
            timeout=30,
        ).strip()

    if git("status", "--porcelain", "--untracked-files=all", "--ignored=matching"):
        raise ValueError(
            f"{row['name']}: checkout contains modified, untracked, or ignored files"
        )
    if git("rev-parse", "HEAD^{tree}") != row["tree"]:
        raise ValueError("source commit does not contain the manifest tree")
    if row["name"] == "zod" and os.path.lexists(root / ZOD_HELPER):
        raise ValueError("Zod: expected the helper path to be absent before analysis")
    if (root / "sonar-project.properties").exists():
        raise ValueError("refuse to load upstream sonar-project.properties")
    return root


def preserve_native_helper(row, root, folder):
    # Both recorded binaries materialize their embedded helper in Zod's
    # package root, even when the compiler is unavailable. The strict precheck
    # ensures it did not exist when this capture started.
    if row["name"] != "zod":
        return
    path = root / ZOD_HELPER
    if not path.exists() and not path.is_symlink():
        return
    if (
        not path.is_file()
        or path.resolve() != path
        or any(
            path.is_relative_to((root / scope).resolve()) for scope in row["sources"]
        )
        or oracle.digest(path) != ZOD_HELPER_SHA256
    ):
        raise ValueError("Zod: unexpected TypeScript helper; leaving checkout intact")
    archive = folder / "native-semantic-helper-v1.cjs"
    if archive.exists() or archive.is_symlink():
        raise ValueError("Zod: helper archive already exists")
    shutil.move(path, archive)


def bootstrap(state):
    verify_local_reference(state)
    path = state / "local-reference-token"
    if not path.exists():
        default = DockerSonar("admin:admin")
        password_path = state / "local-admin-password"
        if password_path.exists():
            password = read_secret_file(password_path).strip()
        else:
            password = secrets.token_urlsafe(40)
            password_path.write_text(password + "\n")
            default.request(
                "/api/users/change_password",
                {
                    "login": "admin",
                    "previousPassword": "admin",
                    "password": password,
                },
                post=True,
            )
        admin = DockerSonar("admin:" + password)
        token = admin.request(
            "/api/user_tokens/generate",
            {"name": "hq-public-corpus-20261120"},
            post=True,
        )["token"]
        path.write_text(token + "\n")
    return read_secret_file(path).strip()


def run_reference(row, root, folder, sonar, token, cache):
    key = row["project_key"]
    try:
        sonar.request("/api/components/show", {"component": key})
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
        sonar.request(
            "/api/projects/create",
            {"project": key, "name": key, "visibility": "private"},
            post=True,
        )
    command = [
        "docker",
        "run",
        "--rm",
        "--platform=linux/amd64",
        "--network",
        NETWORK,
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--memory=2500m",
        "--cpus=2",
        "-e",
        "SONAR_TOKEN",
        "-e",
        "SONAR_HOST_URL=" + SCANNER_URL,
        "-v",
        f"{root}:/usr/src:ro",
    ]
    if "java_classes" in row:
        command.extend(["-v", f"{row['java_classes']}:/usr/classes:ro"])
    if cache:
        command.extend(["-v", f"{CACHE}:/opt/sonar-scanner/.sonar"])
    command.extend(
        [
            oracle.SCANNER,
            f"-Dsonar.projectKey={key}",
            f"-Dsonar.projectVersion={row['commit']}",
            "-Dsonar.working.directory=/tmp/scanner-work",
            "-Dsonar.scm.disabled=true",
            "-Dsonar.cpd.exclusions=",
            "-Dsonar.sourceEncoding=UTF-8",
            "-Dsonar.sources=" + ",".join(row["sources"]),
            "-Dsonar.exclusions=" + ",".join(row["exclude"]),
        ]
    )
    if row["language"] == "java":
        command.extend(
            [
                "-Dsonar.java.binaries=/usr/classes",
                "-Dsonar.java.source=" + row["java_release"],
            ]
        )
    if row["language"] == "py":
        command.append("-Dsonar.python.version=3.13")
    if row["language"] == "rust":
        command.extend(
            [
                "-Dsonar.rust.clippy.enabled=false",
                "-Dsonar.rust.clippyReport.reportPaths=",
            ]
        )
    start = time.monotonic()
    scanner = oracle.run(
        command, folder, "scanner", root, {**os.environ, "SONAR_TOKEN": token}
    )
    oracle.wait_for_compute_engine(scanner, sonar, folder)
    scan_and_ce_seconds = time.monotonic() - start
    oracle.capture_reference(row, sonar, root, folder)
    oracle.verify_reference_files(root, folder)
    oracle.verify_source(row)
    return {
        "status": "complete",
        "scanner_and_ce_seconds": round(scan_and_ce_seconds, 3),
    }


def run_native(row, root, folder, binary):
    command = [
        str(binary),
        "analyze",
        *row["sources"],
        "--format",
        "json",
        "--profile",
        "sonar-parity",
    ]
    for pattern in row["exclude"]:
        command.extend(["--exclude", pattern])
    try:
        output = oracle.run(command, folder, "native", root)
    except RuntimeError:
        output = (folder / "native.stdout").read_text()
        try:
            output = json.loads(output)
        except (json.JSONDecodeError, UnicodeError):
            raise RuntimeError(
                "native execution failed without a valid report"
            ) from None
        if output.get("project", {}).get("complete") is not False:
            raise RuntimeError(
                "native command failed without an incomplete report"
            ) from None
    else:
        output = json.loads(output)
    write_json_atomic(folder / "native.json", output)
    files = []
    for entry in output["files"]:
        path = Path(oracle.normalized_path(entry["path"]))
        resolved = (root / path).resolve()
        if not resolved.is_relative_to(root):
            raise ValueError("native report path escapes the pinned checkout")
        files.append({"path": str(path), "sha256": oracle.digest(resolved)})
    write_json_atomic(folder / "native-source-files.json", files)
    if output.get("schema_version") != 1 or not output.get("parity"):
        raise ValueError("native report is missing the requested parity profile")
    return {
        "status": "complete" if output["project"]["complete"] is True else "incomplete",
        "metrics": output["project"]["metrics"],
        "files_reported": len(output["files"]),
        "issue_records": sum(len(f["issues"]) for f in output["files"]),
        "status_counts": {
            key: len([f for f in output["project"]["files"] if f["status"] == key])
            for key in sorted({f["status"] for f in output["project"]["files"]})
        },
    }


def execute(row, args, sonar, token):
    folder = args.output / row["name"]
    root = verify_checkout(row)
    if folder.resolve().is_relative_to(root):
        raise ValueError("capture output must stay outside the source checkout")
    folder.mkdir(parents=True, exist_ok=True)
    status = {
        "started_at_utc": utc(),
        "reference": {"status": "not_run"},
        "native": {"status": "not_run"},
    }
    write_json_atomic(folder / "source.json", row)
    for label in ("reference", "native"):
        try:
            if label == "reference":
                if row.get("reference_excluded"):
                    status[label] = {
                        "status": "not_run",
                        "reason": row["reference_excluded"],
                    }
                elif not args.native_only:
                    status[label] = run_reference(
                        row, root, folder, sonar, token, not args.no_shared_cache
                    )
            elif not args.reference_only:
                try:
                    status[label] = run_native(row, root, folder, args.binary)
                finally:
                    preserve_native_helper(row, root, folder)
        except Exception as error:  # noqa: BLE001 - retain per-tool failure evidence
            status[label] = {"status": "failed", "reason": str(error)}
        write_json_atomic(folder / "progress.json", status)
    verify_checkout(row)
    status["ended_at_utc"] = utc()
    write_json_atomic(folder / "progress.json", status)
    return status


def reference_environment(sonar):
    meta = {
        name: sonar.request(path)
        for name, path in {
            "server": "/api/system/status",
            "plugins": "/api/plugins/installed",
            "languages": "/api/languages/list",
            "navigation": "/api/navigation/global",
        }.items()
    }
    if meta["server"]["status"] != "UP":
        raise RuntimeError("reference SonarQube is not ready")
    for name, image in {"server": SERVER_IMAGE, "scanner": oracle.SCANNER}.items():
        fingerprint = subprocess.check_output(
            [
                "docker",
                "image",
                "inspect",
                image,
                "--format",
                "{{.Architecture}} {{.Os}} {{.Id}}",
            ],
            text=True,
        ).strip()
        meta[name + "_image"] = {"image": image, "platform_fingerprint": fingerprint}
    meta["captured_at_utc"] = utc()
    return meta


def selected_rows(args):
    rows = [
        row
        for row in json.loads(args.manifest.read_text())
        if not args.names or row["name"] in args.names
    ]
    if not rows:
        raise ValueError("nothing selected")
    names = [row["name"] for row in rows]
    if len(set(names)) != len(names):
        raise ValueError("duplicate corpus row name")
    if any((args.output / name / "progress.json").exists() for name in names):
        raise ValueError("use an unused output directory for selected rows")
    return rows


def execute_manifest(args, rows, sonar, token):
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {
            executor.submit(execute, row, args, sonar, token): row["name"]
            for row in rows
        }
        summary = {}
        for future in as_completed(futures):
            name = futures[future]
            try:
                status = future.result()
            except Exception as error:  # noqa: BLE001 - report each failed row
                status = {"status": "failed", "reason": str(error)}
            summary[name] = status
            print(name, json.dumps(status), flush=True)
            write_json_atomic(args.output / "run-summary.json", summary)
    states = {
        item["status"]
        for row in summary.values()
        for item in ([row] if "status" in row else [row["reference"], row["native"]])
    }
    return 1 if "failed" in states else (2 if "incomplete" in states else 0)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--names", nargs="+")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--reference-only", action="store_true")
    parser.add_argument("--native-only", action="store_true")
    parser.add_argument("--no-shared-cache", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    args.binary = args.binary.resolve()
    if args.native_only and args.reference_only:
        parser.error("select either native-only or reference-only")
    if not 1 <= args.jobs <= 3:
        parser.error("use 1 to 3 concurrent jobs")
    if args.native_only:
        sonar, token = None, ""
    else:
        token = bootstrap(args.state)
        sonar = DockerSonar(token + ":")
        write_json_atomic(
            args.output / "reference-environment.json", reference_environment(sonar)
        )
    write_json_atomic(
        args.output / "native-binary.json",
        {
            "path": str(args.binary),
            "sha256": oracle.digest(args.binary),
            "version": subprocess.check_output(
                [str(args.binary), "--version"], text=True
            ).strip(),
        },
    )
    return execute_manifest(args, selected_rows(args), sonar, token)


if __name__ == "__main__":
    raise SystemExit(main())
