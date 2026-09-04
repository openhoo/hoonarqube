#!/usr/bin/env python3
"""SonarQube Community parity suite.

Lifecycle: starts the SQ container if needed, waits for UP, ensures profiles
and projects, runs scanner + hoonarqube on every fixture set, fetches oracle
issues, diffs per rule key, and prints a parity report.

Usage:
  python3 tools/oracle/parity_suite.py            # full run, report to stdout
  python3 tools/oracle/parity_suite.py --quick    # reuse existing scan results
Exit code 0 when every rule is an exact PASS or an explicit unverified class
whose local bad/good contract passes.
"""

import base64
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from csharp_oracle import generate_solution
from rust_clippy import generate_report as generate_rust_clippy_report

from parity import (
    canonical_sonar_issue,
    classify_sq_misses,
    compare_reports,
    counts,
    failure_count,
    hoonarqube_findings,
    input_paths_sha256,
    load_infra_boundaries,
    parse_json,
    parse_report_task,
    read_json as strict_read_json,
    read_jsonl,
    read_secret_file,
    validate_oracle_report,
    validate_search_page,
    wait_for_compute_engine,
    write_json_atomic,
)

REPO = Path(__file__).resolve().parent.parent.parent
ORACLE = REPO / ".oracle/sonar"
RESULTS = ORACLE / "results"
SONAR_URL = os.environ.get("SONAR_ORACLE_URL", "http://127.0.0.1:9000").rstrip("/")
LANGS = ["oracle-py", "oracle-js", "oracle-ts", "oracle-cs", "oracle-go", "oracle-rust"]
EXT = {
    "oracle-py": "py",
    "oracle-js": "js",
    "oracle-ts": "ts",
    "oracle-cs": "cs",
    "oracle-go": "go",
    "oracle-rust": "rs",
}
FIXTURE_EXTENSIONS = {
    **{project: (extension,) for project, extension in EXT.items()},
    "oracle-js": ("js", "jsx"),
    "oracle-ts": ("ts", "tsx"),
}
CATALOG_LANGUAGE = {
    "py": "python",
    "js": "javascript",
    "ts": "typescript",
    "cs": "csharp",
    "go": "go",
    "rs": "rust",
    "rust": "rust",
}
SONAR_LANGUAGE = {
    "py": "py",
    "js": "js",
    "ts": "ts",
    "cs": "cs",
    "go": "go",
    "rs": "rust",
}
RESULT_TAG = os.environ.get("SONAR_ORACLE_RESULT_TAG", "")
RUST_SCANNER_IMAGE = "localhost/hoonarqube-sonar-rust-scanner:12.1.0.3233_8.0.1"
HTTP_TIMEOUT_SECONDS = 30
PROBE_TIMEOUT_SECONDS = 60
BUILD_TIMEOUT_SECONDS = 900
SCAN_TIMEOUT_SECONDS = 1800
if RESULT_TAG and not re.fullmatch(r"[a-zA-Z0-9_-]+", RESULT_TAG):
    raise RuntimeError(
        "SONAR_ORACLE_RESULT_TAG may contain only letters, digits, '_' and '-'"
    )


def ensure_rust_scanner_image():
    try:
        exists = subprocess.run(
            ["podman", "image", "exists", RUST_SCANNER_IMAGE],
            capture_output=True,
            text=True,
            timeout=PROBE_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print("  Rust scanner image inspection timed out")
        return False
    if exists.returncode == 0:
        return True
    try:
        built = subprocess.run(
            [
                "podman",
                "build",
                "-q",
                "-t",
                RUST_SCANNER_IMAGE,
                "-f",
                str(REPO / "tools/oracle/Containerfile.rust-scanner"),
                str(REPO),
            ],
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print("  Rust scanner image build timed out")
        return False
    if built.returncode != 0:
        print(
            f"  Rust scanner image build failed: {(built.stdout + built.stderr)[-1000:]}"
        )
        return False
    return True


def result_path(project, kind):
    if project not in LANGS or kind not in {"sq", "ours"}:
        raise ValueError(f"invalid oracle artifact identity: {project}/{kind}")
    tag = f".{RESULT_TAG}" if RESULT_TAG else ""
    return RESULTS / f"{project}{tag}.{kind}.json"


def _artifact_input_paths(project, kind, *, project_dir=None):
    project_dir = (
        Path(project_dir) if project_dir is not None else ORACLE / "projects" / project
    )
    language = CATALOG_LANGUAGE[EXT[project]]
    roots = [project_dir, REPO / "catalog/rules" / f"{language}.json"]
    if kind == "ours":
        roots.extend([REPO / "Cargo.toml", REPO / "Cargo.lock", REPO / "crates"])
    paths = []
    for root in roots:
        if root.is_dir():
            paths.extend(path for path in root.rglob("*") if path.is_file())
        elif root.is_file():
            paths.append(root)
        else:
            raise ValueError(f"oracle input does not exist: {root}")
    return sorted(set(paths), key=lambda path: path.as_posix())


def artifact_input_sha256(project, kind, *, project_dir=None):
    return input_paths_sha256(
        REPO, _artifact_input_paths(project, kind, project_dir=project_dir)
    )


def attach_artifact_evidence(report, project, kind, *, project_dir=None):
    if not isinstance(report, dict):
        raise ValueError(f"{kind} artifact must be an object")
    report["oracle_evidence"] = {
        "project": project,
        "kind": kind,
        "input_sha256": artifact_input_sha256(project, kind, project_dir=project_dir),
    }


def validate_artifact_evidence(report, project, kind, *, project_dir=None):
    evidence = report.get("oracle_evidence") if isinstance(report, dict) else None
    if not isinstance(evidence, dict):
        raise ValueError(f"{kind} artifact lacks oracle input fingerprint")
    expected = {
        "project": project,
        "kind": kind,
        "input_sha256": artifact_input_sha256(project, kind, project_dir=project_dir),
    }
    if evidence != expected:
        raise ValueError(f"stale or mismatched {kind} oracle artifact")


def fixture_file_names(project, fixture_dir):
    suffixes = {f".{extension}" for extension in FIXTURE_EXTENSIONS[project]}
    paths = sorted(
        path
        for path in fixture_dir.rglob("*")
        if path.is_file() and path.suffix in suffixes
    )
    names = [path.name for path in paths]
    if len(names) != len(set(names)):
        duplicates = sorted(name for name in set(names) if names.count(name) > 1)
        raise ValueError(f"fixture basename collision: {duplicates[0]}")
    return names


def catalog_rules(language):
    catalog = read_json(REPO / "catalog/rules" / f"{language}.json")
    if not isinstance(catalog, dict) or not isinstance(catalog.get("rules"), list):
        raise ValueError(f"{language} catalog must contain a rules list")
    rules = catalog["rules"]
    for index, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"{language} catalog rule {index} must be an object")
        key = rule.get("external_key")
        if not isinstance(key, str) or not key:
            raise ValueError(
                f"{language} catalog rule {index} external_key must be a string"
            )
        classification = rule.get("classification")
        if classification is not None and not isinstance(classification, str):
            raise ValueError(
                f"{language} catalog rule {index} classification must be a string"
            )
    return rules


def read_json(path):
    return strict_read_json(path)


def write_json(path, value, *, indent=None):
    write_json_atomic(path, value, indent=indent)


def request_json(request):
    with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
        return parse_json(response.read().decode("utf-8"), context="Sonar API JSON")


def auth_header():
    return "Basic " + base64.b64encode(f"{oracle_token()}:".encode()).decode()


def oracle_token():
    token = os.environ.get("SONAR_ORACLE_TOKEN")
    if token is None:
        token_path = ORACLE / "token"
        if not token_path.exists():
            raise RuntimeError("set SONAR_ORACLE_TOKEN or create .oracle/sonar/token")
        token = read_secret_file(token_path).strip()
    if not token:
        raise RuntimeError("SONAR_ORACLE_TOKEN must not be empty")
    return token


def sq_api(path, params=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    req = urllib.request.Request(f"{SONAR_URL}{path}{q}")
    req.add_header("Authorization", auth_header())
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
        raw = response.read()
    return parse_json(raw.decode("utf-8"), context=f"Sonar API {path}") if raw else {}


def sq_post(path, params):
    body = urllib.parse.urlencode(params).encode()
    req = urllib.request.Request(f"{SONAR_URL}{path}", data=body, method="POST")
    req.add_header("Authorization", auth_header())
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
        raw = response.read()
    return parse_json(raw.decode("utf-8"), context=f"Sonar API {path}") if raw else {}


def ensure_project_and_profile(proj):
    """Provision an isolated all-rules profile before the first scan."""
    language = SONAR_LANGUAGE[EXT[proj]]
    search = sq_api("/api/projects/search", {"projects": proj})
    if not any(
        component.get("key") == proj for component in search.get("components", [])
    ):
        sq_post("/api/projects/create", {"project": proj, "name": proj})

    profile_name = f"Hoonarqube Oracle All {language}"
    profiles = sq_api("/api/qualityprofiles/search", {"language": language}).get(
        "profiles", []
    )
    profile = next(
        (item for item in profiles if item.get("name") == profile_name), None
    )
    if profile is None:
        profile = sq_post(
            "/api/qualityprofiles/create",
            {"language": language, "name": profile_name},
        ).get("profile", {})
    profile_key = profile.get("key")
    if not profile_key:
        raise RuntimeError(f"quality profile creation returned no key for {proj}")
    sq_post(
        "/api/qualityprofiles/activate_rules",
        {"targetKey": profile_key, "languages": language},
    )
    if language == "go":
        sq_post(
            "/api/qualityprofiles/activate_rule",
            {
                "key": profile_key,
                "rule": "go:S1451",
                "params": "headerFormat=// Licensed",
            },
        )
    sq_post(
        "/api/qualityprofiles/add_project",
        {"language": language, "project": proj, "qualityProfile": profile_name},
    )


def ensure_container():
    if SONAR_URL == "http://127.0.0.1:9000":
        try:
            st = subprocess.run(
                ["podman", "inspect", "-f", "{{.State.Running}}", "sonarqube"],
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
            ).stdout.strip()
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("SonarQube container inspection timed out") from error
        if st != "true":
            print("starting sonarqube container...")
            subprocess.run(
                ["podman", "start", "sonarqube"],
                check=True,
                timeout=PROBE_TIMEOUT_SECONDS,
            )
            time.sleep(20)
    for _ in range(40):
        try:
            if sq_api("/api/system/status")["status"] == "UP":
                return
        except Exception:
            pass
        time.sleep(5)
    raise SystemExit("sonarqube did not reach UP state")


def local_scanner_command(scanner_path, proj, working):
    command = [
        scanner_path,
        f"-Dsonar.projectKey={proj}",
        f"-Dsonar.host.url={SONAR_URL}",
        f"-Dsonar.working.directory={working}",
    ]
    if proj == "oracle-rust":
        # Keep native rust:S rule identities. Importing the generated generic
        # Clippy report would create external_clippy:* issues instead.
        command.extend(
            [
                "-Dsonar.rust.clippy.enabled=true",
                "-Dsonar.rust.clippy.enable=true",
            ]
        )
    return command


def podman_scanner_command(podman_path, proj, source, working):
    scanner_image = (
        "docker.io/sonarsource/sonar-scanner-cli:"
        "12.1.0.3233_8.0.1@"
        "sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9"
    )
    command = [
        podman_path,
        "run",
        "--rm",
        "--userns=keep-id",
        "--network",
        "host",
        "-e",
        f"SONAR_HOST_URL={SONAR_URL}",
        "-e",
        "SONAR_TOKEN",
        "-v",
        f"{source}:/usr/src:Z",
        "-v",
        f"{working}:/tmp/scannerwork:Z",
    ]
    if proj == "oracle-rust":
        cargo_home = Path.home() / ".cargo"
        rustup_home = Path.home() / ".rustup"
        if not cargo_home.is_dir() or not rustup_home.is_dir():
            print("  scan oracle-rust: FAILED (Rustup Cargo toolchain not found)")
            return None
        if not ensure_rust_scanner_image():
            return None
        scanner_image = RUST_SCANNER_IMAGE
        command.extend(
            [
                "-v",
                f"{cargo_home}:/opt/cargo:ro",
                "-v",
                f"{rustup_home}:/opt/rustup:ro",
                "-e",
                "CARGO_HOME=/opt/cargo",
                "-e",
                "RUSTUP_HOME=/opt/rustup",
                "-e",
                "CARGO_TARGET_DIR=/tmp/cargo-target",
                "-e",
                "PATH=/opt/cargo/bin:/opt/sonar-scanner/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            ]
        )
    command.extend(
        [
            "-w",
            "/usr/src",
            scanner_image,
            f"-Dsonar.projectKey={proj}",
            "-Dsonar.working.directory=/tmp/scannerwork",
        ]
    )
    if proj == "oracle-rust":
        command.extend(
            [
                "-Dsonar.rust.clippy.enabled=true",
                "-Dsonar.rust.clippy.enable=true",
            ]
        )
    return command


def run_generic_scanner(proj, source, working, token, scanner_path, podman_path):
    env = dict(os.environ)
    env["SONAR_TOKEN"] = token
    if scanner_path and Path(scanner_path).is_file():
        command = local_scanner_command(scanner_path, proj, working)
        return subprocess.run(
            command,
            cwd=source,
            capture_output=True,
            text=True,
            timeout=SCAN_TIMEOUT_SECONDS,
            env=env,
        )
    command = podman_scanner_command(podman_path, proj, source, working)
    if command is None:
        return None
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=SCAN_TIMEOUT_SECONDS,
        env=env,
    )


def generate_clippy_oracle(proj, source, reports):
    if proj != "oracle-rust":
        return True
    try:
        count = generate_rust_clippy_report(source, Path(reports) / "clippy.json")
    except RuntimeError as error:
        print(f"  scan {proj}: FAILED (Clippy oracle: {error})")
        return False
    print(f"  Clippy fixtures: {count} validated diagnostic(s)")
    return True


def submitted_task_id(proj, result, working):
    if result is None:
        return None
    if "EXECUTION SUCCESS" not in result.stdout:
        print(f"  scan {proj}: FAILED\n{(result.stdout + result.stderr)[-1000:]}")
        return None
    task_file = Path(working) / "report-task.txt"
    if not task_file.exists():
        print(f"  scan {proj}: FAILED (missing report-task.txt)")
        return None
    try:
        return parse_report_task(task_file.read_text(), expected_project=proj)[
            "ceTaskId"
        ]
    except (OSError, UnicodeError, ValueError) as error:
        print(f"  scan {proj}: FAILED ({error})")
        return None


def wait_for_scan(proj, task_id, engine_label="compute engine"):
    try:
        status = wait_for_compute_engine(
            task_id,
            lambda value: (
                sq_api("/api/ce/task", {"id": value}).get("task", {}).get("status")
            ),
            lambda: time.sleep(1),
        )
    except (OSError, ValueError) as error:
        print(f"  scan {proj}: FAILED ({engine_label}: {error})")
        return False
    if status == "SUCCESS":
        print(f"  scan {proj}: SUCCESS ({engine_label} complete)")
        return True
    print(f"  scan {proj}: FAILED ({engine_label} {status})")
    return False


def scan_project(proj):
    if proj == "oracle-cs":
        return scan_csharp_project(proj)
    scanner = os.environ.get("SONAR_SCANNER", "sonar-scanner")
    scanner_path = shutil.which(scanner) if os.path.sep not in scanner else scanner
    podman_path = shutil.which("podman")
    if (not scanner_path or not Path(scanner_path).is_file()) and not podman_path:
        print(f"  scan {proj}: FAILED (set SONAR_SCANNER or install podman)")
        return False
    ensure_project_and_profile(proj)
    d = (ORACLE / "projects" / proj).resolve()
    token = oracle_token()
    with (
        tempfile.TemporaryDirectory(prefix=f"sqscanner-{proj}-") as working,
        tempfile.TemporaryDirectory(prefix=f"sqreports-{proj}-") as reports,
    ):
        if not generate_clippy_oracle(proj, d, reports):
            return False
        try:
            result = run_generic_scanner(
                proj, d, working, token, scanner_path, podman_path
            )
        except subprocess.TimeoutExpired:
            print(f"  scan {proj}: FAILED (scanner timed out)")
            return False
        task_id = submitted_task_id(proj, result, working)
        if task_id is None:
            return False
    return wait_for_scan(proj, task_id)


def csharp_begin_command(scanner_path, proj, output_dir, auth_arg):
    return [
        scanner_path,
        "begin",
        f"/k:{proj}",
        f"/d:sonar.host.url={SONAR_URL}",
        f"/d:sonar.projectBaseDir={output_dir}",
        "/d:sonar.scm.exclusions.disabled=true",
        auth_arg,
    ]


def csharp_scanner_path():
    scanner = os.environ.get("SONAR_DOTNET_SCANNER", "dotnet-sonarscanner")
    scanner_path = shutil.which(scanner) if os.path.sep not in scanner else scanner
    if not scanner_path or not Path(scanner_path).is_file():
        print("  scan oracle-cs: FAILED (set SONAR_DOTNET_SCANNER)")
        return None
    if not shutil.which("dotnet"):
        print("  scan oracle-cs: FAILED (dotnet SDK missing)")
        return None
    return scanner_path


def csharp_fixture_limit():
    value = os.environ.get("SONAR_CSHARP_FIXTURE_LIMIT")
    return int(value) if value else None


def native_csharp_task_id(
    proj, scanner_path, output_dir, solution, fixture_count, auth_arg
):
    begin = _native_begin(proj, scanner_path, output_dir, auth_arg)
    if begin is None or begin.returncode != 0:
        return None
    build, end = _native_build_and_end(
        proj, scanner_path, output_dir, solution, auth_arg
    )
    if end is None or end.returncode != 0 or build is None:
        return None
    print(
        f"  native build: {fixture_count} isolated fixture project(s), "
        f"exit {build.returncode}"
    )
    if build.returncode != 0:
        output = (build.stdout + "\n" + build.stderr).strip()
        print(f"  scan {proj}: FAILED (native build)\n{output[-2000:]}")
        return None
    return _native_report_task_id(proj, output_dir)


def _native_begin(proj, scanner_path, output_dir, auth_arg):
    try:
        begin = subprocess.run(
            csharp_begin_command(scanner_path, proj, output_dir, auth_arg),
            cwd=output_dir,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"  scan {proj}: FAILED (native begin timed out)")
        return None
    if begin.returncode != 0:
        print(f"  scan {proj}: FAILED (native begin)\n{begin.stdout[-500:]}")
    return begin


def _native_build_and_end(proj, scanner_path, output_dir, solution, auth_arg):
    build = None
    try:
        build = subprocess.run(
            [
                "dotnet",
                "build",
                str(solution),
                "--no-incremental",
                "--disable-build-servers",
            ],
            cwd=output_dir,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"  scan {proj}: FAILED (native build timed out)")
    # Once begin succeeds, end must always run so the scanner can finalize or
    # reject the analysis even when compilation failed.
    try:
        end = subprocess.run(
            [scanner_path, "end", auth_arg],
            cwd=output_dir,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"  scan {proj}: FAILED (native end timed out)")
        return build, None
    if end.returncode != 0:
        print(f"  scan {proj}: FAILED (native end)\n{end.stdout[-2000:]}")
    return build, end


def _native_report_task_id(proj, output_dir):
    task_file = output_dir / ".sonarqube/out/.sonar/report-task.txt"
    if not task_file.exists():
        print(f"  scan {proj}: FAILED (missing native report-task.txt)")
        return None
    try:
        return parse_report_task(task_file.read_text(), expected_project=proj)[
            "ceTaskId"
        ]
    except (OSError, UnicodeError, ValueError) as error:
        print(f"  scan {proj}: FAILED ({error})")
        return None


def scan_csharp_project(proj):
    scanner_path = csharp_scanner_path()
    if scanner_path is None:
        return False

    project_dir = (ORACLE / "projects" / proj).resolve()
    token = oracle_token()
    version = str(sq_api("/api/system/status").get("version", ""))
    auth_name = "sonar.login" if version.startswith("9.") else "sonar.token"
    auth_arg = f"/d:{auth_name}={token}"
    try:
        fixture_limit = csharp_fixture_limit()
    except ValueError:
        print(
            "  scan oracle-cs: FAILED (SONAR_CSHARP_FIXTURE_LIMIT must be an integer)"
        )
        return False
    with tempfile.TemporaryDirectory(
        prefix="native-csharp-", dir=REPO / "tools/oracle"
    ) as directory:
        output_dir = Path(directory)
        solution, fixture_count = generate_solution(
            project_dir, output_dir, limit=fixture_limit
        )
        task_id = native_csharp_task_id(
            proj,
            scanner_path,
            output_dir,
            solution,
            fixture_count,
            auth_arg,
        )
        if task_id is None:
            return False
    return wait_for_scan(proj, task_id, "native compute engine")


def _search_page(request, label):
    for attempt in range(5):
        try:
            return request_json(request)
        except urllib.error.HTTPError as error:
            body = error.read().decode(errors="replace")[:200]
            if error.code not in {400, 429, 502, 503, 504} or attempt == 4:
                print(f"  {label} API {error.code}: {body}")
                raise
        except urllib.error.URLError as error:
            if attempt == 4:
                print(f"  {label} API unavailable: {error.reason}")
                raise
        time.sleep(min(30, 5 * (attempt + 1)))
    raise AssertionError("bounded search retry loop exhausted")


def _issue_page(proj, page):
    q = urllib.parse.urlencode(
        {"componentKeys": proj, "resolved": "false", "ps": 500, "p": page}
    )
    req = urllib.request.Request(f"{SONAR_URL}/api/issues/search?{q}")
    req.add_header("Authorization", auth_header())
    return _search_page(req, "issues")


def _fetch_standard_issues(proj):
    return _fetch_paginated(
        lambda page: _issue_page(proj, page),
        "issues",
        hotspot=False,
        expected_project=proj,
    )


def _hotspot_page(proj, page):
    q = urllib.parse.urlencode({"projectKey": proj, "ps": 500, "p": page})
    req = urllib.request.Request(f"{SONAR_URL}/api/hotspots/search?{q}")
    req.add_header("Authorization", auth_header())
    return _search_page(req, "hotspots")


def _fetch_paginated(page_loader, item_key, *, hotspot, expected_project):
    issues, page = [], 1
    expected_total = expected_page_size = None
    while True:
        payload = page_loader(page)
        items, total, page_size, done = validate_search_page(
            payload,
            item_key,
            page,
            expected_total=expected_total,
            expected_page_size=expected_page_size,
        )
        if expected_total is None:
            expected_total, expected_page_size = total, page_size
        issues.extend(
            canonical_sonar_issue(
                issue, hotspot=hotspot, expected_project=expected_project
            )
            for issue in items
        )
        if done:
            return issues
        page += 1


def _fetch_hotspots(proj):
    return _fetch_paginated(
        lambda page: _hotspot_page(proj, page),
        "hotspots",
        hotspot=True,
        expected_project=proj,
    )


def fetch_issues(proj):
    issues = _fetch_standard_issues(proj)
    issues.extend(_fetch_hotspots(proj))
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = result_path(proj, "sq")
    report = {
        "schema_version": 2,
        "project": proj,
        "server": sq_api("/api/system/status"),
        "issues": issues,
    }
    attach_artifact_evidence(report, proj, "sq")
    validate_oracle_report(report, expected_project=proj)
    write_json(out, report, indent=1)
    return len(issues)


def run_ours(proj):
    # oracle-cs keeps sources at the project root; others under src/
    src = ORACLE / "projects" / proj / ("." if proj == "oracle-cs" else "src")
    out = result_path(proj, "ours")
    command = [
        "cargo",
        "run",
        "-q",
        "-p",
        "hoonarqube-cli",
        "--",
        "analyze",
        "--format",
        "json",
    ]
    if proj == "oracle-go":
        command.extend(["--go-header-format", "// Licensed"])
    command.append(str(src))
    try:
        r = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=REPO,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print(f"  ours {proj}: FAILED (analysis timed out)")
        return None
    if r.returncode != 0:
        print(f"  ours {proj}: FAILED\n{r.stderr[-500:]}")
        return None
    try:
        data = parse_json(r.stdout, context=f"hoonarqube {proj} report")
        hoonarqube_findings(data)
        attach_artifact_evidence(data, proj, "ours")
    except (OSError, ValueError) as error:
        print(f"  ours {proj}: FAILED (invalid report: {error})")
        return None
    write_json(out, data)
    return out


def diff(proj, lang, sq_json, ours_json):
    project_dir = ORACLE / "projects" / proj
    exp_path = project_dir / "expected.jsonl"
    expected = read_jsonl(exp_path)
    sq = read_json(sq_json)
    ours = read_json(ours_json)
    validate_oracle_report(sq, expected_project=proj)
    language = CATALOG_LANGUAGE[lang]
    rules = catalog_rules(language)
    catalog_keys = [rule["external_key"] for rule in rules]
    enterprise_unverified = [
        rule["external_key"]
        for rule in rules
        if rule.get("classification") == "enterprise-unverified"
    ]
    fixture_dir = project_dir if proj == "oracle-cs" else project_dir / "src"
    available_files = fixture_file_names(proj, fixture_dir)
    rows = compare_reports(
        expected,
        sq,
        ours,
        infra=load_infra_boundaries(REPO / "catalog/infra-boundaries.json"),
        catalog_keys=catalog_keys,
        available_files=available_files,
        enterprise_unverified=enterprise_unverified,
    )
    return counts(rows), rows


def parse_args():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--quick", action="store_true", help="reuse cached scan artifacts"
    )
    parser.add_argument(
        "--project",
        action="append",
        choices=LANGS,
        help="run only this oracle project (repeatable)",
    )
    return parser.parse_args()


def project_rows(proj, quick):
    lang = proj.replace("oracle-", "")
    print(f"[{proj}]")
    if not quick:
        if not scan_project(proj):
            return None, None, "oracle scan failed"
        try:
            issue_count = fetch_issues(proj)
        except (OSError, ValueError) as error:
            print(f"  invalid oracle response: {error}")
            return None, None, str(error)
        print(f"  oracle issues: {issue_count}")
        if run_ours(proj) is None:
            return None, None, "hoonarqube analysis failed"
    sq_json = result_path(proj, "sq")
    ours_json = result_path(proj, "ours")
    if not sq_json.exists() or not ours_json.exists():
        print("  missing artifacts; run without --quick")
        return None, None, "missing artifacts"
    try:
        sq_report = read_json(sq_json)
        ours_report = read_json(ours_json)
        validate_artifact_evidence(sq_report, proj, "sq")
        validate_artifact_evidence(ours_report, proj, "ours")
        project_counts, rows = diff(proj, lang, sq_json, ours_json)
        oracle_issues = validate_oracle_report(sq_report, expected_project=proj)
    except (OSError, ValueError) as error:
        print(f"  invalid artifact: {error}")
        return None, None, str(error)
    print(" ", project_counts)
    return rows, oracle_issues, None


def collect_project_rows(projects, quick):
    all_rows = {}
    invalid_artifacts = {}
    blocked_projects = set()
    for proj in projects:
        rows, oracle_issues, error = project_rows(proj, quick)
        if error is not None:
            invalid_artifacts[proj] = error
            continue
        assert rows is not None and oracle_issues is not None
        all_rows[proj] = rows
        if proj == "oracle-cs" and not oracle_issues:
            blocked_projects.add(proj)
    return all_rows, invalid_artifacts, blocked_projects


def ce_rule_availability(quick):
    """Build a cached rule-availability lookup for SQ miss classification."""
    if quick:
        return lambda _key: None
    status = sq_api("/api/system/status")
    version = status.get("version") if isinstance(status, dict) else None
    if not isinstance(version, str) or not version:
        raise ValueError("Sonar system status lacks version")
    identity = f"{SONAR_URL}\0{version}"
    server_cache_key = hashlib.sha256(identity.encode()).hexdigest()[:12]
    ce_cache_path = RESULTS / f"ce_rule_cache.{server_cache_key}.json"
    ce = read_json(ce_cache_path) if ce_cache_path.exists() else {}
    if not isinstance(ce, dict) or any(
        not isinstance(key, str) or not isinstance(value, bool)
        for key, value in ce.items()
    ):
        raise ValueError(f"invalid CE rule cache: {ce_cache_path}")

    def rule_in_ce(key):
        if key not in ce:
            try:
                sq_api("/api/rules/show", {"key": key})
                ce[key] = True
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    ce[key] = False
                else:
                    return None
            except (OSError, ValueError):
                return None
            write_json(ce_cache_path, ce)
        return ce[key]

    return rule_in_ce


def classify_missing_rules(all_rows, quick):
    if not all_rows:
        return {}, {}
    rule_in_ce = ce_rule_availability(quick)
    beyond_ce = {}
    unverified = {}
    for proj, rows in all_rows.items():
        beyond, unknown = classify_sq_misses(rows, rule_in_ce)
        if beyond:
            beyond_ce[proj] = beyond
        if unknown:
            unverified[proj] = unknown
    return beyond_ce, unverified


def status_keys(all_rows, status):
    return {
        proj: [row["key"] for row in rows if row["status"] == status]
        for proj, rows in all_rows.items()
        if any(row["status"] == status for row in rows)
    }


def result_filename(projects):
    result_parts = [] if projects == LANGS else list(projects)
    if RESULT_TAG:
        result_parts.append(RESULT_TAG)
    suffix = "." + ".".join(result_parts) if result_parts else ""
    return f"parity_divergences{suffix}.json"


def build_report(
    projects, all_rows, invalid_artifacts, blocked_projects, beyond_ce, unverified
):
    divergences = {
        proj: [row for row in rows if row["status"] != "PASS"]
        for proj, rows in all_rows.items()
    }
    final_counts = {proj: counts(rows) for proj, rows in all_rows.items()}
    n_failures = sum(failure_count(rows) for rows in all_rows.values())
    n_failures += len(invalid_artifacts) + len(blocked_projects)
    return {
        "schema_version": 2,
        "result_tag": RESULT_TAG or None,
        "projects": projects,
        "summary": final_counts,
        "failure_count": n_failures,
        "beyond_ce": beyond_ce,
        "oracle_unverified": unverified,
        "enterprise_unverified": status_keys(all_rows, "ENTERPRISE_UNVERIFIED"),
        "upstream_unverified": status_keys(all_rows, "UPSTREAM_UNVERIFIED"),
        "invalid_artifacts": invalid_artifacts,
        "blocked_projects": sorted(blocked_projects),
        "divergences": divergences,
    }


def print_summary(report, result_name):
    all_rows = {proj: rows for proj, rows in report["divergences"].items()}
    beyond_ce = report["beyond_ce"]
    invalid_artifacts = report["invalid_artifacts"]
    blocked_projects = report["blocked_projects"]
    # A native scanner run producing no C# findings is invalid evidence.
    cs_blocked = "oracle-cs" in blocked_projects
    n_beyond = sum(len(keys) for keys in beyond_ce.values())
    n_enterprise_unverified = sum(
        len(keys) for keys in report["enterprise_unverified"].values()
    )
    n_upstream_unverified = sum(
        len(keys) for keys in report["upstream_unverified"].values()
    )
    print(f"BEYOND-CE (rule absent from SonarQube Community): {n_beyond}")
    for proj, keys in beyond_ce.items():
        if keys:
            print(f"  {proj}: {len(keys)}")
    print(
        f"ENTERPRISE-UNVERIFIED (Community cannot certify): {n_enterprise_unverified}"
    )
    print(
        f"UPSTREAM-UNVERIFIED (current analyzer cannot certify): {n_upstream_unverified}"
    )
    if cs_blocked:
        print("C# ORACLE-BLOCKED: zero Sonar findings; parity is unverified")
    print("PARITY FAILURES:", report["failure_count"])
    for proj, rows in all_rows.items():
        for r in rows[:20]:
            print(f"  {proj} {r['key']} [{r['status']}]")
        if len(rows) > 20:
            print(f"  {proj}: {len(rows) - 20} more divergence(s); see {result_name}")
    for proj, reason in invalid_artifacts.items():
        print(f"  {proj} [INVALID_ARTIFACT] {reason}")


def main():
    args = parse_args()
    quick = args.quick
    projects = args.project or LANGS
    if not quick:
        ensure_container()
    all_rows, invalid_artifacts, blocked_projects = collect_project_rows(
        projects, quick
    )
    try:
        beyond_ce, unverified = classify_missing_rules(all_rows, quick)
    except (OSError, ValueError) as error:
        invalid_artifacts["rule_availability"] = str(error)
        beyond_ce, unverified = {}, {}
    report = build_report(
        projects,
        all_rows,
        invalid_artifacts,
        blocked_projects,
        beyond_ce,
        unverified,
    )
    result_name = result_filename(projects)
    RESULTS.mkdir(parents=True, exist_ok=True)
    write_json(RESULTS / result_name, report, indent=1)
    print_summary(report, result_name)
    sys.exit(0 if report["failure_count"] == 0 else 1)


if __name__ == "__main__":
    main()
