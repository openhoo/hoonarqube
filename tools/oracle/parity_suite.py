#!/usr/bin/env python3
"""SonarQube Community parity suite.

Lifecycle: starts the SQ container if needed, waits for UP, ensures profiles
and projects, runs scanner + hoonarqube on every fixture set, fetches oracle
issues, diffs per rule key, and prints a parity report.

Usage:
  python3 tools/oracle/parity_suite.py            # full run, report to stdout
  python3 tools/oracle/parity_suite.py --quick    # reuse existing scan results
Exit code 0 only when every rule is an exact PASS or an explicitly approved
unverified class whose local bad/good contract passes; incomplete native runs
remain ORACLE_UNVERIFIED failures.
"""

import base64
import argparse
import shlex
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
from reference_matrix import build_reference_report, write_reference_report
from reference_provenance import (
    command_fingerprint,
    file_metadata,
    make_manifest,
    manifest_digest,
    package_metadata,
    tool_versions,
    validate_compatible_manifests,
    validate_manifest,
)

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
SCANNER_IMAGE = (
    "docker.io/sonarsource/sonar-scanner-cli:12.1.0.3233_8.0.1@"
    "sha256:23ca0f137965d9dff2198074043fd48d386280bc5d0ccac8c8349cea4cf096a9"
)
HTTP_TIMEOUT_SECONDS = 30
PROBE_TIMEOUT_SECONDS = 60
BUILD_TIMEOUT_SECONDS = 900
_IMMUTABLE_IMAGE_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_CSHARP_TIMEOUT_ENV = "HOONARQUBE_CSHARP_TIMEOUT_MS"
_DEFAULT_CSHARP_TIMEOUT_MS = 30_000
_TYPESCRIPT_PACKAGE_ENV = "HOONARQUBE_TYPESCRIPT_MODULE"
_EXPECTED_TS_CONFIG = {
    "compilerOptions": {
        "allowJs": False,
        "target": "es2020",
        "module": "commonjs",
        "jsx": "react-jsx",
    },
    "include": ["src/**/*.ts", "src/**/*.tsx"],
}


def _immutable_image_digest(name: str) -> str:
    value = os.environ.get(name)
    if value is None or _IMMUTABLE_IMAGE_RE.fullmatch(value) is None:
        raise ValueError(f"{name} must be an immutable @sha256 image reference")
    return value


SCAN_TIMEOUT_SECONDS = 1800
_NATIVE_REPORT_SCHEMA = 1


def _native_execution(
    native_context: dict[str, object],
    *,
    status: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    project_complete: bool | None,
    reason: str | None = None,
    argv: list[str] | None = None,
) -> None:
    """Record one invocation without discarding failed-process evidence."""
    execution: dict[str, object] = {
        "status": status,
        "cwd": str(native_context.get("cwd", REPO)),
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "project_complete": project_complete,
    }
    if reason is not None:
        execution["reason"] = reason
    if argv is not None:
        execution["argv"] = [str(argument) for argument in argv]
    native_context["execution"] = execution


def _native_stream(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _native_report_complete(report: object) -> bool:
    """Validate the native JSON envelope and return its project completeness."""
    if not isinstance(report, dict):
        raise ValueError("hoonarqube native report must be an object")
    schema = report.get("schema_version")
    if (
        not isinstance(schema, int)
        or isinstance(schema, bool)
        or schema != _NATIVE_REPORT_SCHEMA
    ):
        raise ValueError(
            f"hoonarqube native report schema {_NATIVE_REPORT_SCHEMA} required"
        )
    if not isinstance(report.get("files"), list):
        raise ValueError("hoonarqube native report must contain a files list")
    project = report.get("project")
    if not isinstance(project, dict):
        raise ValueError("hoonarqube native report must contain a project object")
    complete = project.get("complete")
    if not isinstance(complete, bool):
        raise ValueError("hoonarqube native report project.complete must be boolean")
    warnings = project.get("warnings")
    if warnings is not None and (
        not isinstance(warnings, list)
        or any(not isinstance(warning, str) for warning in warnings)
    ):
        raise ValueError("hoonarqube native report project.warnings must be strings")
    return complete


def _native_incomplete_reason(report: object) -> str:
    if isinstance(report, dict):
        project = report.get("project")
        if isinstance(project, dict):
            warnings = project.get("warnings")
            if isinstance(warnings, list):
                details = [warning for warning in warnings if isinstance(warning, str)]
                if details:
                    return "native project analysis is incomplete: " + "; ".join(
                        details
                    )
    return "native project analysis is incomplete"


RUN_PROVENANCE: dict[str, dict[str, object]] = {}
RUN_NATIVE_CONTEXT: dict[str, dict[str, object]] = {}
REFERENCE_ONLY = False
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
        if root.is_symlink():
            raise ValueError(f"oracle input must not be a symlink: {root}")
        if root.is_dir():
            for path in root.rglob("*"):
                if path.is_symlink():
                    raise ValueError(f"oracle input must not be a symlink: {path}")
                if path.is_file():
                    paths.append(path)
        elif root.is_file():
            if root.is_symlink():
                raise ValueError(f"oracle input must not be a symlink: {root}")
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


def _plugin_root() -> Path | None:
    value = os.environ.get("SONAR_ORACLE_PLUGIN_ROOT")
    if not value:
        return None
    root = Path(value).resolve()
    if not root.is_dir():
        raise ValueError(f"SONAR_ORACLE_PLUGIN_ROOT is not a directory: {root}")
    return root


def _profile_active_rules(proj: str, key: str) -> list[dict[str, object]]:
    rules: list[dict[str, object]] = []
    page = 1
    while True:
        response = sq_api(
            "/api/rules/search",
            {"qprofile": key, "activation": "true", "ps": 500, "p": page},
        )
        if not isinstance(response, dict) or not isinstance(
            response.get("rules"), list
        ):
            raise ValueError(f"invalid active-rule response for {proj}")
        for raw in response["rules"]:
            if not isinstance(raw, dict) or not isinstance(raw.get("key"), str):
                raise ValueError(f"invalid active rule in profile {key}")
            rules.append(
                {
                    field: raw[field]
                    for field in ("key", "severity", "params", "status", "type")
                    if field in raw
                }
            )
        paging = response.get("paging", {})
        if not isinstance(paging, dict):
            raise ValueError(f"invalid active-rule paging for {proj}")
        total = paging.get("total")
        page_size = paging.get("pageSize")
        if (
            not isinstance(total, int)
            or total < 0
            or not isinstance(page_size, int)
            or page_size <= 0
            or len(response["rules"]) > page_size
            or len(rules) > total
        ):
            raise ValueError(f"active-rule paging lacks exact totals for {proj}")
        if len(rules) == total:
            return rules
        if not response["rules"]:
            raise ValueError(f"active-rule response truncated for {proj}")
        page += 1


def _profile_snapshot(proj: str) -> dict[str, object]:
    language = SONAR_LANGUAGE[EXT[proj]]
    payload = sq_api("/api/qualityprofiles/search", {"project": proj})
    profiles = payload.get("profiles", []) if isinstance(payload, dict) else []
    profile = next(
        (
            item
            for item in profiles
            if isinstance(item, dict)
            and item.get("name") == f"Hoonarqube Oracle All {language}"
        ),
        None,
    )
    if profile is None:
        raise ValueError(
            f"project {proj} is not assigned Hoonarqube Oracle All {language}"
        )
    if not isinstance(profile, dict) or not isinstance(profile.get("key"), str):
        raise ValueError(f"cannot identify quality profile for {proj}")
    key = profile["key"]
    rules = _profile_active_rules(proj, key)
    catalog_keys = {
        rule["external_key"] for rule in catalog_rules(CATALOG_LANGUAGE[EXT[proj]])
    }
    active_keys = {str(item["key"]) for item in rules}
    activation_gaps = {
        "missing_catalog_rules": sorted(catalog_keys - active_keys),
        "extra_active_rules": sorted(active_keys - catalog_keys),
    }
    return {
        "key": key,
        "name": profile.get("name"),
        "language": profile.get("language", language),
        "active_rule_count": profile.get("activeRuleCount", len(rules)),
        "rules": sorted(rules, key=lambda item: str(item["key"])),
        "activation_gaps": activation_gaps,
    }


def _reference_executable_metadata() -> dict[str, object]:
    executable_value = os.environ.get("HOONARQUBE_EXECUTABLE")
    if executable_value:
        executable = Path(executable_value)
        if not executable.is_absolute():
            executable = REPO / executable
    else:
        target_value = os.environ.get("CARGO_TARGET_DIR", "target")
        target = Path(target_value)
        if not target.is_absolute():
            target = REPO / target
        executable = target / "debug" / "hoonarqube"
    if not executable.is_file() or executable.is_symlink():
        raise ValueError(
            "HOONARQUBE_EXECUTABLE or target/debug/hoonarqube is required "
            "for native provenance"
        )
    return file_metadata(executable, root=REPO)


def _reference_tools(proj: str, kind: str) -> tuple[dict[str, object], list[Path]]:
    tools: dict[str, object] = {
        "python": sys.version.split()[0],
        "scanner_image": SCANNER_IMAGE,
    }
    if kind == "ours":
        tools["hoonarqube_executable"] = _reference_executable_metadata()
    packages: list[Path] = []
    if proj == "oracle-cs":
        tools.update(tool_versions(include_dotnet=True))
        scanner_dll = os.environ.get("SONAR_DOTNET_SCANNER_DLL")
        analyzer_package = os.environ.get("SONAR_CSHARP_ANALYZER_PACKAGE")
        if not scanner_dll:
            raise ValueError("SONAR_DOTNET_SCANNER_DLL is required for C# provenance")

        scanner_path = Path(scanner_dll)
        tools["dotnet_scanner_dll"] = file_metadata(scanner_path, root=REPO)
        if not analyzer_package:
            raise ValueError(
                "SONAR_CSHARP_ANALYZER_PACKAGE is required for C# provenance"
            )
        packages.append(Path(analyzer_package))
    if proj == "oracle-go":
        tools.update(tool_versions(include_go=True))
    if proj == "oracle-rust":
        tools.update(tool_versions(include_rust=True))
        tools["rust_scanner_image"] = RUST_SCANNER_IMAGE
        digest = _immutable_image_digest("SONAR_ORACLE_RUST_SCANNER_IMAGE_DIGEST")
        tools["rust_scanner_image_digest"] = digest
        tools["rust_containerfile"] = file_metadata(
            REPO / "tools/oracle/Containerfile.rust-scanner", root=REPO
        )
    return tools, packages


def _typescript_fixture_paths() -> Path:
    project_root = (ORACLE / "projects" / "oracle-ts").resolve()
    config_path = project_root / "tsconfig.json"
    source_root = project_root / "src"
    if config_path.is_symlink() or not config_path.is_file():
        raise ValueError(f"TypeScript fixture tsconfig is unavailable: {config_path}")
    if source_root.is_symlink() or not source_root.is_dir():
        raise ValueError(
            f"TypeScript fixture source root is unavailable: {source_root}"
        )
    config = read_json(config_path)
    if config != _EXPECTED_TS_CONFIG:
        raise ValueError(
            "TypeScript fixture tsconfig identity mismatch; "
            f"expected {config_path} to describe only {source_root}"
        )
    if fixture_file_names("oracle-ts", source_root) == []:
        raise ValueError("TypeScript fixture source root is empty")
    return config_path


def _typescript_package_details() -> tuple[Path, dict[str, object], Path, Path]:
    module_value = os.environ.get(_TYPESCRIPT_PACKAGE_ENV)
    if not module_value:
        raise ValueError(
            f"{_TYPESCRIPT_PACKAGE_ENV} must point to the pinned TypeScript package"
        )
    module_path = Path(module_value)
    if module_path.is_symlink():
        raise ValueError(f"{_TYPESCRIPT_PACKAGE_ENV} must not point through a symlink")
    module_path = module_path.resolve()
    if not module_path.is_dir():
        raise ValueError(
            f"{_TYPESCRIPT_PACKAGE_ENV} must point to an installed package root"
        )
    package_json = module_path / "package.json"
    compiler = module_path / "lib" / "typescript.js"
    compiler_launcher = module_path / "bin" / "tsc"
    if (
        package_json.is_symlink()
        or not package_json.is_file()
        or compiler.is_symlink()
        or not compiler.is_file()
        or compiler_launcher.is_symlink()
        or not compiler_launcher.is_file()
    ):
        raise ValueError(f"pinned TypeScript package is incomplete: {module_path}")
    package = read_json(package_json)
    if (
        not isinstance(package, dict)
        or package.get("name") != "typescript"
        or package.get("version") != "6.0.3"
        or package.get("main") != "./lib/typescript.js"
    ):
        raise ValueError(
            f"pinned TypeScript package must be typescript 6.0.3: {package_json}"
        )
    return module_path, package, package_json, compiler


def _typescript_node_fingerprint() -> dict[str, object]:
    node = shutil.which("node")
    if not node or not Path(node).is_file():
        raise ValueError("node is required for TypeScript semantic replay")
    node_fingerprint = command_fingerprint([node])
    if (
        node_fingerprint.get("available") is not True
        or node_fingerprint.get("version_exit") != 0
    ):
        raise ValueError("node version fingerprint failed")
    return node_fingerprint


def _typescript_native_context() -> dict[str, object]:
    config_path = _typescript_fixture_paths()
    module_path, package, package_json, compiler = _typescript_package_details()
    node_fingerprint = _typescript_node_fingerprint()
    return {
        "status": "SEMANTIC_REQUESTED",
        "kind": "typescript",
        "semantic_requested": True,
        "typescript_project": file_metadata(config_path, root=REPO),
        "typescript_project_path": str(config_path),
        "typescript_module": str(module_path),
        "typescript_package": {
            "name": package["name"],
            "version": package["version"],
            "root": str(module_path),
            "package_json": package_metadata(package_json),
            "compiler": file_metadata(compiler),
        },
        "node": node_fingerprint,
    }


def _csharp_workspace_project_files(projects: Path) -> list[Path]:
    files: list[Path] = []
    for path in projects.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"retained C# workspace contains a symlink: {path}")
        try:
            relative = path.relative_to(projects)
        except ValueError as error:
            raise ValueError(
                f"retained C# project path escaped workspace: {path}"
            ) from error
        if not path.is_file() or any(part in {"bin", "obj"} for part in relative.parts):
            continue
        if path.suffix.lower() in {".cs", ".csproj"}:
            files.append(path)
    return files


def _csharp_workspace_static_files(workspace: Path) -> list[Path]:
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError(f"retained C# workspace is unavailable: {workspace}")
    solution = workspace / "Oracle.slnx"
    if solution.is_symlink() or not solution.is_file():
        raise ValueError(f"retained C# solution is unavailable: {solution}")
    projects = workspace / "projects"
    if projects.is_symlink() or not projects.is_dir():
        raise ValueError(f"retained C# projects directory is unavailable: {projects}")
    files = [solution]
    editor_config = workspace / ".editorconfig"
    if editor_config.exists() or editor_config.is_symlink():
        if editor_config.is_symlink() or not editor_config.is_file():
            raise ValueError(
                f"retained C# config is not a regular file: {editor_config}"
            )
        files.append(editor_config)
    files.extend(_csharp_workspace_project_files(projects))
    return sorted(set(files), key=lambda path: _csharp_relative(path, workspace))


def _server_snapshot() -> tuple[dict[str, object], list[dict[str, object]]]:
    status = sq_api("/api/system/status")
    if not isinstance(status, dict):
        raise ValueError("Sonar system status must be an object")
    plugins = sq_api("/api/plugins/installed").get("plugins")
    if not isinstance(plugins, list):
        raise ValueError("Sonar plugin response must contain a plugins list")
    image = _immutable_image_digest("SONAR_ORACLE_IMAGE_DIGEST")
    server = {
        "url": SONAR_URL,
        "id": status.get("id"),
        "version": status.get("version"),
        "status": status.get("status"),
        "image": image,
    }
    if not isinstance(server["id"], str) or not isinstance(server["version"], str):
        raise ValueError("Sonar system status lacks stable identity")
    return server, [item for item in plugins if isinstance(item, dict)]


def _reference_parameters(proj: str, kind: str) -> dict[str, object]:
    params: dict[str, object] = {
        "project_key": proj,
        "language": SONAR_LANGUAGE[EXT[proj]],
        "kind": kind,
        "scanner_image": SCANNER_IMAGE,
        "sonar_scm_exclusions_disabled": proj == "oracle-cs",
    }
    if proj == "oracle-go":
        params["sonar.go.headerFormat"] = "// Licensed"
    if proj == "oracle-rust":
        params["sonar.rust.clippy.enabled"] = True
        params["sonar.rust.clippy.enable"] = True
    if proj == "oracle-cs":
        params.update(
            {
                "target_framework": "net10.0",
                "lang_version": "preview",
                "nullable": "enable",
                "allow_unsafe_blocks": True,
                "enable_default_compile_items": False,
            }
        )
    return params


_CSHARP_WORKSPACE_MANIFEST_NAME = "csharp-reference-workspace.json"
_CSHARP_WORKSPACE_SCHEMA = 1
_CSHARP_COMPILER_CONFIG = {
    "target_framework": "net10.0",
    "lang_version": "preview",
    "nullable": "enable",
    "allow_unsafe_blocks": True,
    "enable_default_compile_items": False,
}


def _csharp_reject_symlink_ancestors(path: Path) -> None:
    ancestor = path.parent
    while ancestor != ancestor.parent:
        if ancestor.is_symlink():
            raise ValueError(
                f"SONAR_CSHARP_WORKSPACE parent must not be a symlink: {ancestor}"
            )
        ancestor = ancestor.parent


def _csharp_workspace_path() -> Path | None:
    value = os.environ.get("SONAR_CSHARP_WORKSPACE")
    if value is None or value == "":
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = REPO / path
    return path.absolute()


def _prepare_csharp_workspace() -> Path | None:
    path = _csharp_workspace_path()
    if path is None:
        return None
    _csharp_reject_symlink_ancestors(path)
    if path.is_symlink():
        raise ValueError(f"SONAR_CSHARP_WORKSPACE must not be a symlink: {path}")
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"SONAR_CSHARP_WORKSPACE must be a directory: {path}")
        try:
            next(path.iterdir())
        except StopIteration:
            return path
        raise ValueError(
            "SONAR_CSHARP_WORKSPACE must be absent or empty for a fresh reference: "
            f"{path}"
        )
    parent = path.parent
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise ValueError(
            f"SONAR_CSHARP_WORKSPACE parent is not a regular directory: {parent}"
        )
    path.mkdir(parents=True)
    return path


def _csharp_selected_sources(project_dir: Path, limit: int | None) -> list[Path]:
    if project_dir.is_symlink() or not project_dir.is_dir():
        raise ValueError(f"C# fixture source root is unavailable: {project_dir}")
    sources = sorted(project_dir.glob("*.cs"), key=lambda path: path.name)
    for source in sources:
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"C# fixture source must be a regular file: {source}")
    if limit is not None and limit < 1:
        raise ValueError("C# fixture limit must be positive")
    if limit is not None:
        sources = sources[:limit]
    if not sources:
        raise ValueError(f"no C# fixtures under {project_dir}")
    return sources


def _csharp_relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as error:
        raise ValueError(f"path is outside its retained root: {path}") from error


def _csharp_metadata_map(paths: list[Path], root: Path) -> dict[str, dict[str, object]]:
    rows = [file_metadata(path, root=root) for path in paths]
    return {str(row["path"]): row for row in rows}


def _csharp_redacted_argv(argv: list[str], auth_arg: str) -> list[str]:
    auth_key = auth_arg.split("=", 1)[0]
    return [
        f"{auth_key}=<redacted>" if item == auth_arg else str(item) for item in argv
    ]


def _csharp_workspace_manifest(
    *,
    workspace: Path,
    project_dir: Path,
    solution: Path,
    fixture_limit: int | None,
    fixture_count: int,
    task_id: str,
    scanner_path,
    auth_arg: str,
) -> dict[str, object]:
    sources = _csharp_selected_sources(project_dir, fixture_limit)
    if len(sources) != fixture_count:
        raise ValueError(
            "generated C# fixture count does not match the current source inventory"
        )
    solution = solution.resolve()
    expected_solution = (workspace / "Oracle.slnx").resolve()
    if solution != expected_solution:
        raise ValueError(f"generated C# solution is not {expected_solution}")

    static_files = _csharp_workspace_static_files(workspace)
    static = _csharp_metadata_map(static_files, workspace)
    mappings: list[dict[str, object]] = []
    for ordinal, source in enumerate(sources):
        fixture = f"fixture-{ordinal:04}"
        copied = workspace / "projects" / fixture / source.name
        project = workspace / "projects" / fixture / f"{fixture}.csproj"
        if (
            copied.is_symlink()
            or not copied.is_file()
            or project.is_symlink()
            or not project.is_file()
        ):
            raise ValueError(
                f"generated C# fixture project is incomplete for {source.name}"
            )
        source_metadata = file_metadata(source, root=REPO)
        copied_metadata = file_metadata(copied, root=workspace)
        project_metadata = file_metadata(project, root=workspace)
        if source_metadata["sha256"] != copied_metadata["sha256"]:
            raise ValueError(
                f"generated C# fixture source differs from its copied source: "
                f"{source.name}"
            )
        mappings.append(
            {
                "source": source.name,
                "source_path": source_metadata["path"],
                "source_sha256": source_metadata["sha256"],
                "copy": copied_metadata["path"],
                "copy_sha256": copied_metadata["sha256"],
                "project": project_metadata["path"],
                "project_sha256": project_metadata["sha256"],
            }
        )

    project_hashes = {
        path: row["sha256"]
        for path, row in static.items()
        if path.lower().endswith(".csproj")
    }
    config_hashes = {
        path: row["sha256"]
        for path, row in static.items()
        if path == "Oracle.slnx" or path == ".editorconfig"
    }
    project_files = [path for path in static_files if path.suffix.lower() == ".csproj"]
    config_files = [
        path
        for path in static_files
        if _csharp_relative(path, workspace) in {"Oracle.slnx", ".editorconfig"}
    ]
    source_input_sha256 = input_paths_sha256(REPO, sources)
    artifact_input_sha256_value = artifact_input_sha256(
        "oracle-cs", "sq", project_dir=project_dir
    )
    begin_argv = csharp_begin_command(scanner_path, "oracle-cs", workspace, auth_arg)
    build_argv = _native_build_command(solution)
    end_argv = [*_scanner_argv(scanner_path), "end", auth_arg]
    manifest: dict[str, object] = {
        "schema_version": _CSHARP_WORKSPACE_SCHEMA,
        "kind": "csharp_reference_workspace",
        "project": "oracle-cs",
        "status": "REFERENCE_SUCCESS",
        "workspace": {
            "solution": "Oracle.slnx",
            "manifest": _CSHARP_WORKSPACE_MANIFEST_NAME,
        },
        "source_root": _csharp_relative(project_dir, REPO),
        "fixture_limit": fixture_limit,
        "fixture_count": fixture_count,
        "compiler": dict(_CSHARP_COMPILER_CONFIG),
        "source_mapping": mappings,
        "solution_metadata": static["Oracle.slnx"],
        "project_hashes": project_hashes,
        "config_hashes": config_hashes,
        "static_files": list(static.values()),
        "input_sha256": artifact_input_sha256_value,
        "source_input_sha256": source_input_sha256,
        "project_sha256": input_paths_sha256(workspace, project_files),
        "config_sha256": input_paths_sha256(workspace, config_files),
        "input_hashes": {
            "source_sha256": source_input_sha256,
            "artifact_sha256": artifact_input_sha256_value,
        },
        "reference_execution": {
            "status": "SUCCESS",
            "compute_engine": "SUCCESS",
            "task_id": task_id,
            "cwd": str(workspace),
            "solution": "Oracle.slnx",
            "scanner": _scanner_argv(scanner_path),
            "argv": {
                "begin": _csharp_redacted_argv(begin_argv, auth_arg),
                "build": [str(item) for item in build_argv],
                "end": _csharp_redacted_argv(end_argv, auth_arg),
            },
        },
    }
    manifest["workspace_sha256"] = input_paths_sha256(workspace, static_files)
    manifest["manifest_sha256"] = manifest_digest(manifest)
    return manifest


def _csharp_workspace_manifest_identity(
    workspace: Path,
) -> tuple[Path, dict[str, object], str]:
    manifest_path = workspace / _CSHARP_WORKSPACE_MANIFEST_NAME
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise ValueError(
            "retained C# workspace lacks a successful reference manifest: "
            f"{manifest_path}"
        )
    manifest = read_json(manifest_path)
    if not isinstance(manifest, dict):
        raise ValueError("retained C# workspace manifest must be an object")
    if (
        manifest.get("schema_version") != _CSHARP_WORKSPACE_SCHEMA
        or manifest.get("kind") != "csharp_reference_workspace"
        or manifest.get("project") != "oracle-cs"
    ):
        raise ValueError("retained C# workspace manifest identity mismatch")
    digest = manifest.get("manifest_sha256")
    if (
        not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
        or digest != manifest_digest(manifest)
    ):
        raise ValueError("retained C# workspace manifest digest mismatch")
    if manifest.get("status") != "REFERENCE_SUCCESS":
        raise ValueError("retained C# workspace lacks a successful reference")
    workspace_identity = manifest.get("workspace")
    if workspace_identity != {
        "solution": "Oracle.slnx",
        "manifest": _CSHARP_WORKSPACE_MANIFEST_NAME,
    }:
        raise ValueError("retained C# workspace solution identity mismatch")
    compiler = manifest.get("compiler")
    if compiler != _CSHARP_COMPILER_CONFIG:
        raise ValueError("retained C# workspace compiler configuration mismatch")
    return manifest_path, manifest, digest


def _csharp_workspace_fixture_selection(
    project_dir: Path, manifest: dict[str, object]
) -> tuple[int | None, list[Path], int]:
    try:
        fixture_limit = csharp_fixture_limit()
    except ValueError as error:
        raise ValueError("SONAR_CSHARP_FIXTURE_LIMIT must be an integer") from error
    sources = _csharp_selected_sources(project_dir, fixture_limit)
    fixture_count = manifest.get("fixture_count")
    if not isinstance(fixture_count, int) or isinstance(fixture_count, bool):
        raise ValueError("retained C# workspace fixture count is invalid")
    if fixture_count != len(sources) or manifest.get("fixture_limit") != fixture_limit:
        raise ValueError(
            "retained C# workspace fixture selection does not match the current corpus"
        )
    return fixture_limit, sources, fixture_count


def _csharp_workspace_input_hashes(
    project_dir: Path, sources: list[Path], manifest: dict[str, object]
) -> dict[str, object]:
    input_hashes = manifest.get("input_hashes")
    if not isinstance(input_hashes, dict):
        raise ValueError("retained C# workspace lacks input hashes")
    current_source_input_sha256 = input_paths_sha256(REPO, sources)
    current_artifact_input_sha256 = artifact_input_sha256(
        "oracle-cs", "sq", project_dir=project_dir
    )
    if input_hashes.get("source_sha256") != current_source_input_sha256:
        raise ValueError("retained C# workspace source input hash mismatch")
    if input_hashes.get("artifact_sha256") != current_artifact_input_sha256:
        raise ValueError("retained C# workspace artifact input hash mismatch")
    if manifest.get("source_input_sha256") != current_source_input_sha256:
        raise ValueError("retained C# workspace source input hash mismatch")
    if manifest.get("input_sha256") != current_artifact_input_sha256:
        raise ValueError("retained C# workspace artifact input hash mismatch")
    return input_hashes


def _csharp_recorded_static_map(
    recorded_static: object,
) -> dict[str, dict[str, object]]:
    if not isinstance(recorded_static, list):
        raise ValueError("retained C# workspace lacks static file hashes")
    recorded_static_map: dict[str, dict[str, object]] = {}
    for row in recorded_static:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str):
            raise ValueError("retained C# workspace has invalid static file metadata")
        path = row["path"]
        if path in recorded_static_map:
            raise ValueError("retained C# workspace has duplicate static file metadata")
        recorded_static_map[path] = row
    return recorded_static_map


def _csharp_workspace_static_inventory(
    workspace: Path, manifest: dict[str, object]
) -> tuple[list[Path], dict[str, dict[str, object]]]:
    static_files = _csharp_workspace_static_files(workspace)
    current_static = _csharp_metadata_map(static_files, workspace)
    recorded_static_map = _csharp_recorded_static_map(manifest.get("static_files"))
    if set(recorded_static_map) != set(current_static):
        raise ValueError("retained C# workspace static file inventory mismatch")
    for path, current in current_static.items():
        recorded = recorded_static_map[path]
        if (
            recorded.get("size") != current["size"]
            or recorded.get("sha256") != current["sha256"]
        ):
            raise ValueError(f"retained C# workspace file hash mismatch: {path}")
    return static_files, current_static


def _csharp_workspace_static_hashes(
    workspace: Path,
    manifest: dict[str, object],
    static_files: list[Path],
    current_static: dict[str, dict[str, object]],
) -> tuple[dict[str, object], dict[str, object]]:
    project_hashes = manifest.get("project_hashes")
    current_project_hashes = {
        path: row["sha256"]
        for path, row in current_static.items()
        if path.lower().endswith(".csproj")
    }
    if project_hashes != current_project_hashes:
        raise ValueError("retained C# workspace project hash mismatch")
    config_hashes = manifest.get("config_hashes")
    current_config_hashes = {
        path: row["sha256"]
        for path, row in current_static.items()
        if path == "Oracle.slnx" or path == ".editorconfig"
    }
    if config_hashes != current_config_hashes:
        raise ValueError("retained C# workspace config hash mismatch")
    current_project_files = [
        path for path in static_files if path.suffix.lower() == ".csproj"
    ]
    current_config_files = [
        path
        for path in static_files
        if _csharp_relative(path, workspace) in {"Oracle.slnx", ".editorconfig"}
    ]
    if manifest.get("project_sha256") != input_paths_sha256(
        workspace, current_project_files
    ):
        raise ValueError("retained C# workspace project input hash mismatch")
    if manifest.get("config_sha256") != input_paths_sha256(
        workspace, current_config_files
    ):
        raise ValueError("retained C# workspace config input hash mismatch")
    if manifest.get("solution_metadata") != current_static.get("Oracle.slnx"):
        raise ValueError("retained C# workspace solution hash mismatch")
    if manifest.get("workspace_sha256") != input_paths_sha256(workspace, static_files):
        raise ValueError("retained C# workspace static input hash mismatch")
    return project_hashes, config_hashes


def _csharp_source_mapping_row(
    workspace: Path, source: Path, row: object, ordinal: int
) -> dict[str, object]:
    if not isinstance(row, dict):
        raise ValueError("retained C# workspace source mapping is invalid")
    fixture = f"fixture-{ordinal:04}"
    expected_copy = workspace / "projects" / fixture / source.name
    expected_project = workspace / "projects" / fixture / f"{fixture}.csproj"
    expected_source_metadata = file_metadata(source, root=REPO)
    expected_copy_metadata = file_metadata(expected_copy, root=workspace)
    expected_project_metadata = file_metadata(expected_project, root=workspace)
    expected = {
        "source": source.name,
        "source_path": expected_source_metadata["path"],
        "source_sha256": expected_source_metadata["sha256"],
        "copy": expected_copy_metadata["path"],
        "copy_sha256": expected_copy_metadata["sha256"],
        "project": expected_project_metadata["path"],
        "project_sha256": expected_project_metadata["sha256"],
    }
    if row != expected:
        raise ValueError(
            f"retained C# workspace source mapping mismatch: {source.name}"
        )
    if expected_source_metadata["sha256"] != expected_copy_metadata["sha256"]:
        raise ValueError(f"retained C# workspace copied source mismatch: {source.name}")
    return expected


def _csharp_workspace_source_mappings(
    workspace: Path, sources: list[Path], manifest: dict[str, object]
) -> list[dict[str, object]]:
    mappings = manifest.get("source_mapping")
    if not isinstance(mappings, list) or len(mappings) != len(sources):
        raise ValueError("retained C# workspace source mapping is incomplete")
    return [
        _csharp_source_mapping_row(workspace, source, row, ordinal)
        for ordinal, (source, row) in enumerate(zip(sources, mappings, strict=True))
    ]


def _csharp_workspace_reference_argv(
    workspace: Path, reference_execution: dict[str, object]
) -> None:
    solution = workspace / "Oracle.slnx"
    expected_build_argv = [str(item) for item in _native_build_command(solution)]
    recorded_argv = reference_execution.get("argv")
    scanner = reference_execution.get("scanner")
    if (
        not isinstance(recorded_argv, dict)
        or recorded_argv.get("build") != expected_build_argv
        or not isinstance(recorded_argv.get("begin"), list)
        or not isinstance(recorded_argv.get("end"), list)
        or not recorded_argv.get("begin")
        or not recorded_argv.get("end")
        or not isinstance(scanner, list)
        or not scanner
        or any(not isinstance(item, str) for item in scanner)
    ):
        raise ValueError("retained C# workspace reference argv does not match")
    expected_base_dir = f"/d:sonar.projectBaseDir={workspace}"
    expected_begin = [
        *scanner,
        "begin",
        "/k:oracle-cs",
        f"/d:sonar.host.url={SONAR_URL}",
        expected_base_dir,
        "/d:sonar.scm.exclusions.disabled=true",
    ]
    recorded_begin = recorded_argv["begin"]
    recorded_end = recorded_argv["end"]
    if not all(isinstance(item, str) for item in [*recorded_begin, *recorded_end]):
        raise ValueError("retained C# workspace reference argv does not match")
    if (
        recorded_begin[:-1] != expected_begin
        or recorded_end[:-1] != [*scanner, "end"]
        or recorded_begin[-1]
        not in {
            "/d:sonar.login=<redacted>",
            "/d:sonar.token=<redacted>",
        }
        or recorded_end[-1] != recorded_begin[-1]
    ):
        raise ValueError("retained C# workspace reference argv does not match")


def _csharp_workspace_reference_execution(
    workspace: Path, manifest: dict[str, object]
) -> dict[str, object]:
    reference_execution = manifest.get("reference_execution")
    if not isinstance(reference_execution, dict):
        raise ValueError("retained C# workspace lacks reference execution evidence")
    if (
        reference_execution.get("status") != "SUCCESS"
        or reference_execution.get("compute_engine") != "SUCCESS"
        or not isinstance(reference_execution.get("task_id"), str)
        or not reference_execution["task_id"]
    ):
        raise ValueError("retained C# workspace reference execution is not successful")
    _csharp_workspace_reference_argv(workspace, reference_execution)
    if reference_execution.get("cwd") != str(workspace):
        raise ValueError("retained C# workspace reference cwd mismatch")
    if reference_execution.get("solution") != "Oracle.slnx":
        raise ValueError("retained C# workspace reference solution mismatch")
    return reference_execution


def _csharp_reject_foreign_workspace_inputs(workspace: Path) -> None:
    for path in workspace.rglob("*"):
        if path.is_symlink():
            raise ValueError(f"retained C# workspace contains a symlink: {path}")
    allowed_root_entries = {
        "Oracle.slnx",
        ".editorconfig",
        "projects",
        _CSHARP_WORKSPACE_MANIFEST_NAME,
    }
    for path in workspace.iterdir():
        if path.name in allowed_root_entries:
            continue
        if path.suffix.lower() in {
            ".cs",
            ".csproj",
            ".sln",
            ".slnx",
            ".props",
            ".targets",
        } or path.name.lower() in {
            "directory.build.props",
            "directory.build.targets",
            "directory.packages.props",
            "global.json",
            "nuget.config",
        }:
            raise ValueError(
                f"retained C# workspace contains foreign project input: {path}"
            )


def _validate_csharp_workspace() -> tuple[Path, dict[str, object]]:
    workspace = _csharp_workspace_path()
    if workspace is None:
        raise ValueError("SONAR_CSHARP_WORKSPACE is not set")
    _csharp_reject_symlink_ancestors(workspace)
    if workspace.is_symlink() or not workspace.is_dir():
        raise ValueError(f"retained C# workspace is unavailable: {workspace}")
    manifest_path, manifest, digest = _csharp_workspace_manifest_identity(workspace)
    project_dir = (ORACLE / "projects" / "oracle-cs").resolve()
    fixture_limit, sources, fixture_count = _csharp_workspace_fixture_selection(
        project_dir, manifest
    )
    input_hashes = _csharp_workspace_input_hashes(project_dir, sources, manifest)
    static_files, current_static = _csharp_workspace_static_inventory(
        workspace, manifest
    )
    project_hashes, config_hashes = _csharp_workspace_static_hashes(
        workspace, manifest, static_files, current_static
    )
    normalized_mappings = _csharp_workspace_source_mappings(
        workspace, sources, manifest
    )
    reference_execution = _csharp_workspace_reference_execution(workspace, manifest)
    _csharp_reject_foreign_workspace_inputs(workspace)
    solution = workspace / "Oracle.slnx"
    context: dict[str, object] = {
        "status": "READY",
        "kind": "csharp",
        "semantic_requested": True,
        "required_target_framework": _CSHARP_COMPILER_CONFIG["target_framework"],
        "workspace": str(workspace),
        "workspace_manifest": file_metadata(manifest_path, root=workspace),
        "workspace_manifest_sha256": digest,
        "solution": str(solution),
        "source_mapping": normalized_mappings,
        "source_paths": [
            str(workspace / str(row["copy"])) for row in normalized_mappings
        ],
        "compiler": dict(_CSHARP_COMPILER_CONFIG),
        "input_hashes": dict(input_hashes),
        "solution_metadata": dict(manifest["solution_metadata"]),
        "input_sha256": manifest["input_sha256"],
        "source_input_sha256": manifest["source_input_sha256"],
        "project_sha256": manifest["project_sha256"],
        "config_sha256": manifest["config_sha256"],
        "project_hashes": dict(project_hashes),
        "config_hashes": dict(config_hashes),
        "workspace_sha256": manifest["workspace_sha256"],
        "reference_execution": reference_execution,
    }
    return workspace, context


def _csharp_native_context() -> dict[str, object]:
    workspace = _csharp_workspace_path()
    if workspace is None:
        legacy_project = ORACLE / "projects" / "oracle-cs" / "oracle-cs.csproj"
        metadata: dict[str, object] = {"path": str(legacy_project)}
        if legacy_project.is_file() and not legacy_project.is_symlink():
            metadata = file_metadata(legacy_project, root=REPO)
        return {
            "status": "UNAVAILABLE",
            "kind": "csharp",
            "semantic_requested": True,
            "reason": (
                "no matching net10.0 C# project is available; the captured legacy "
                "net8.0 project is not passed to native analysis"
            ),
            "legacy_project": metadata,
            "required_target_framework": "net10.0",
        }
    _, context = _validate_csharp_workspace()
    return context


def _csharp_report_mapping_indexes(
    mappings: list[object], workspace: Path
) -> tuple[
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
    dict[str, dict[str, object]],
]:
    by_source: dict[str, dict[str, object]] = {}
    by_original: dict[str, dict[str, object]] = {}
    by_copy: dict[str, dict[str, object]] = {}
    for row in mappings:
        if not isinstance(row, dict):
            raise ValueError("C# native context has an invalid source mapping")
        source = row.get("source")
        source_path = row.get("source_path")
        copy = row.get("copy")
        if (
            not isinstance(source, str)
            or not isinstance(source_path, str)
            or not isinstance(copy, str)
        ):
            raise ValueError("C# native context has an incomplete source mapping")
        if source in by_source:
            raise ValueError(f"duplicate C# source mapping: {source}")
        if source_path in by_original:
            raise ValueError(f"duplicate C# source path mapping: {source_path}")
        if copy in by_copy:
            raise ValueError(f"duplicate C# copied source mapping: {copy}")
        by_source[source] = row
        by_original[source_path] = row
        by_original[str((REPO / source_path).resolve()).replace("\\", "/")] = row
        by_copy[copy] = row
        by_copy[str((workspace / copy).resolve()).replace("\\", "/")] = row
    return by_source, by_original, by_copy


def _csharp_resolved_report_mapping(
    raw_path: str,
    workspace: Path,
    by_original: dict[str, dict[str, object]],
    by_copy: dict[str, dict[str, object]],
) -> dict[str, object] | None:
    try:
        row = by_copy.get(str((workspace / raw_path).resolve()).replace("\\", "/"))
    except (OSError, RuntimeError):
        row = None
    if row is not None:
        return row
    try:
        row = by_copy.get(str(Path(raw_path).resolve()).replace("\\", "/"))
    except (OSError, RuntimeError):
        row = None
    if row is not None:
        return row
    try:
        return by_original.get(str((REPO / raw_path).resolve()).replace("\\", "/"))
    except (OSError, RuntimeError):
        return None


def _csharp_report_mapping_for_path(
    raw_path: str,
    workspace: Path,
    by_source: dict[str, dict[str, object]],
    by_original: dict[str, dict[str, object]],
    by_copy: dict[str, dict[str, object]],
) -> dict[str, object] | None:
    row = by_source.get(raw_path)
    if row is None:
        row = by_original.get(raw_path)
    if row is None:
        row = by_copy.get(raw_path)
    if row is None:
        row = _csharp_resolved_report_mapping(raw_path, workspace, by_original, by_copy)
    if row is None and "/" not in raw_path:
        row = by_source.get(raw_path)
    return row


def _normalize_csharp_report_paths(report: object, context: dict[str, object]) -> None:
    if not isinstance(report, dict) or not isinstance(report.get("files"), list):
        raise ValueError("C# native report must contain a files list")
    mappings = context.get("source_mapping")
    workspace_value = context.get("workspace")
    if not isinstance(mappings, list) or not isinstance(workspace_value, str):
        raise ValueError("C# native context lacks source mapping")
    workspace = Path(workspace_value).resolve()
    by_source, by_original, by_copy = _csharp_report_mapping_indexes(
        mappings, workspace
    )
    for file_report in report["files"]:
        if not isinstance(file_report, dict) or not isinstance(
            file_report.get("path"), str
        ):
            raise ValueError("C# native report has an invalid file path")
        original_path = file_report["path"]
        raw_path = original_path.replace("\\", "/")
        row = _csharp_report_mapping_for_path(
            raw_path, workspace, by_source, by_original, by_copy
        )
        if row is None:
            raise ValueError(
                f"C# native report path is outside the retained fixture mapping: "
                f"{original_path}"
            )
        file_report["path"] = str(row["source"])


def _require_complete_typescript_report(report: object) -> None:
    if not isinstance(report, dict):
        raise ValueError("TypeScript native report must be an object")
    project = report.get("project")
    if not isinstance(project, dict) or project.get("complete") is not True:
        raise ValueError("TypeScript semantic replay produced an incomplete project")
    warnings = project.get("warnings", [])
    if not isinstance(warnings, list):
        raise ValueError("TypeScript native report has invalid project warnings")
    semantic_warnings = [
        warning
        for warning in warnings
        if isinstance(warning, str) and warning.startswith("semantic context:")
    ]
    if semantic_warnings:
        raise ValueError(
            "TypeScript semantic replay produced warnings: "
            + "; ".join(semantic_warnings)
        )


def artifact_provenance(proj: str, kind: str) -> dict[str, object]:
    project_dir = (ORACLE / "projects" / proj).resolve()
    language = CATALOG_LANGUAGE[EXT[proj]]
    catalog = REPO / "catalog/rules" / f"{language}.json"
    plugin_root = _plugin_root()
    if plugin_root is None:
        raise ValueError("SONAR_ORACLE_PLUGIN_ROOT is required for provenance")
    server, plugins = _server_snapshot()
    tools, packages = _reference_tools(proj, kind)
    source_root = project_dir if proj == "oracle-cs" else project_dir / "src"
    manifest = make_manifest(
        repo=REPO,
        project=proj,
        kind=kind,
        input_sha256=artifact_input_sha256(proj, kind),
        source_root=source_root,
        expected=project_dir / "expected.jsonl",
        catalog=catalog,
        server=server,
        profile=_profile_snapshot(proj),
        plugins=plugins,
        parameters=_reference_parameters(proj, kind),
        tools=tools,
        plugin_root=plugin_root,
        packages=packages,
    )
    RUN_PROVENANCE[f"{proj}:{kind}"] = manifest
    return manifest


def attach_artifact_provenance(report: dict[str, object], proj: str, kind: str) -> None:
    manifest = RUN_PROVENANCE.get(f"{proj}:{kind}") or artifact_provenance(proj, kind)
    native_context = RUN_NATIVE_CONTEXT.get(f"{proj}:{kind}")
    if native_context is not None:
        manifest = dict(manifest)
        manifest["native_context"] = native_context
        manifest["manifest_sha256"] = manifest_digest(manifest)
        RUN_PROVENANCE[f"{proj}:{kind}"] = manifest
    report["oracle_provenance"] = manifest
    evidence = report.get("oracle_evidence")
    if not isinstance(evidence, dict):
        raise ValueError(f"{kind} artifact lacks oracle evidence")
    if native_context is not None:
        evidence["native_context"] = native_context
    evidence["provenance_sha256"] = manifest["manifest_sha256"]


def validate_artifact_provenance(
    report: object,
    proj: str,
    kind: str,
    *,
    project_dir: Path | None = None,
    require_server: bool = True,
) -> dict[str, object]:
    if not isinstance(report, dict):
        raise ValueError(f"{kind} artifact must be an object")
    expected_input = artifact_input_sha256(proj, kind, project_dir=project_dir)
    manifest = validate_manifest(
        report.get("oracle_provenance"),
        project=proj,
        kind=kind,
        input_sha256=expected_input,
    )
    if require_server and manifest["server"].get("url") != SONAR_URL:
        raise ValueError(f"{kind} artifact references a different Sonar server")
    evidence = report.get("oracle_evidence")
    if (
        not isinstance(evidence, dict)
        or evidence.get("provenance_sha256") != manifest["manifest_sha256"]
    ):
        raise ValueError(f"{kind} artifact provenance evidence mismatch")
    return manifest


def validate_artifact_evidence(report, project, kind, *, project_dir=None):
    evidence = report.get("oracle_evidence") if isinstance(report, dict) else None
    if not isinstance(evidence, dict):
        raise ValueError(f"{kind} artifact lacks oracle input fingerprint")
    expected = {
        "project": project,
        "kind": kind,
        "input_sha256": artifact_input_sha256(project, kind, project_dir=project_dir),
    }
    if any(evidence.get(key) != value for key, value in expected.items()):
        raise ValueError(f"stale or mismatched {kind} oracle artifact")
    if "provenance_sha256" in evidence:
        validate_artifact_provenance(report, project, kind, project_dir=project_dir)


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
        token_path = Path(
            os.environ.get("SONAR_ORACLE_TOKEN_FILE", str(ORACLE / "token"))
        )
        if not token_path.exists():
            raise RuntimeError(
                "set SONAR_ORACLE_TOKEN or SONAR_ORACLE_TOKEN_FILE or "
                "create .oracle/sonar/token"
            )
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


def _scanner_argv(scanner_path):
    if isinstance(scanner_path, (list, tuple)):
        return list(scanner_path)
    return [str(scanner_path)]


def csharp_begin_command(scanner_path, proj, output_dir, auth_arg):
    return [
        *_scanner_argv(scanner_path),
        "begin",
        f"/k:{proj}",
        f"/d:sonar.host.url={SONAR_URL}",
        f"/d:sonar.projectBaseDir={output_dir}",
        "/d:sonar.scm.exclusions.disabled=true",
        auth_arg,
    ]


def csharp_scanner_path():
    dotnet = shutil.which("dotnet")
    if not dotnet:
        print("  scan oracle-cs: FAILED (dotnet SDK missing)")
        return None
    scanner_dll = os.environ.get("SONAR_DOTNET_SCANNER_DLL")
    if scanner_dll:
        path = Path(scanner_dll).resolve()
        if not path.is_file():
            print(f"  scan oracle-cs: FAILED (scanner DLL missing: {path})")
            return None
        return [dotnet, str(path)]
    scanner = os.environ.get("SONAR_DOTNET_SCANNER", "dotnet-sonarscanner")
    scanner_path = shutil.which(scanner) if os.path.sep not in scanner else scanner
    if not scanner_path or not Path(scanner_path).is_file():
        print(
            "  scan oracle-cs: FAILED (set SONAR_DOTNET_SCANNER or "
            "SONAR_DOTNET_SCANNER_DLL)"
        )
        return None
    return scanner_path


def _native_build_command(solution: Path) -> list[str]:
    return [
        "dotnet",
        "build",
        str(solution),
        "--no-incremental",
        "--disable-build-servers",
    ]


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
            _native_build_command(solution),
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
            [*_scanner_argv(scanner_path), "end", auth_arg],
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


def _scan_csharp_retained_workspace(
    proj: str,
    project_dir: Path,
    output_dir: Path,
    fixture_limit: int | None,
    scanner_path,
    auth_arg: str,
) -> bool:
    try:
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
        if not wait_for_scan(proj, task_id, "native compute engine"):
            return False
        if not isinstance(task_id, str) or not task_id:
            raise ValueError("native reference task has no stable identifier")
        manifest = _csharp_workspace_manifest(
            workspace=output_dir,
            project_dir=project_dir,
            solution=solution,
            fixture_limit=fixture_limit,
            fixture_count=fixture_count,
            task_id=task_id,
            scanner_path=scanner_path,
            auth_arg=auth_arg,
        )
        manifest_path = output_dir / _CSHARP_WORKSPACE_MANIFEST_NAME
        if manifest_path.exists() or manifest_path.is_symlink():
            raise ValueError(
                f"retained C# workspace manifest already exists: {manifest_path}"
            )
        write_json_atomic(manifest_path, manifest, indent=1)
        _, context = _validate_csharp_workspace()
        context["status"] = "REFERENCE_SUCCESS"
        RUN_NATIVE_CONTEXT[f"{proj}:sq"] = context
        print(f"  retained C# reference workspace: {output_dir}")
        return True
    except (OSError, TypeError, ValueError) as error:
        print(f"  scan {proj}: FAILED (retained workspace: {error})")
        return False


def _scan_csharp_temporary_workspace(
    proj: str,
    project_dir: Path,
    fixture_limit: int | None,
    scanner_path,
    auth_arg: str,
) -> bool:
    with tempfile.TemporaryDirectory(
        prefix="native-csharp-", dir=REPO / "tools/oracle"
    ) as directory:
        output_dir = Path(directory)
        try:
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
        except (OSError, ValueError) as error:
            print(f"  scan {proj}: FAILED (C# fixture generation: {error})")
            return False
        return wait_for_scan(proj, task_id, "native compute engine")


def scan_csharp_project(proj):
    context_key = f"{proj}:sq"
    RUN_NATIVE_CONTEXT.pop(context_key, None)
    scanner_path = csharp_scanner_path()
    if scanner_path is None:
        return False
    if SONAR_URL != "http://127.0.0.1:9000" or os.environ.get(
        "SONAR_ORACLE_REQUIRE_PROFILE"
    ):
        ensure_project_and_profile(proj)

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

    try:
        retained_workspace = _prepare_csharp_workspace()
    except (OSError, ValueError) as error:
        print(f"  scan {proj}: FAILED (retained workspace: {error})")
        return False

    if retained_workspace is not None:
        return _scan_csharp_retained_workspace(
            proj,
            project_dir,
            retained_workspace,
            fixture_limit,
            scanner_path,
            auth_arg,
        )
    return _scan_csharp_temporary_workspace(
        proj, project_dir, fixture_limit, scanner_path, auth_arg
    )


def _search_page(request, label):
    for attempt in range(5):
        try:
            return request_json(request)
        except urllib.error.HTTPError as error:
            with error:
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


def _issue_page(proj, page, *, rules=None, severities=None):
    params = {"componentKeys": proj, "resolved": "false", "ps": 500, "p": page}
    if rules:
        params["rules"] = ",".join(rules)
    if severities:
        params["severities"] = severities
    q = urllib.parse.urlencode(params)
    req = urllib.request.Request(f"{SONAR_URL}/api/issues/search?{q}")
    req.add_header("Authorization", auth_header())
    return _search_page(req, "issues")


def _fetch_standard_issues(proj, *, project_issues=None, project_rules=()):
    if proj != "oracle-cs":
        return _fetch_paginated(
            lambda page: _issue_page(proj, page),
            "issues",
            hotspot=False,
            expected_project=proj,
            project_issues=project_issues,
            project_rules=project_rules,
        )
    severities = ("BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO")
    baseline = sq_api(
        "/api/issues/search",
        {"componentKeys": proj, "resolved": "false", "ps": 1, "p": 1},
    )
    baseline_total = baseline.get("total")
    if not isinstance(baseline_total, int):
        raise ValueError("C# issue search response lacks total")
    shard_totals = [
        sq_api(
            "/api/issues/search",
            {
                "componentKeys": proj,
                "resolved": "false",
                "severities": severity,
                "ps": 1,
                "p": 1,
            },
        ).get("total")
        for severity in severities
    ]
    if any(not isinstance(total, int) for total in shard_totals):
        raise ValueError("C# severity shard response lacks total")
    if sum(shard_totals) != baseline_total:
        raise ValueError("C# severity shards do not cover advertised issue total")
    issues = []
    seen_issue_keys = set()
    for severity in severities:
        issues.extend(
            _fetch_paginated(
                lambda page, severity=severity: _issue_page(
                    proj, page, severities=severity
                ),
                "issues",
                hotspot=False,
                expected_project=proj,
                project_issues=project_issues,
                project_rules=project_rules,
                seen_issue_keys=seen_issue_keys,
            )
        )
    if len(seen_issue_keys) != baseline_total:
        raise ValueError("C# severity shards yielded duplicate or missing issues")
    return issues


def _hotspot_page(proj, page):
    q = urllib.parse.urlencode({"projectKey": proj, "ps": 500, "p": page})
    req = urllib.request.Request(f"{SONAR_URL}/api/hotspots/search?{q}")
    req.add_header("Authorization", auth_header())
    return _search_page(req, "hotspots")


def _fetch_paginated(
    page_loader,
    item_key,
    *,
    hotspot,
    expected_project,
    project_issues=None,
    project_rules=(),
    seen_issue_keys=None,
):
    issues, page = [], 1
    expected_total = expected_page_size = None
    seen_keys = set()
    seen_issue_keys = seen_issue_keys if seen_issue_keys is not None else set()
    project_rules = set(project_rules)
    while True:
        payload = page_loader(page)
        items, total, page_size, done = validate_search_page(
            payload,
            item_key,
            page,
            expected_total=expected_total,
            expected_page_size=expected_page_size,
            seen_keys=seen_keys,
        )
        if expected_total is None:
            expected_total, expected_page_size = total, page_size
        for issue in items:
            issue_key = issue.get("key")
            if not isinstance(issue_key, str) or not issue_key:
                raise ValueError("issues response item lacks stable key")
            if issue_key in seen_issue_keys:
                raise ValueError(f"duplicate issue key across rule shards: {issue_key}")
            seen_issue_keys.add(issue_key)
            if (
                project_issues is not None
                and not hotspot
                and issue.get("component") == expected_project
            ):
                rule = issue.get("rule")
                if rule not in project_rules:
                    raise ValueError(f"unapproved project-level issue rule: {rule!r}")
                project_issues.append(
                    {
                        "kind": "PROJECT_LEVEL",
                        "key": issue["key"],
                        "rule": rule,
                        "message": issue["message"],
                        "component": expected_project,
                        "severity": issue.get("severity"),
                        "type": issue.get("type"),
                    }
                )
                continue
            issues.append(
                canonical_sonar_issue(
                    issue, hotspot=hotspot, expected_project=expected_project
                )
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


def fetch_issues(proj, *, allow_project_issues=False):
    project_issues = [] if allow_project_issues and proj == "oracle-cs" else None
    project_rules = (
        load_infra_boundaries(REPO / "catalog/infra-boundaries.json")
        if project_issues is not None
        else {}
    )
    issues = _fetch_standard_issues(
        proj, project_issues=project_issues, project_rules=project_rules
    )
    issues.extend(_fetch_hotspots(proj))
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = result_path(proj, "sq")
    report = {
        "schema_version": 2,
        "project": proj,
        "server": sq_api("/api/system/status"),
        "issues": issues,
    }
    if project_issues is not None:
        report["project_issues"] = project_issues
    attach_artifact_evidence(report, proj, "sq")
    attach_artifact_provenance(report, proj, "sq")
    validate_oracle_report(report, expected_project=proj)
    validate_artifact_provenance(report, proj, "sq")
    write_json(out, report, indent=1)
    return len(issues) + len(project_issues or [])


def _ours_command(proj: str) -> list[str] | None:
    executable = os.environ.get("HOONARQUBE_EXECUTABLE")
    if executable:
        executable_path = Path(executable)
        if not executable_path.is_file() or executable_path.is_symlink():
            print(f"  ours {proj}: FAILED (native executable missing: {executable})")
            return None
        return [str(executable_path)]
    return [
        "cargo",
        "run",
        "-q",
        "-p",
        "hoonarqube-cli",
        "--",
    ]


def _ours_native_context(proj: str) -> dict[str, object]:
    try:
        if proj == "oracle-ts":
            return _typescript_native_context()
        if proj == "oracle-cs":
            return _csharp_native_context()
        return {
            "status": "SYNTAX_ONLY",
            "kind": CATALOG_LANGUAGE[EXT[proj]],
            "semantic_requested": False,
        }
    except (OSError, ValueError) as error:
        print(f"  ours {proj}: FAILED (native context unavailable: {error})")
        return {
            "status": "UNAVAILABLE",
            "kind": CATALOG_LANGUAGE[EXT[proj]],
            "semantic_requested": proj in {"oracle-ts", "oracle-cs"},
            "reason": str(error),
        }


def _csharp_timeout_override() -> int | None:
    raw = os.environ.get(_CSHARP_TIMEOUT_ENV)
    if not raw:
        return None
    if re.fullmatch(r"[0-9]+", raw) is None:
        raise ValueError(f"{_CSHARP_TIMEOUT_ENV} must be a positive finite u64")
    timeout_ms = int(raw)
    if timeout_ms == 0 or timeout_ms > (1 << 64) - 1:
        raise ValueError(f"{_CSHARP_TIMEOUT_ENV} must be a positive finite u64")
    return timeout_ms


def _append_ours_command(
    command: list[str],
    proj: str,
    src: Path,
    native_context: dict[str, object],
) -> None:
    command.extend(["analyze", "--format", "json"])
    if proj == "oracle-ts":
        command.extend(
            [
                "--typescript-project",
                str(native_context["typescript_project_path"]),
                "--typescript-module",
                str(native_context["typescript_module"]),
            ]
        )
    if proj == "oracle-cs":
        if native_context.get("status") != "READY":
            raise ValueError(
                "C# native analysis requires a validated workspace context"
            )
        command.extend(
            [
                "--csharp-project",
                str(native_context["solution"]),
                "--allow-project-build",
            ]
        )
        timeout_ms = _csharp_timeout_override()
        effective_timeout_ms = (
            _DEFAULT_CSHARP_TIMEOUT_MS if timeout_ms is None else timeout_ms
        )
        native_context["csharp_timeout_ms"] = effective_timeout_ms
        if timeout_ms is not None:
            command.extend(["--csharp-timeout-ms", str(timeout_ms)])
        command.extend([str(path) for path in native_context["source_paths"]])
    elif proj == "oracle-go":
        command.extend(["--go-header-format", "// Licensed"])
        command.append(str(src))
    elif proj != "oracle-cs":
        command.append(str(src))


def _parse_ours_report(
    proj: str,
    stdout: str,
    native_context: dict[str, object],
    *,
    attach_artifacts: bool = True,
) -> dict[str, object]:
    data = parse_json(stdout, context=f"hoonarqube {proj} report")
    complete = _native_report_complete(data)
    native_context["project_complete"] = complete
    if proj == "oracle-cs":
        if native_context.get("status") != "READY":
            raise ValueError("C# native report requires a validated workspace context")
        _normalize_csharp_report_paths(data, native_context)
        if complete:
            native_context["status"] = "COMPLETE"
    hoonarqube_findings(data)
    if proj == "oracle-ts" and complete:
        _require_complete_typescript_report(data)
    if attach_artifacts:
        attach_artifact_evidence(data, proj, "ours")
        attach_artifact_provenance(data, proj, "ours")
        validate_artifact_provenance(data, proj, "ours")
    return data


def _run_ours_process(
    proj: str,
    command: list[str],
    native_context: dict[str, object],
    argv: list[str],
) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=REPO,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
    except (subprocess.TimeoutExpired, OSError) as error:
        if isinstance(error, subprocess.TimeoutExpired):
            status = "TIMEOUT"
            stdout = _native_stream(error.stdout)
            stderr = _native_stream(error.stderr)
            reason = "analysis timed out"
        else:
            status = "FAILED"
            stdout = ""
            stderr = ""
            reason = f"native process failed: {error}"
        _native_execution(
            native_context,
            status=status,
            exit_code=None,
            stdout=stdout,
            stderr=stderr,
            project_complete=None,
            reason=reason,
            argv=argv,
        )
        print(f"  ours {proj}: FAILED ({reason})")
        return None


def _execute_ours(
    proj: str,
    command: list[str],
    output: Path,
    native_context: dict[str, object],
) -> Path | None:
    argv = [str(argument) for argument in command]
    native_context["argv"] = argv
    native_context["cwd"] = str(REPO)
    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.unlink(missing_ok=True)
    except OSError as error:
        reason = f"cannot clear stale native artifact: {error}"
        _native_execution(
            native_context,
            status="FAILED",
            exit_code=None,
            stdout="",
            stderr="",
            project_complete=None,
            reason=reason,
            argv=argv,
        )
        print(f"  ours {proj}: FAILED ({reason})")
        return None
    result = _run_ours_process(proj, command, native_context, argv)
    if result is None:
        return None

    stdout = _native_stream(result.stdout)
    stderr = _native_stream(result.stderr)
    try:
        data = _parse_ours_report(proj, stdout, native_context, attach_artifacts=False)
        complete = _native_report_complete(data)
    except (OSError, TypeError, ValueError, KeyError) as error:
        reason = f"invalid report: {error}"
        _native_execution(
            native_context,
            status="INVALID",
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            project_complete=(
                native_context.get("project_complete")
                if isinstance(native_context.get("project_complete"), bool)
                else None
            ),
            reason=reason,
            argv=argv,
        )
        print(f"  ours {proj}: FAILED ({reason})")
        return None

    if result.returncode == 2 and not complete:
        execution_status = "INCOMPLETE"
        reason = _native_incomplete_reason(data)
    elif result.returncode == 0 and complete:
        execution_status = "COMPLETE"
        reason = None
    else:
        execution_status = "INVALID"
        reason = (
            "native exit code is inconsistent with report completeness: "
            f"exit_code={result.returncode}, project.complete={complete}"
        )
        _native_execution(
            native_context,
            status=execution_status,
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            project_complete=complete,
            reason=reason,
            argv=argv,
        )
        print(f"  ours {proj}: FAILED ({reason})")
        return None

    _native_execution(
        native_context,
        status=execution_status,
        exit_code=result.returncode,
        stdout=stdout,
        stderr=stderr,
        project_complete=complete,
        reason=reason,
        argv=argv,
    )
    try:
        attach_artifact_evidence(data, proj, "ours")
        attach_artifact_provenance(data, proj, "ours")
        validate_artifact_provenance(data, proj, "ours")
        write_json(output, data)
    except (OSError, TypeError, ValueError, KeyError) as error:
        reason = f"cannot retain native report: {error}"
        _native_execution(
            native_context,
            status="FAILED",
            exit_code=result.returncode,
            stdout=stdout,
            stderr=stderr,
            project_complete=complete,
            reason=reason,
            argv=argv,
        )
        print(f"  ours {proj}: FAILED ({reason})")
        return None
    return output


def run_ours(proj):
    # oracle-cs keeps sources at the project root; others under src/
    src = ORACLE / "projects" / proj / ("." if proj == "oracle-cs" else "src")
    out = result_path(proj, "ours")
    context_key = f"{proj}:ours"
    RUN_NATIVE_CONTEXT.pop(context_key, None)
    RUN_PROVENANCE.pop(context_key, None)

    def unavailable(reason: str) -> dict[str, object]:
        context: dict[str, object] = {
            "status": "UNAVAILABLE",
            "kind": CATALOG_LANGUAGE[EXT[proj]],
            "semantic_requested": proj in {"oracle-ts", "oracle-cs"},
            "reason": reason,
            "cwd": str(REPO),
        }
        RUN_NATIVE_CONTEXT[context_key] = context
        return context

    command = _ours_command(proj)
    if command is None:
        context = unavailable(f"native executable is unavailable for {proj}")
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.unlink(missing_ok=True)
        except OSError as error:
            reason = f"cannot clear stale native artifact: {error}"
            context["reason"] = reason
        _native_execution(
            context,
            status="NOT_ATTEMPTED",
            exit_code=None,
            stdout="",
            stderr="",
            project_complete=None,
            reason=context["reason"],
        )
        return None

    native_context = _ours_native_context(proj)
    native_context["cwd"] = str(REPO)
    RUN_NATIVE_CONTEXT[context_key] = native_context
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.unlink(missing_ok=True)
    except OSError as error:
        reason = f"cannot clear stale native artifact: {error}"
        _native_execution(
            native_context,
            status="FAILED",
            exit_code=None,
            stdout="",
            stderr="",
            project_complete=None,
            reason=reason,
        )
        print(f"  ours {proj}: FAILED ({reason})")
        return None

    if native_context.get("status") == "UNAVAILABLE":
        reason = str(native_context.get("reason", "native context is unavailable"))
        _native_execution(
            native_context,
            status="NOT_ATTEMPTED",
            exit_code=None,
            stdout="",
            stderr="",
            project_complete=None,
            reason=reason,
            argv=[str(argument) for argument in command],
        )
        print(f"  ours {proj}: FAILED (native context unavailable: {reason})")
        return None
    try:
        _append_ours_command(command, proj, src, native_context)
    except (KeyError, TypeError, ValueError) as error:
        reason = f"native context is invalid: {error}"
        _native_execution(
            native_context,
            status="NOT_ATTEMPTED",
            exit_code=None,
            stdout="",
            stderr="",
            project_complete=None,
            reason=reason,
            argv=[str(argument) for argument in command],
        )
        print(f"  ours {proj}: FAILED ({reason})")
        return None
    native_context["argv"] = [str(argument) for argument in command]
    return _execute_ours(proj, command, out, native_context)


def diff(proj, lang, sq_json, ours_json):
    project_dir = ORACLE / "projects" / proj
    exp_path = project_dir / "expected.jsonl"
    expected = read_jsonl(exp_path)
    sq = read_json(sq_json)
    ours = read_json(ours_json)
    validate_oracle_report(sq, expected_project=proj)
    validate_artifact_provenance(sq, proj, "sq")
    validate_artifact_provenance(ours, proj, "ours")
    validate_compatible_manifests(sq, ours)
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
        "--reference-only",
        action="store_true",
        help="run Sonar and fixture reference scans without invoking Hoonarqube",
    )
    parser.add_argument(
        "--project",
        action="append",
        choices=LANGS,
        help="run only this oracle project (repeatable)",
    )
    return parser.parse_args()


def reference_command(proj: str) -> str:
    env = {
        "SONAR_ORACLE_URL": SONAR_URL,
        "SONAR_ORACLE_TOKEN_FILE": os.environ.get(
            "SONAR_ORACLE_TOKEN_FILE", str(ORACLE / "token")
        ),
    }
    if RESULT_TAG:
        env["SONAR_ORACLE_RESULT_TAG"] = RESULT_TAG
    for name in (
        "SONAR_ORACLE_PLUGIN_ROOT",
        "SONAR_ORACLE_IMAGE_DIGEST",
        "SONAR_ORACLE_RUST_SCANNER_IMAGE_DIGEST",
        "SONAR_DOTNET_SCANNER",
        "SONAR_DOTNET_SCANNER_DLL",
        "SONAR_CSHARP_ANALYZER_PACKAGE",
        "SONAR_CSHARP_WORKSPACE",
        "SONAR_CSHARP_FIXTURE_LIMIT",
    ):
        value = os.environ.get(name)
        if value:
            env[name] = value
    prefix = " ".join(f"{name}={shlex.quote(value)}" for name, value in env.items())
    return (
        f"{prefix} python3 tools/oracle/parity_suite.py "
        f"--reference-only --project {proj}"
    )


def reference_project(
    proj: str, quick: bool
) -> tuple[dict[str, object] | None, str | None]:
    print(f"[reference {proj}]")
    if not quick:
        if not scan_project(proj):
            return None, "oracle scan failed"
        try:
            issue_count = fetch_issues(proj, allow_project_issues=True)
        except (OSError, ValueError) as error:
            print(f"  invalid oracle response: {error}")
            return None, str(error)
        print(f"  oracle issues: {issue_count}")
    sq_json = result_path(proj, "sq")
    if not sq_json.exists():
        return None, "missing Sonar artifact"
    try:
        sq_report = read_json(sq_json)
        validate_oracle_report(sq_report, expected_project=proj)
        manifest = validate_artifact_provenance(sq_report, proj, "sq")
        project_dir = ORACLE / "projects" / proj
        language = CATALOG_LANGUAGE[proj.replace("oracle-", "")]
        rules = catalog_rules(language)
        catalog_keys = [rule["external_key"] for rule in rules]
        enterprise_unverified = [
            rule["external_key"]
            for rule in rules
            if rule.get("classification") == "enterprise-unverified"
        ]
        sq_name = str(sq_json.relative_to(REPO))
        ours_name = str(result_path(proj, "ours").relative_to(REPO))
        compare = (
            f"python3 tools/oracle/diff.py {proj.replace('oracle-', '')} "
            f"{project_dir.relative_to(REPO)} {sq_name} {ours_name}"
        )
        return (
            build_reference_report(
                project=proj,
                language=language,
                project_dir=project_dir,
                sonar_report=sq_report,
                provenance=manifest,
                catalog_keys=catalog_keys,
                enterprise_unverified=enterprise_unverified,
                compare_command=compare,
                reference_command=reference_command(proj),
                sonar_artifact=sq_name,
            ),
            None,
        )
    except (OSError, ValueError) as error:
        print(f"  invalid reference artifact: {error}")
        return None, str(error)


def collect_reference_reports(
    projects: list[str], quick: bool
) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
    reports: dict[str, dict[str, object]] = {}
    invalid: dict[str, str] = {}
    for proj in projects:
        report, error = reference_project(proj, quick)
        if error is not None:
            invalid[proj] = error
        else:
            assert report is not None
            reports[proj] = report
    return reports, invalid


def reference_result_filename(projects: list[str]) -> str:
    result_parts = [] if projects == LANGS else list(projects)
    if RESULT_TAG:
        result_parts.append(RESULT_TAG)
    suffix = "." + ".".join(result_parts) if result_parts else ""
    return f"oracle_reference_matrix{suffix}.json"


def build_reference_suite_report(
    projects: list[str],
    reports: dict[str, dict[str, object]],
    invalid: dict[str, str],
) -> dict[str, object]:
    commits = sorted(
        {
            str(report["provenance"]["repository"]["commit"])
            for report in reports.values()
            if isinstance(report.get("provenance"), dict)
            and isinstance(report["provenance"].get("repository"), dict)
        }
    )
    summaries = {project: report["summary"] for project, report in reports.items()}
    reference_evidence: dict[str, object] = {}
    invalid_result = dict(invalid)
    upstream_path = RESULTS / (
        f"oracle-rust{'.' + RESULT_TAG if RESULT_TAG else ''}.upstream-contract.json"
    )
    if "oracle-rust" in projects:
        if not upstream_path.exists():
            invalid_result["oracle-rust.upstream"] = "missing Rust upstream evidence"
        else:
            try:
                upstream = read_json(upstream_path)
                if (
                    not isinstance(upstream, dict)
                    or upstream.get("schema_version") != 1
                    or not isinstance(upstream.get("boundaries"), list)
                    or not upstream["boundaries"]
                    or not isinstance(upstream.get("provenance"), dict)
                ):
                    raise ValueError("invalid Rust upstream evidence schema")
                upstream_commit = (
                    upstream["provenance"].get("repository", {}).get("commit")
                    if isinstance(upstream["provenance"].get("repository"), dict)
                    else None
                )
                if len(commits) != 1 or upstream_commit != commits[0]:
                    raise ValueError("Rust upstream evidence commit mismatch")
                reference_evidence["rust_upstream_boundaries"] = upstream
            except (OSError, ValueError, TypeError) as error:
                invalid_result["oracle-rust.upstream"] = str(error)
    if len(commits) > 1:
        invalid_result["provenance"] = "reference artifacts bind different commits"
    return {
        "schema_version": 1,
        "kind": "reference_matrix_suite",
        "reference_only": True,
        "native_status": "DEFERRED",
        "result_tag": RESULT_TAG or None,
        "projects": projects,
        "repository_commits": commits,
        "summary": summaries,
        "matrices": reports,
        "reference_evidence": reference_evidence,
        "invalid_artifacts": invalid_result,
        "failure_count": len(invalid_result),
    }


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
            native_context = RUN_NATIVE_CONTEXT.get(f"{proj}:ours")
            execution = (
                native_context.get("execution")
                if isinstance(native_context, dict)
                else None
            )
            reason = (
                execution.get("reason")
                if isinstance(execution, dict)
                else native_context.get("reason")
                if isinstance(native_context, dict)
                else None
            )
            return None, None, str(reason or "hoonarqube analysis failed")
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
        validate_artifact_provenance(sq_report, proj, "sq")
        validate_artifact_provenance(ours_report, proj, "ours")
        validate_compatible_manifests(sq_report, ours_report)
        native_evidence = ours_report.get("oracle_evidence")
        if (
            f"{proj}:ours" not in RUN_NATIVE_CONTEXT
            and isinstance(native_evidence, dict)
            and isinstance(native_evidence.get("native_context"), dict)
        ):
            RUN_NATIVE_CONTEXT[f"{proj}:ours"] = dict(native_evidence["native_context"])
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
    provenance: dict[str, dict[str, object]] = {}
    for proj in projects:
        artifacts: dict[str, object] = {}
        for kind in ("sq", "ours"):
            path = result_path(proj, kind)
            if not path.exists():
                continue
            try:
                artifact = read_json(path)
            except (OSError, ValueError):
                continue
            if isinstance(artifact, dict) and isinstance(
                artifact.get("oracle_provenance"), dict
            ):
                artifacts[kind] = artifact["oracle_provenance"]
        if artifacts:
            provenance[proj] = artifacts
    native_context = {
        proj: dict(context)
        for proj in projects
        if isinstance((context := RUN_NATIVE_CONTEXT.get(f"{proj}:ours")), dict)
    }
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
        "matrix": {proj: list(rows) for proj, rows in all_rows.items()},
        "artifact_provenance": provenance,
        "native_context": native_context,
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


def print_reference_summary(report: dict[str, object], result_name: str) -> None:
    print("REFERENCE-ONLY MATRIX (native status: DEFERRED)")
    for project, matrix in report["matrices"].items():
        summary = matrix["summary"]
        print(f"  {project}: {summary}")
        print(f"    native compare: {matrix['compare_command']}")
    for project, reason in report["invalid_artifacts"].items():
        print(f"  {project} [INVALID_ARTIFACT] {reason}")
    print(f"matrix: {result_name}")


def reference_main(projects: list[str], quick: bool) -> None:
    if not quick:
        ensure_container()
    matrices, invalid = collect_reference_reports(projects, quick)
    report = build_reference_suite_report(projects, matrices, invalid)
    result_name = reference_result_filename(projects)
    RESULTS.mkdir(parents=True, exist_ok=True)
    write_reference_report(RESULTS / result_name, report)
    print_reference_summary(report, result_name)
    sys.exit(0 if report["failure_count"] == 0 else 1)


def main():
    args = parse_args()
    quick = args.quick
    projects = args.project or LANGS
    if args.reference_only:
        reference_main(projects, quick)
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
