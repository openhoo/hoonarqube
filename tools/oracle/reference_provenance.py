#!/usr/bin/env python3
"""Deterministic provenance for SonarQube oracle artifacts.

The reference artifacts are evidence, not just cached JSON.  Every artifact
records the exact repository commit, fixture/catalog bytes, reference server,
profile, analyzer plugins, scanner/compiler context, and stable scan
parameters.  The manifest digest is stored in the artifact's oracle_evidence
and is checked before a matrix or comparison can consume the artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = 1
_HEX40 = set("0123456789abcdef")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Hash a manifest without trusting a self-reported digest field."""
    value = dict(manifest)
    value.pop("manifest_sha256", None)
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_metadata(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    original = Path(path)
    if original.is_symlink():
        raise ValueError(f"provenance input must be a regular file: {original}")
    path = original.resolve()
    if not path.is_file():
        raise ValueError(f"provenance input must be a regular file: {path}")
    display = str(path)
    if root is not None:
        try:
            display = str(path.relative_to(root.resolve()))
        except ValueError:
            display = str(path)
    return {
        "path": display,
        "size": path.stat().st_size,
        "sha256": file_sha256(path),
    }


def command_fingerprint(
    command: Iterable[str], *, version_args: Iterable[str] = ("--version",)
) -> dict[str, Any]:
    """Capture an executable path, digest, argv, and bounded version output."""
    argv = [str(item) for item in command]
    if not argv:
        raise ValueError("provenance command must not be empty")
    executable = Path(argv[0])
    resolved = executable if executable.is_absolute() else shutil.which(argv[0])
    if resolved is None:
        return {"argv": argv, "available": False}
    resolved_path = Path(resolved).resolve()
    result: dict[str, Any] = {
        "argv": argv,
        "available": resolved_path.is_file(),
        "path": str(resolved_path),
    }
    if resolved_path.is_file():
        result["sha256"] = file_sha256(resolved_path)
    try:
        version = subprocess.run(
            [*argv, *version_args],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        result["version_error"] = str(error)
    else:
        output = (version.stdout + version.stderr).strip()
        result["version_exit"] = version.returncode
        result["version"] = output[:4096]
        result["version_sha256"] = hashlib.sha256(output.encode()).hexdigest()
    return result


def git_provenance(repo: Path) -> dict[str, Any]:
    """Bind evidence to the checked-out commit without requiring a clean tree."""
    repo = repo.resolve()
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout.strip()
        status = subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(
            f"cannot determine repository provenance: {error}"
        ) from error
    if len(revision) != 40 or any(char not in _HEX40 for char in revision.lower()):
        raise RuntimeError(f"unexpected repository revision: {revision!r}")
    return {
        "commit": revision,
        "worktree_dirty": bool(status),
        "worktree_status_sha256": hashlib.sha256(status.encode()).hexdigest(),
    }


def _plugin_file(
    plugin_root: Path | None, plugin: Mapping[str, Any]
) -> dict[str, Any] | None:
    if plugin_root is None:
        return None
    filename = plugin.get("filename")
    if not isinstance(filename, str) or not filename:
        return None
    matches = sorted(plugin_root.resolve().rglob(filename))
    if len(matches) != 1:
        return {"filename": filename, "matches": [str(path) for path in matches]}
    return file_metadata(matches[0], root=plugin_root)


def normalize_plugins(
    plugins: Iterable[Mapping[str, Any]], *, plugin_root: Path | None = None
) -> list[dict[str, Any]]:
    """Keep server plugin API metadata and hash the exact live JAR when possible."""
    normalized = []
    for raw in plugins:
        key = raw.get("key")
        filename = raw.get("filename")
        if not isinstance(key, str) or not isinstance(filename, str):
            continue
        item = {
            field: raw[field]
            for field in (
                "key",
                "name",
                "version",
                "implementationBuild",
                "filename",
                "hash",
                "editionBundled",
            )
            if field in raw
        }
        live = _plugin_file(plugin_root, raw)
        if live is not None:
            item["live_file"] = live
        normalized.append(item)
    return sorted(normalized, key=lambda value: (value["key"], value["filename"]))


def package_metadata(path: Path, *, root: Path | None = None) -> dict[str, Any]:
    """Hash a package and its public metadata sidecars."""
    original = Path(path)
    if original.is_symlink():
        raise ValueError(f"provenance package must not be a symlink: {original}")
    path = original.resolve()
    if not path.is_file():
        raise ValueError(f"package does not exist: {path}")
    result = file_metadata(path, root=root)
    candidates = [path.with_name(path.name + ".sha512")]
    candidates.extend(path.parent.glob("*.nuspec"))
    candidates.append(path.parent / ".signature.p7s")
    sidecars = []
    seen: set[Path] = set()
    for candidate in candidates:
        original_candidate = Path(candidate)
        if original_candidate.is_symlink():
            raise ValueError(
                f"provenance sidecar must not be a symlink: {original_candidate}"
            )
        candidate = original_candidate.resolve()
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        sidecars.append(file_metadata(original_candidate, root=root))
    if sidecars:
        result["sidecars"] = sorted(sidecars, key=lambda value: value["path"])
    return result


def make_manifest(
    *,
    repo: Path,
    project: str,
    kind: str,
    input_sha256: str,
    source_root: Path,
    expected: Path,
    catalog: Path,
    server: Mapping[str, Any],
    profile: Mapping[str, Any],
    plugins: Iterable[Mapping[str, Any]],
    parameters: Mapping[str, Any],
    tools: Mapping[str, Any],
    plugin_root: Path | None = None,
    packages: Iterable[Path] = (),
) -> dict[str, Any]:
    if kind not in {"sq", "ours"}:
        raise ValueError(f"invalid provenance artifact kind: {kind}")
    manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "project": project,
        "kind": kind,
        "repository": git_provenance(repo),
        "inputs": {
            "input_sha256": input_sha256,
            "source_root": str(source_root.resolve()),
            "expected": file_metadata(expected, root=repo),
            "catalog": file_metadata(catalog, root=repo),
        },
        "server": dict(server),
        "profile": dict(profile),
        "plugins": normalize_plugins(plugins, plugin_root=plugin_root),
        "parameters": dict(parameters),
        "tools": dict(tools),
    }
    package_rows = [package_metadata(path, root=repo) for path in packages]
    if package_rows:
        manifest["packages"] = sorted(package_rows, key=lambda value: value["path"])
    manifest["manifest_sha256"] = manifest_digest(manifest)
    return manifest


def validate_manifest(
    manifest: Any,
    *,
    project: str,
    kind: str,
    input_sha256: str | None = None,
    commit: str | None = None,
) -> dict[str, Any]:
    if not isinstance(manifest, dict):
        raise ValueError("oracle artifact lacks provenance manifest")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("unsupported oracle provenance schema")
    if manifest.get("project") != project or manifest.get("kind") != kind:
        raise ValueError("oracle provenance identity mismatch")
    digest = manifest.get("manifest_sha256")
    if not isinstance(digest, str) or digest != manifest_digest(manifest):
        raise ValueError("oracle provenance manifest digest mismatch")
    repository = manifest.get("repository")
    if not isinstance(repository, dict):
        raise ValueError("oracle provenance lacks repository context")
    actual_commit = repository.get("commit")
    if (
        not isinstance(actual_commit, str)
        or len(actual_commit) != 40
        or any(char not in _HEX40 for char in actual_commit.lower())
    ):
        raise ValueError("oracle provenance lacks exact repository commit")
    if commit is not None and actual_commit != commit:
        raise ValueError("oracle provenance commit mismatch")
    inputs = manifest.get("inputs")
    if not isinstance(inputs, dict):
        raise ValueError("oracle provenance lacks input context")
    if input_sha256 is not None and inputs.get("input_sha256") != input_sha256:
        raise ValueError("oracle provenance input fingerprint mismatch")
    return manifest


def _validate_equal_fields(
    left: Mapping[str, Any],
    right: Mapping[str, Any],
    fields: tuple[str, ...],
    *,
    prefix: str = "",
) -> None:
    for field in fields:
        if left.get(field) != right.get(field):
            label = f"{prefix}.{field}" if prefix else field
            raise ValueError(f"comparison provenance mismatch: {label}")


def _validate_repository_context(
    left: Mapping[str, Any], right: Mapping[str, Any]
) -> None:
    left_repo = left.get("repository")
    right_repo = right.get("repository")
    if (
        not isinstance(left_repo, dict)
        or not isinstance(right_repo, dict)
        or left_repo.get("commit") != right_repo.get("commit")
    ):
        raise ValueError("comparison provenance mismatch: repository commit")


def _validate_input_context(left: Mapping[str, Any], right: Mapping[str, Any]) -> None:
    left_inputs = left.get("inputs")
    right_inputs = right.get("inputs")
    if not isinstance(left_inputs, dict) or not isinstance(right_inputs, dict):
        raise ValueError("comparison provenance lacks input context")
    _validate_equal_fields(
        left_inputs,
        right_inputs,
        ("source_root", "expected", "catalog"),
        prefix="inputs",
    )


def _comparable_tools(left: Any, right: Any) -> tuple[Any, Any]:
    if isinstance(left, dict) and isinstance(right, dict):
        native_executable = right.get("hoonarqube_executable")
        if not isinstance(native_executable, dict):
            raise ValueError("comparison provenance lacks native executable")
        left = {
            key: value for key, value in left.items() if key != "hoonarqube_executable"
        }
        right = {
            key: value for key, value in right.items() if key != "hoonarqube_executable"
        }
    return left, right


def _comparable_parameters(left: Any, right: Any) -> tuple[Any, Any]:
    if isinstance(left, dict) and isinstance(right, dict):
        left = {key: value for key, value in left.items() if key != "kind"}
        right = {key: value for key, value in right.items() if key != "kind"}
    return left, right


def _provenance_pair(
    sonar: Mapping[str, Any], ours: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    left = sonar.get("oracle_provenance")
    right = ours.get("oracle_provenance")
    if not isinstance(left, dict) or not isinstance(right, dict):
        raise ValueError("comparison artifacts require provenance manifests")
    return left, right


def validate_compatible_manifests(
    sonar: Mapping[str, Any], ours: Mapping[str, Any]
) -> None:
    """Require shared fixture/server/tool identity for a native comparison."""
    left, right = _provenance_pair(sonar, ours)
    _validate_repository_context(left, right)
    _validate_input_context(left, right)
    _validate_equal_fields(
        left,
        right,
        ("server", "profile", "plugins", "packages"),
    )
    left_tools, right_tools = _comparable_tools(left.get("tools"), right.get("tools"))
    if left_tools != right_tools:
        raise ValueError("comparison provenance mismatch: tools")
    left_parameters, right_parameters = _comparable_parameters(
        left.get("parameters"), right.get("parameters")
    )
    if left_parameters != right_parameters:
        raise ValueError("comparison provenance mismatch: parameters")


def tool_versions(
    *,
    include_dotnet: bool = False,
    include_rust: bool = False,
    include_go: bool = False,
) -> dict[str, Any]:
    tools: dict[str, Any] = {}
    if include_dotnet:
        tools["dotnet"] = command_fingerprint(["dotnet"], version_args=("--version",))
    if include_rust:
        tools["rustc"] = command_fingerprint(["rustc"], version_args=("--version",))
        tools["cargo"] = command_fingerprint(["cargo"], version_args=("--version",))
    if include_go:
        tools["go"] = command_fingerprint(["go"], version_args=("version",))
    return tools


def environment_value(name: str) -> str | None:
    value = os.environ.get(name)
    return value if value else None
