"""Negative CLI and HTTP controls for scoped Dockerfile duplication evidence."""

from copy import deepcopy
import json
from pathlib import Path
import secrets
import tempfile

from public_scope_gate import assigned, request, require, running_service, scan


def path_cases(cli, work, policy):
    source = work / "negative-scope"
    source.mkdir()
    dockerfile = source / "Dockerfile"
    dockerfile.write_text("FROM scratch\n")
    (source / "lib.go").write_text("package demo\n")
    for name, content, flags in [
        ("Dockerfile", b"FROM\x00scratch", []),
        ("Dockerfile", b"\xff", []),
        ("Dockerfile", b"FROM scratch", ["--test-include", "Dockerfile"]),
        ("Dockerfile", b"FROM scratch", ["--duplication-exclude", "Dockerfile"]),
        ("Dockerfile", b"FROM scratch", ["--duplication-exclude", "*.go"]),
        ("Dockerfile", b"FROM scratch", ["--duplication-min-lines", "2"]),
        ("style.css", b"body {}", []),
        ("other.py", b"print(1)", []),
    ]:
        f = source / name
        f.write_bytes(content)
        code, report = scan(cli, source, ["."], [*flags, "--quality-gate", policy])
        gate = report["assessment"]["gate"]
        require(
            code == 2
            and gate["status"] == "unavailable"
            and gate["conditions"][0]["actual"] is None,
            f"unsafe decision for {name}, {flags}",
        )
        require(
            "docker_duplication" not in report["project"],
            "partial source population accepted",
        )
        if name != "Dockerfile":
            f.unlink()
    dockerfile.unlink()
    dockerfile.symlink_to("lib.go")
    code, _ = scan(cli, source, ["Dockerfile", "lib.go"], ["--quality-gate", policy])
    require(code == 2, "symlink yielded a measured Dockerfile")
    dockerfile.unlink()
    dockerfile.write_text("FROM scratch")
    return source


def with_gate(binaries, root, config):
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        p = work / "policy.json"
        p.write_text(json.dumps(config))
        code, report = scan(binaries / "hoonarqube", root, ["."], ["--quality-gate", p])
        gate = report["assessment"]["gate"]
        require(
            code == 2 and gate["status"] == "unavailable", "other gate was released"
        )
        require(gate["conditions"][-1]["actual"] is None, "unproven value")
        _, raw = scan(binaries / "hoonarqube", root, ["."], [])
        assigned(
            binaries / "hoonarqube-service",
            work,
            config,
            "a" * 40,
            {"partial": (raw, gate, code)},
        )
        return raw


def http_controls(service, work, raw):
    token = secrets.token_urlsafe(32)
    mutations = [
        ("complete", lambda p: p.update(complete=True)),
        ("extra-warning", lambda p: p["warnings"].append("unreadable file")),
        ("missing-warning", lambda p: p["warnings"].clear()),
        ("fake-count", lambda p: p["docker_duplication"].update(go_duplicated_lines=1)),
        (
            "wrong-path",
            lambda p: p["docker_duplication"]["dockerfiles"][0].update(
                path="foo/Dockerfile"
            ),
        ),
        (
            "alias-path",
            lambda p: p["docker_duplication"]["dockerfiles"][0].update(
                path="a/../Dockerfile"
            ),
        ),
        (
            "oversize",
            lambda p: p["docker_duplication"]["dockerfiles"][0].update(bytes=2**25),
        ),
        ("missing-go-input", lambda p: p["docker_duplication"]["go_files"].clear()),
        (
            "unexpected-source",
            lambda p: p["files"].append(
                dict(
                    path="a.css",
                    status="unsupported",
                    classification="source",
                    reason="language is unsupported",
                )
            ),
        ),
        (
            "downgraded-source",
            lambda p: p["files"].append(
                dict(
                    path="a.css",
                    status="unsupported",
                    classification="excluded",
                    reason="language is unsupported",
                )
            ),
        ),
    ]
    with running_service(service, work, token) as port:
        for label, mutate in mutations:
            report = deepcopy(raw)
            mutate(report["project"])
            data = dict(
                schema_version=1,
                branch=label,
                commit="d" * 40,
                analyzed_at="2026-11-23T00:00:00Z",
                report=report,
            )
            try:
                request(port, token, "/smoke/analyses", data)
            except RuntimeError as error:
                require("HTTP 400:" in str(error), f"{label}: {error}")
            else:
                raise ValueError(f"service accepted {label}")


def check(binaries, work, policy):
    root = path_cases(binaries / "hoonarqube", work, policy)
    condition = json.loads(policy.read_bytes())["conditions"][0]
    for scope, metric in [
        ("overall", "files"),
        ("overall", "issues"),
        ("overall", "coverage"),
        ("new_code", "duplicated_lines_density"),
        ("overall", "duplicated_blocks"),
    ]:
        other = dict(scope=scope, metric=metric, operator="lte", threshold=3)
        raw = with_gate(
            binaries, root, {"schema_version": 1, "conditions": [condition, other]}
        )
    http_controls(binaries / "hoonarqube-service", work, raw)
