"""Replay two assigned Community file gates on the same pinned Laravel sources."""

import argparse
import json
import tempfile
from pathlib import Path

from public_scope_gate import assigned, require, scan
from wave4_prepare import git, inventory, verify_checkout_paths, verify_head

REFERENCE = Path(__file__).with_name("fixtures") / "laravel-php-gate-2611.json"
JS = "resources/js/app.js"
PHP = "routes/web.php"


def verify_source(repo, ref):
    verify_head(repo, ref["commit"], ref["tree"])
    blobs = {
        p: git(repo, "rev-parse", f"HEAD:{p}").decode().strip() for p in ref["files"]
    }
    verify_checkout_paths(repo, blobs)
    require(
        {p: v["sha256"] for p, v in inventory(repo, blobs).items()} == ref["files"],
        "source bytes changed",
    )


def checkout(repo, ref, remote):
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "fetch", "--quiet", "--depth=1", "--no-tags", remote, ref["commit"])
    git(repo, "sparse-checkout", "init", "--no-cone")
    git(
        repo,
        "sparse-checkout",
        "set",
        "--no-cone",
        "--stdin",
        stdin=f"/{JS}\n/{PHP}\n".encode(),
    )
    git(repo, "checkout", "--quiet", "--detach", ref["commit"])
    verify_source(repo, ref)


def verify_reference(ref):
    full, scoped = (ref["cases"][k] for k in ("mixed", "exclude_php"))
    require(
        ref["community_version"] == "26.11.0.134175"
        and ref["repository"] == "laravel/laravel",
        "reference changed",
    )
    require(
        ref["gate"]["metric"] == "files"
        and ref["gate"]["comparator"] == "GT"
        and ref["gate"]["error"] == "1",
        "wrong policy",
    )
    require(
        full["analysis"] != scoped["analysis"] and full["task"] != scoped["task"],
        "analyses must be independent",
    )
    require(
        (full["status"], full["actual_files"], full["indexed"], full["exclusions"])
        == ("ERROR", 2, {JS: "js", PHP: "php"}, []),
        "wrong mixed reference",
    )
    require(
        (
            scoped["status"],
            scoped["actual_files"],
            scoped["indexed"],
            scoped["exclusions"],
        )
        == ("OK", 1, {JS: "js"}, ["**/*.php"]),
        "wrong excluded reference",
    )


def results(cli, repo, policy, ref):
    cases = {}
    for name, paths, exclude in (
        ("mixed", ["."], False),
        ("explicit", [JS, PHP], False),
        ("overlap", [".", PHP], False),
        ("exclude_php", ["."], True),
    ):
        scoped = ref["cases"]["exclude_php" if exclude else "mixed"]["exclusions"]
        scope = [arg for pattern in scoped for arg in ("--exclude", pattern)]
        code, report = scan(cli, repo, paths, [*scope, "--quality-gate", policy])
        gate = report["assessment"]["gate"]
        (condition,) = gate["conditions"]
        expected = ("pass", 0, 1.0) if exclude else ("unavailable", 2, None)
        require(
            (gate["status"], code, condition["actual"]) == expected,
            f"{name}: {gate['status']}, exit {code}, actual {condition['actual']}",
        )
        require(report["project"]["complete"] == exclude, f"{name}: completeness")
        rows = [
            (Path(i["path"]).as_posix(), i["classification"], i["status"])
            for i in report["project"]["files"]
        ]
        require(
            sorted(rows)
            == [
                (JS, "source", "complete"),
                (
                    PHP,
                    "excluded" if exclude else "source",
                    "excluded" if exclude else "unsupported",
                ),
            ],
            f"{name}: wrong inventory {rows}",
        )
        _, raw = scan(cli, repo, paths, [*scope, "--assessment"])
        cases[name] = (raw, gate, code)
    return cases


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("binaries", type=Path)
    p.add_argument("--repository", default="https://github.com/laravel/laravel.git")
    a = p.parse_args()
    ref = json.loads(REFERENCE.read_bytes())
    verify_reference(ref)
    with tempfile.TemporaryDirectory() as td:
        work = Path(td).resolve()
        repo = work / "repo"
        checkout(repo, ref, a.repository)
        config = {
            "schema_version": 1,
            "conditions": [
                {
                    "metric": "files",
                    "scope": "overall",
                    "operator": "lte",
                    "threshold": 1,
                }
            ],
        }
        policy = work / "gate.json"
        policy.write_text(json.dumps(config))
        bins = a.binaries.resolve()
        cases = results(bins / "hoonarqube", repo, policy, ref)
        assigned(bins / "hoonarqube-service", work, config, ref["commit"], cases)
        verify_source(repo, ref)
        print(
            "laravel/laravel:",
            ", ".join(
                f"{name} {gate['status']}/CI {code}"
                for name, (_, gate, code) in cases.items()
            ),
            "; restart verified",
        )


if __name__ == "__main__":
    main()
