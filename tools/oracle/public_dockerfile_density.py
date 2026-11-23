"""Check overall duplication gates without running the pinned public sources."""

import argparse
import hashlib
import json
import tempfile
from pathlib import Path
from urllib.request import urlopen

from docker_density_controls import check as check_negative_controls
from public_scope_gate import assigned, require, scan


REFERENCE = Path(__file__).with_name("fixtures") / "dockerfile-duplication-2611.json"
POLICY = {
    "schema_version": 1,
    "conditions": [
        {
            "scope": "overall",
            "metric": "duplicated_lines_density",
            "operator": "lte",
            "threshold": 3,
        }
    ],
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_bytes(index, cache):
    result = {}
    for sha, row in index.items():
        if "hex" in row:
            data = bytes.fromhex(row["hex"])
        elif cache:
            data = (cache / sha).read_bytes()
        else:
            url = "https://raw.githubusercontent.com/{repository}/{commit}/{path}"
            with urlopen(url.format(**row), timeout=30) as stream:
                data = stream.read(1024 * 1024)
        require(digest(data) == sha, f"source digest {sha}")
        result[sha] = data
    return result


def verify_tree(root, row):
    paths = sorted(root.rglob("*"))
    require(all(not p.is_symlink() for p in paths), "unexpected symlink")
    files = {
        p.relative_to(root).as_posix(): digest(p.read_bytes())
        for p in paths
        if p.is_file()
    }
    manifest = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    require(
        len(files) == row["count"] and digest(manifest) == row["sha256"],
        "wrong complete tracked tree",
    )


def run_case(binaries, root, row, policy, one_decimal):
    cli = binaries / "hoonarqube"
    code, gated = scan(cli, root, ["."], ["--quality-gate", policy])
    raw_exit, raw = scan(cli, root, ["."], [])
    gate = gated["assessment"]["gate"]
    expect = 1 if row["status"] == "ERROR" else 0
    project = raw["project"]
    require(
        code == expect and gate["status"] == ("fail" if expect else "pass"),
        f"wrong decision: {root.name}",
    )
    require(project == gated["project"], "CLI and service inputs differ")
    if row["dockerfiles"]:
        require(
            raw_exit == 2
            and not project["complete"]
            and project["duplication"] is None,
            "unknown analysis scope",
        )
        evidence = project["docker_duplication"]
        measured = {
            Path(f["path"]).as_posix(): f["lines"] for f in evidence["dockerfiles"]
        }
        require(
            measured == row["dockerfiles"],
            "Dockerfile denominator differs from Community",
        )
        lines = project["metrics"]["lines"] + sum(measured.values())
        duplicated = evidence["go_duplicated_lines"]
    else:
        require(raw_exit == 0 and project["complete"], "missing Go baseline")
        lines = project["metrics"]["lines"]
        duplicated = project["duplication"]["duplicated_lines"]
    require(lines > 0, "empty denominator")
    actual = gate["conditions"][0]["actual"]
    expected = (
        ((duplicated * 2000 + lines) // (2 * lines)) / 10
        if one_decimal
        else 100.0 * duplicated / lines
    )
    require(abs(actual - expected) < 1e-10, "value differs from counters")
    if "lines" in row:
        require(lines == row["lines"], "wrong whole denominator")
    return (raw, gate, code), {
        "eligible_lines": lines,
        "duplicated_lines": duplicated,
        "actual": actual,
        "community": row["density"],
        "cli_and_ci_exit": code,
    }


def replay(binaries, tree_dir, cache, one_decimal):
    reference = json.loads(REFERENCE.read_bytes())
    sources = source_bytes(reference["sources"], cache)
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        policy = dict(POLICY, conditions=[dict(POLICY["conditions"][0])])
        if one_decimal:
            policy["conditions"][0]["precision"] = "one_decimal"
        policy_file = work / "policy.json"
        policy_file.write_text(json.dumps(policy))
        cases = {}
        results = {}
        for name, row in reference["cases"].items():
            root = work / name
            for name_in_tree, sha in row["files"].items():
                path = root / name_in_tree
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(sources[sha])
            cases[name], results[name] = run_case(
                binaries, root, row, policy_file, one_decimal
            )
        for name, result in results.items():
            if name != "only-redis":
                require(
                    result["duplicated_lines"]
                    == results["baseline"]["duplicated_lines"],
                    "Dockerfiles created duplicate blocks",
                )
        if tree_dir:
            for name, row in reference["trees"].items():
                root = tree_dir / name / "files"
                verify_tree(root, row)
                cases[name], results[name] = run_case(
                    binaries, root, row, policy_file, one_decimal
                )
        check_negative_controls(binaries, work, policy_file)
        assigned(binaries / "hoonarqube-service", work, policy, "d" * 40, cases)
        return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binaries", type=Path)
    parser.add_argument(
        "--source-cache", type=Path, help="immutable public blobs, named by SHA-256"
    )
    parser.add_argument(
        "--trees",
        type=Path,
        help="optional complete pinned trees under OWNER--REPO/files",
    )
    parser.add_argument(
        "--one-decimal",
        action="store_true",
        help="requires the Community rounding policy",
    )
    args = parser.parse_args()
    print(
        json.dumps(
            replay(
                args.binaries.resolve(), args.trees, args.source_cache, args.one_decimal
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
