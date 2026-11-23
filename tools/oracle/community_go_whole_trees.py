"""Replay Community 26.11 overall duplication on complete, immutable public Git trees.

Run with --binary /path/to/hoonarqube. Add --mirrors DIR for offline use
(DIR/owner--repo/objects is a bare mirror), --project owner/repo for one case,
--output FILE for full residual line maps, or --enforce-gate for a CLI supporting
an overall one_decimal duplication gate. Without that flag compare the scanner's
density to the frozen Community threshold, independently of the CLI exit policy.
No checkout, repository build, hooks, submodule initialization or source execution.
"""

import argparse
from collections import defaultdict
from decimal import Decimal, ROUND_HALF_UP
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from public_contract import require

MANIFEST = Path(__file__).with_suffix(".json")
TENTH = Decimal("0.1")
LIMIT = Decimal("3.0")
POLICY = {
    "schema_version": 1,
    "conditions": [
        {
            "metric": "duplicated_lines_density",
            "operator": "lte",
            "scope": "overall",
            "precision": "one_decimal",
            "threshold": 3.0,
        }
    ],
}
MAX_FILES, MAX_BYTES, MAX_BLOB, MAX_LINES = 4096, 64 << 20, 16 << 20, 1_000_000
OID = re.compile(r"[0-9a-f]{40}")
SLUG = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*")
SEGMENT = re.compile(r"[A-Za-z0-9_.() -]{1,255}")
DEVICE = re.compile(r"(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", re.I)


def safe_tree_path(path):
    parts = path.split("/")
    require(
        len(path) <= 1024
        and all(
            SEGMENT.fullmatch(s)
            and s.lower() != ".git"
            and not s.endswith((".", " "))
            and not DEVICE.fullmatch(s)
            for s in parts
        ),
        f"unsafe tree path: {path!r}",
    )
    return path


def inventory_hash(files):
    """Canonical SHA-256 of path -> content SHA-256; Git tree also binds modes."""
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def git(repo, *args, mirror=None, data=None, network=False):
    env = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "https" if network else "",
    }
    if mirror is not None:
        # Only read objects. Never open a supplied mirror's Git config or hooks.
        env["GIT_ALTERNATE_OBJECT_DIRECTORIES"] = str(
            (mirror / "objects").resolve(strict=True)
        )
    return subprocess.run(
        [
            "git",
            "-c",
            "core.hooksPath=" + os.devnull,
            "-c",
            "credential.helper=",
            "-C",
            str(repo),
            *args,
        ],
        input=data,
        env=env,
        capture_output=True,
        check=True,
        timeout=120,
    ).stdout


def tree_entries(listing):
    files, directories, spellings, total = [], set(), {}, 0
    for entry in listing.split(b"\0"):
        if not entry:
            continue
        head, raw = entry.split(b"\t", 1)
        mode, kind, oid, size = head.split()
        path = safe_tree_path(raw.decode("ascii"))
        parent = path.rpartition("/")[0]
        require(not parent or parent in directories, f"unknown tree parent: {path}")
        key = path.casefold()
        require(key not in spellings, f"colliding Git path: {path}")
        spellings[key] = path
        require(OID.fullmatch(oid.decode()), "invalid object ID")
        if (mode, kind, size) == (b"040000", b"tree", b"-"):
            directories.add(path)
            continue
        require(
            mode in {b"100644", b"100755"} and kind == b"blob",
            f"non-regular Git entry: {path}",
        )
        require(size.isdigit() and int(size) <= MAX_BLOB, f"oversized Git blob: {path}")
        total += int(size)
        files.append((path, oid, int(size)))
        require(
            len(files) <= MAX_FILES and total <= MAX_BYTES, "tree exceeds corpus bounds"
        )
    # Reject separately tracked empty tree entries rather than silently omitting them.
    parents = {p.rpartition("/")[0] for p in {*directories, *(f[0] for f in files)}}
    require(directories <= parents and files, "empty Git tree")
    return files, total


def stage(case, scratch, mirror=None):
    repo = scratch / "objects"
    repo.mkdir()
    git(repo, "init", "--quiet", "--bare", "--template=")
    commit, tree, slug = case["commit"], case["tree"], case["repository"]
    require(
        OID.fullmatch(commit) and OID.fullmatch(tree) and SLUG.fullmatch(slug),
        "invalid project pin",
    )
    if mirror is None:
        git(
            repo,
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "--no-recurse-submodules",
            f"https://github.com/{slug}.git",
            commit,
            network=True,
        )
        require(
            git(repo, "rev-parse", "FETCH_HEAD").decode().strip() == commit,
            "wrong fetched commit",
        )
    require(
        git(repo, "cat-file", "-t", commit, mirror=mirror).strip() == b"commit",
        "not a commit",
    )
    require(
        git(repo, "rev-parse", commit + "^{tree}", mirror=mirror).decode().strip()
        == tree,
        "wrong tree",
    )
    rows, total = tree_entries(git(repo, "ls-tree", "-rltz", tree, mirror=mirror))
    pin = case["tracked"]
    require(
        (len(rows), total) == (pin["files"], pin["bytes"]), "incomplete tree inventory"
    )
    payload = git(
        repo,
        "cat-file",
        "--batch",
        mirror=mirror,
        data=b"".join(oid + b"\n" for _, oid, _ in rows),
    )
    source = scratch / "source"
    source.mkdir()
    offset, digests, limits = 0, {}, {}
    for path, oid, size in rows:
        end = payload.index(b"\n", offset)
        require(
            payload[offset:end].split() == [oid, b"blob", str(size).encode()],
            f"wrong Git blob: {path}",
        )
        body = payload[end + 1 : end + 1 + size]
        offset = end + size + 2
        require(
            len(body) == size and payload[offset - 1 : offset] == b"\n",
            "truncated Git blob",
        )
        dest = source / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open("xb") as out:
            out.write(body)  # Executable Git blobs are staged as ordinary data.
        digests[path] = hashlib.sha256(body).hexdigest()
        limits[path] = body.count(b"\n") + 1
    require(
        offset == len(payload) and inventory_hash(digests) == pin["sha256"],
        "wrong complete source bytes",
    )
    return source, limits


def compact(points):
    by_path = defaultdict(list)
    for path, line in sorted(points):
        ranges = by_path[path]
        if ranges and line == ranges[-1][1] + 1:
            ranges[-1][1] = line
        else:
            ranges.append([line, line])
    return {
        path: ",".join(str(a) if a == b else f"{a}-{b}" for a, b in ranges)
        for path, ranges in by_path.items()
    }


def expand(mapping, limits):
    result = set()
    for path, text in mapping.items():
        require(path in limits, f"untracked reference path: {path}")
        previous = -1
        for part in text.split(","):
            m = re.fullmatch(r"([1-9][0-9]*)(?:-([1-9][0-9]*))?", part)
            require(m, f"invalid line range: {part}")
            first, last = int(m[1]), int(m[2] or m[1])
            require(
                previous + 1 < first <= last <= min(limits[path], MAX_LINES),
                f"invalid lines for {path}: {part}",
            )
            require(
                len(result) + last - first + 1 <= MAX_LINES, "too many duplicated lines"
            )
            result.update((path, i) for i in range(first, last + 1))
            previous = last
    return result


def decimal(value):
    require(
        type(value) in (str, Decimal, int, float), f"missing numeric measure: {value}"
    )
    number = Decimal(str(value))
    require(number.is_finite() and 0 <= number <= 100, f"invalid percentage: {number}")
    return number


def one_decimal(value):
    return value.quantize(TENTH, rounding=ROUND_HALF_UP)


def status(density):
    return "ERROR" if density > LIMIT else "OK"


def file_path(text):
    return safe_tree_path(text.removeprefix("./"))


def observed(project, limits):
    require(
        project["complete"] is True
        and project["roots"] == ["."]
        and not project["warnings"],
        "incomplete native analysis or incorrect roots",
    )
    inventory, complete = set(), set()
    for row in project["files"]:
        path = file_path(row["path"])
        require(
            path in limits and path not in inventory, f"invalid native file: {path}"
        )
        inventory.add(path)
        if row["status"] == "complete":
            complete.add(path)
    lines = set()
    for group in project["duplications"]:
        per_group = group["occurrences"]
        require(len(per_group) >= 2, "duplication has no companion")
        for item in per_group:
            path = file_path(item["path"])
            a, b = item["start_line"], item["end_line"]
            require(
                path in complete
                and type(a) is type(b) is int
                and 1 <= a <= b <= min(limits[path], MAX_LINES),
                f"invalid duplicated lines: {path} {a}:{b}",
            )
            related_only = item.get("relation_only", False)
            require(type(related_only) is bool, "invalid duplication relation flag")
            if not related_only:
                lines.update((path, n) for n in range(a, b + 1))
            require(len(lines) <= MAX_LINES, "too many native duplicated lines")
    measures = project["duplication"]
    require(
        type(measures["duplicated_lines"]) is int
        and measures["duplicated_lines"] == len(lines),
        "native total and duplicated line locations disagree",
    )
    denominator = project["metrics"]["lines"]
    require(
        type(denominator) is int and denominator > 0, "missing native line denominator"
    )
    density = one_decimal(decimal(measures["duplicated_lines_density"]))
    require(
        density == one_decimal(Decimal(100) * len(lines) / denominator),
        "inconsistent native density",
    )
    return complete, lines, density


def compare(case, project, limits):
    ref, allowance = case["community"], case["allowed_residual"]
    measured, actual, density = observed(project, limits)
    indexed = set(ref["indexed_files"])
    require(
        indexed <= limits.keys() and len(indexed) == len(ref["indexed_files"]),
        "invalid Community file inventory",
    )
    expected = expand(ref["duplicated_lines"], {p: limits[p] for p in indexed})
    require(
        len(expected) == ref["duplicated_line_count"],
        "wrong Community duplicated line count",
    )
    ref_density = decimal(ref["density"])
    require(
        ref_density == one_decimal(Decimal(100) * len(expected) / ref["lines"])
        and ref["status"] == status(ref_density),
        "inconsistent Community gate",
    )
    missing, extra = expected - actual, actual - expected
    missing_files = indexed - measured
    allowed_missing, allowed_extra = (
        expand(allowance[k], limits) for k in ("missing_lines", "extra_lines")
    )
    require(
        allowed_missing <= expected
        and allowed_extra.isdisjoint(expected)
        and set(allowance["missing_files"]) <= indexed,
        "inconsistent residual allowance",
    )
    regressions = []
    if status(density) != ref["status"]:
        regressions.append("gate decision")
    if abs(density - ref_density) > decimal(allowance["density_delta"]):
        regressions.append("density")
    if not missing <= allowed_missing or not extra <= allowed_extra:
        regressions.append("duplicated line locations")
    if not missing_files <= set(allowance["missing_files"]) or measured - indexed:
        regressions.append("indexed files")
    return {
        "repository": case["repository"],
        "commit": case["commit"],
        "tree": case["tree"],
        "analysis": ref["analysis"],
        "tracked": len(limits),
        "community_status": ref["status"],
        "community_density": str(ref_density),
        "candidate_density_decision": status(density),
        "candidate_density": str(density),
        "matched_lines": len(expected & actual),
        "missing_lines": compact(missing),
        "extra_lines": compact(extra),
        "missing_files": sorted(missing_files),
        "extra_files": sorted(measured - indexed),
        "regressions": regressions,
    }


def verify_gate(report, code, result):
    gate = report["assessment"]["gate"]
    label, expected_code = (
        ("pass", 0) if result["candidate_density_decision"] == "OK" else ("fail", 1)
    )
    require(
        code == expected_code
        and gate["status"] == label
        and len(gate["conditions"]) == 1,
        "CLI exit/status differs from the measured gate",
    )
    cond = gate["conditions"][0]
    require(
        all(cond.get(k) == v for k, v in POLICY["conditions"][0].items())
        and cond["status"] == label
        and decimal(cond["actual"]) == decimal(result["candidate_density"]),
        "CLI did not evaluate the assigned condition",
    )


def replay(case, binary, mirror=None, enforce=False):
    with tempfile.TemporaryDirectory(prefix="go-tree-") as tmp:
        scratch = Path(tmp)
        source, limits = stage(case, scratch, mirror)
        empty = scratch / "empty"
        empty.mkdir()
        args = [binary, "analyze", ".", "--profile", "sonar-parity", "--format", "json"]
        if enforce:
            policy = scratch / "gate.json"
            policy.write_text(json.dumps(POLICY))
            args.extend(["--quality-gate", policy])
        proc = subprocess.run(
            args,
            cwd=source,
            capture_output=True,
            timeout=240,
            env={
                "PATH": str(empty),
                "HOME": str(empty),
                "TMPDIR": str(scratch),
                "LC_ALL": "C",
            },
        )
        require(
            proc.returncode in ((0, 1, 2) if enforce else (0,)),
            f"unexpected scan exit: {proc.returncode}",
        )
        report = json.loads(proc.stdout, parse_float=Decimal)
        parity = report["parity"]
        require(
            parity["reference"]["profile"] == "sonar-parity"
            and parity["scope"]["roots"] == ["."]
            and not any(
                parity["scope"][key]
                for key in (
                    "exclude",
                    "test_include",
                    "vendor_include",
                    "generated_include",
                    "duplication_exclude",
                )
            ),
            "incorrect native profile or exclusions",
        )
        project = report["project"]
        if project["complete"] is not True or not isinstance(
            project.get("duplication"), dict
        ):
            gate = report.get("assessment", {}).get("gate") or {}
            return {
                "repository": case["repository"],
                "commit": case["commit"],
                "tree": case["tree"],
                "analysis": case["community"]["analysis"],
                "community_density": case["community"]["density"],
                "community_status": case["community"]["status"],
                "candidate_density": None,
                "candidate_density_decision": None,
                "cli_exit": proc.returncode,
                "cli_gate_status": gate.get("status") if enforce else None,
                "comparison": "cli_gate" if enforce else "density_threshold_only",
                "tracked": len(limits),
                "diagnostics": project["warnings"],
                "regressions": ["complete-project duplication measure unavailable"],
            }
        result = compare(case, project, limits)
        result["comparison"] = "cli_gate" if enforce else "density_threshold_only"
        if enforce:
            result["cli_exit"] = proc.returncode
            result["cli_gate_status"] = (
                report.get("assessment", {}).get("gate") or {}
            ).get("status")
            try:
                verify_gate(report, proc.returncode, result)
            except (ValueError, KeyError, TypeError) as error:
                result["regressions"].append(
                    f"CLI gate {result['cli_gate_status']!r} (exit {proc.returncode}): {error}"
                )
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--mirrors", type=Path)
    parser.add_argument("--project")
    parser.add_argument("--enforce-gate", action="store_true")
    parser.add_argument(
        "--output",
        type=Path,
        help="save all actual residual line sets and errors as JSON",
    )
    args = parser.parse_args()
    ref = json.loads(MANIFEST.read_bytes())
    cases = ref["projects"]
    require(
        ref["format"] == 1
        and ref["community_version"] == "26.11.0.134175"
        and ref["policy"] == POLICY
        and len(cases) == 32
        and all(
            len({c[key] for c in cases}) == len(cases)
            for key in ("repository", "github_id")
        ),
        "incorrect frozen Community cohort",
    )
    binary = args.binary.resolve(strict=True)
    selected = [c for c in cases if not args.project or c["repository"] == args.project]
    require(selected, "unknown project")
    rows = []
    for case in selected:
        slug = case["repository"]
        try:
            mirror = (
                args.mirrors / slug.replace("/", "--") / "objects"
                if args.mirrors is not None
                else None
            )
            row = replay(case, binary, mirror, args.enforce_gate)
        except (
            OSError,
            ValueError,
            ArithmeticError,
            KeyError,
            TypeError,
            subprocess.SubprocessError,
        ) as error:
            row = {"repository": slug, "regressions": [str(error)]}
        rows.append(row)
        print(json.dumps(row, sort_keys=True), flush=True)
    if args.output:
        args.output.write_text(json.dumps(rows, indent=2) + "\n")
    failures = sum(bool(r["regressions"]) for r in rows)
    print(
        f"{len(rows) - failures}/{len(rows)} projects passed the frozen Community decision, density and line-map checks."
    )
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
