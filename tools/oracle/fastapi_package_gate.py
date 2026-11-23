"""Check every new and duplicated line in the shipped FastAPI Python package."""

import argparse
import gzip
import hashlib
import json
import math
import tempfile
from collections import defaultdict
from pathlib import Path

from community_new_duplication import CONFIG, check, git
from community_scm_period import descriptor, run_case
from fastapi_default_gate import replay_default

CAPTURE = Path(__file__).with_name("fixtures") / "fastapi-package-scm-20261122.json.gz"
UPSTREAM = "https://github.com/fastapi/fastapi.git"


def checkout(work, repository, revision):
    root = work / "repository"
    if repository is None:
        git(work, "init", "--quiet", str(root))
        git(root, "fetch", "--quiet", "--no-tags", UPSTREAM, revision)
    else:
        git(
            work,
            "clone",
            "--quiet",
            "--no-tags",
            "--no-checkout",
            "--shared",
            "--",
            str(repository.resolve(strict=True)),
            str(root),
        )
    check(
        git(root, "rev-parse", "--is-shallow-repository").strip() == b"false",
        "full history required",
    )
    git(root, "sparse-checkout", "set", "fastapi")
    return root


def verify_pin(root, stage, capture):
    pin = capture["pins"][stage]
    git(root, "checkout", "--quiet", "--detach", pin["revision"])
    check(
        git(root, "rev-parse", "HEAD", "HEAD^{tree}").decode().splitlines()
        == [pin["revision"], pin["root_tree"]],
        "unexpected Git revision or tree",
    )
    actual = {
        p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (root / "fastapi").rglob("*.py")
        if not p.is_symlink()
    }
    expected = {k: v[stage + "_sha256"] for k, v in capture["files"].items()}
    check(len(actual) == 48 and actual == expected, "wrong FastAPI package inventory")


def check_locations(report, capture):
    locations = capture["source_locations"]
    for rows in (report["files"], report["project"]["files"]):
        check(
            len(rows) == len(locations) and {f["path"] for f in rows} == set(locations),
            "scanner inventory differs",
        )
    check(
        all(
            f["classification"] == "source" and f["status"] == "complete"
            for f in report["project"]["files"]
        ),
        "incomplete source files",
    )
    new = {
        s["path"]: set(s["lines"]) for s in report["assessment"]["new_code"]["lines"]
    }
    dup = defaultdict(set)
    for group in report["project"]["duplications"]:
        for item in group["occurrences"]:
            dup[item["path"]].update(range(item["start_line"], item["end_line"] + 1))
    check(set(new) | set(dup) <= set(locations), "unexpected source location")
    for path, ref in locations.items():
        check(new.get(path, set()) == set(ref["new"]), f"new lines differ: {path}")
        check(dup[path] == set(ref["duplicated"]), f"duplicated lines differ: {path}")
    return sum(map(len, new.values())), sum(
        len(lines & dup[path]) for path, lines in new.items()
    )


def replay(binary, repository, work, *, current_default=False):
    cap = json.loads(gzip.decompress(CAPTURE.read_bytes()))
    root = checkout(work, repository, cap["pins"]["candidate"]["revision"])
    for stage in ("base", "candidate"):
        verify_pin(root, stage, cap)
    base, head = (cap["pins"][s]["revision"] for s in ("base", "candidate"))
    selected = descriptor(
        cap["reference_gate"]["period"], cap["analyses"]["base"], base
    )
    code, report, _ = run_case(
        binary, root, work, sorted(cap["files"]), base, head, selected, [CONFIG]
    )
    new, duplicated = check_locations(report, cap)
    measures = {x["metric"]: float(x["period"]["value"]) for x in cap["measures"]}
    expected = cap["reference_gate"]
    (c,) = expected["conditions"]
    check(
        cap["version"] == "26.9.0.129388"
        and cap["repository"] == "fastapi/fastapi"
        and expected["status"] == c["status"] == "ERROR"
        and not expected["ignoredConditions"]
        and (c["metricKey"], c["comparator"], float(c["errorThreshold"]))
        == ("new_duplicated_lines_density", "GT", 3),
        "different reference policy",
    )
    check(
        (new, duplicated)
        == (measures["new_lines"], measures["new_duplicated_lines"])
        == (41, 2),
        "project totals differ",
    )
    native = report["assessment"]["gate"]
    (cond,) = native["conditions"]
    check(
        code == 1
        and native["status"] == cond["status"] == "fail"
        and not cond.get("ignored_on_small_change")
        and all(cond[k] == v for k, v in CONFIG.items())
        and math.isclose(cond["actual"], float(c["actualValue"]), abs_tol=0.000005),
        "blocking gate differs",
    )
    result = {
        "files": len(cap["files"]),
        "all_duplicated_lines": sum(
            len(v["duplicated"]) for v in cap["source_locations"].values()
        ),
        "new_lines": new,
        "duplicated_new_lines": duplicated,
        "native_status": native["status"],
        "reference_analysis": cap["analyses"]["candidate"],
    }
    if current_default:
        result["community_26_11_default"] = replay_default(binary, root, work, cap)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--current-default",
        action="store_true",
        help="Also check each Community 26.11 default condition.",
    )
    parser.add_argument(
        "--repository", type=Path, help="Optional local full FastAPI Git mirror"
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as folder:
        print(
            json.dumps(
                replay(
                    args.binary.resolve(),
                    args.repository,
                    Path(folder).resolve(),
                    current_default=args.current_default,
                ),
                indent=2,
            )
        )


if __name__ == "__main__":
    main()
