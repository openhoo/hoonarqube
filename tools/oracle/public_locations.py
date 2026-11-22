"""Reject new differences from Community at pinned source locations in 24 public projects."""

import argparse
import gzip
import json
from collections import Counter
from pathlib import Path

from public_contract import observe, require, scan, validate_scope

FIXTURE = Path(__file__).with_name("fixtures") / "public-locations-24.json.gz"


def difference(found, reference, allowed_missing, allowed_extra):
    missing, extra = reference - found, found - reference
    new_missing, new_extra = missing - allowed_missing, extra - allowed_extra
    require(
        not new_missing and not new_extra,
        f"new differences: missing={dict(new_missing)}, extra={dict(new_extra)}",
    )
    return {
        "matched": (found & reference).total(),
        "native_only": extra.total(),
        "reference_only": missing.total(),
    }


def evaluate(case, report, source):
    found = observe(case, report, source)
    return difference(
        found, *(Counter(map(tuple, case[k])) for k in ("sonar", "missing", "extra"))
    )


def validate(data):
    cases = data["projects"]
    require(data["format"] == 1 and data["sonar"] == "26.9.0.129388", "wrong reference")
    require(
        len(cases) == 24 and sum(len(c["files"]) for c in cases) == 196,
        "incomplete cohort",
    )
    require(
        len({c["repository_id"] for c in cases})
        == len({c["repository"].casefold() for c in cases})
        == 24,
        "duplicate repository",
    )
    require(
        len(
            {
                v
                for c in cases
                for v in (c["evidence"]["analysis"], c["evidence"]["task"])
            }
        )
        == 48,
        "duplicate analysis or task",
    )
    require(
        Counter(c["language"] for c in cases)
        == dict.fromkeys(("go", "py", "rust", "ruby", "js", "ts"), 4),
        "incomplete language cohort",
    )
    for case in cases:
        validate_case(case)


def validate_case(case):
    validate_scope(case)
    require(
        case["parameters"]
        and Counter(case["sources"]) == Counter(case["files"].keys()),
        "wrong source scope",
    )
    sonar, missing = (Counter(map(tuple, case[k])) for k in ("sonar", "missing"))
    require(missing <= sonar, "missing allowance outside reference")
    for rule, path, sl, sc, el, ec in (*case["sonar"], *case["extra"]):
        require(
            rule in case["parameters"]
            and path in case["files"]
            and all(type(n) is int for n in (sl, sc, el, ec))
            and min(sl, el) >= 1
            and min(sc, ec) >= 0
            and (sl, sc) <= (el, ec),
            "invalid primary location",
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--local-sources",
        type=Path,
        help="Map GitHub slugs to pinned local Git checkouts.",
    )
    parser.add_argument(
        "--output", type=Path, help="Save observed counts per repository."
    )
    args = parser.parse_args()
    data = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    validate(data)
    sources = json.loads(args.local_sources.read_bytes()) if args.local_sources else {}
    rows = {}
    for case in data["projects"]:
        name = case["repository"]
        local = sources[name] if args.local_sources else None
        try:
            rows[name] = scan(case, args.binary.resolve(strict=True), local, evaluate)
        except ValueError as error:
            raise SystemExit(f"{name}: {error}") from error
        print(f"{name}: {rows[name]}", flush=True)
    total = Counter()
    for row in rows.values():
        total.update(row)
    print(f"{len(rows)} repositories: {dict(total)}")
    if args.output:
        args.output.write_text(json.dumps(rows, indent=2) + "\n")


if __name__ == "__main__":
    main()
