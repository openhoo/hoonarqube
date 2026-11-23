"""Compare S1192 primary and supporting locations on public Go source packages."""

import argparse
from collections import Counter
import json
from pathlib import Path
import tempfile

from community_go_packages import measure, stage_sources
from community_scm_period import check
from public_corpus_summary import utf16_coordinates

FIXTURE = (
    Path(__file__).parent / "fixtures/community-go-packages/duplicate-logging.json"
)


def location(path, row, lines):
    return (path, *utf16_coordinates(row, lines))


def freeze(obj):
    return (
        tuple(obj["primary"]),
        obj["message"],
        tuple(tuple(tuple(loc) for loc in batch) for batch in obj["flows"]),
    )


def native_objects(report, root):
    found = Counter()
    for file in report["files"]:
        name = file["path"]
        lines = (root / name).read_bytes().decode("utf-8").splitlines()
        for issue in file["issues"]:
            if issue["rule_key"] != "go:S1192":
                continue
            flows = []
            for flow in issue.get("flows", []):
                locations = []
                for loc in flow["locations"]:
                    check(
                        loc.get("path") in (None, name),
                        "unexpected cross-file S1192 location",
                    )
                    locations.append((*location(name, loc, lines), loc["message"]))
                flows.append(tuple(locations))
            found[(location(name, issue, lines), issue["message"], tuple(flows))] += 1
    return found


def check_case(case, cli, mirrors, work, known):
    root = stage_sources(case, mirrors, work)
    code, report = measure(cli, root, case["files"])
    check(code == 0, "unavailable analysis")
    expected = Counter(map(freeze, case["issues"]))
    actual = native_objects(report, root)
    extra, missing = actual - expected, expected - actual
    allowed = Counter(
        (row[0], row[1]) for row in map(freeze, case["issues"]) if list(row[0]) in known
    )
    missing_primary = Counter((p, msg) for p, msg, _ in missing.elements())
    check(
        not extra and not (missing_primary - allowed),
        f"{case['repository']}: unexpected {list(extra.elements())}; missing {list(missing.elements())}",
    )
    print(
        f"{case['repository']}: {len(case['files'])} files, {(actual & expected).total()} exact S1192 objects, "
        f"{missing.total()} known omissions"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cli", type=Path)
    parser.add_argument(
        "--mirrors", type=Path, help="optional OWNER--REPO/objects directories"
    )
    args = parser.parse_args()
    data = json.loads(FIXTURE.read_bytes())
    check(
        data["server"] == "26.11.0.134175" and data["threshold"] == 3, "reference drift"
    )
    for case in data["cases"]:
        with tempfile.TemporaryDirectory() as tmp:
            check_case(
                case,
                args.cli.resolve(),
                args.mirrors,
                Path(tmp),
                data["known_missing_primaries"].get(case["repository"], []),
            )


if __name__ == "__main__":
    main()
