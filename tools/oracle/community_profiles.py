"""Check three Community 26.11 quality profiles with one native scan per public project."""

import argparse
import gzip
import json
from collections import Counter
from functools import partial
from pathlib import Path

from public_contract import require, scan
from public_locations import evaluate, validate_case

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixtures/community-profiles-26.11.json.gz"
VERSION = "26.11.0.134175"
TIERS = ("core", "extended", "comprehensive")
RULE_NAMESPACES = {"go": "go", "py": "python", "js": "javascript", "ts": "typescript"}
LANGUAGES = set(RULE_NAMESPACES)


def load_resolutions():
    resolved = {}
    for path in sorted(FIXTURE.parent.glob("community-profiles-26.11-resolved-*.json")):
        row = json.loads(path.read_bytes())
        direction = row["allowance"]
        require(direction in ("missing", "extra"), "invalid allowance direction")
        locations = Counter(map(tuple, row["locations"]))
        require(locations, "empty resolved allowance")
        for tier in row["tiers"]:
            key = (row["repository"], tier, direction)
            saved = resolved.setdefault(key, Counter())
            require(not (locations & saved), "duplicate resolved location")
            saved.update(locations)
    return resolved


def tightened(case, tier, resolved):
    for direction in ("missing", "extra"):
        removed = resolved.get((case["repository"], tier, direction))
        if removed:
            allowances = Counter(map(tuple, case[direction]))
            require(
                removed <= allowances, "resolved location outside archived allowance"
            )
            case[direction] = list((allowances - removed).elements())
    return case


def check_bundle(bundle, resolved=None):
    if resolved is None:
        resolved = load_resolutions()
    require(
        bundle["format"] == 1 and bundle["sonar"] == VERSION, "wrong profile fixture"
    )
    require(set(bundle["profiles"]) == set(TIERS), "missing profile")
    absent = bundle["without_reference_language"]
    require(
        len(absent) == 8
        and sum(x["files"] for x in absent) == 92
        and Counter(x["language"] for x in absent) == {"ruby": 4, "rust": 4},
        "incorrect unavailable scope",
    )
    scopes = bundle["projects"]
    require(
        len(scopes) == 16 and sum(len(c["files"]) for c in scopes) == 104,
        "wrong source cohort",
    )
    require(
        Counter(c["language"] for c in scopes) == dict.fromkeys(LANGUAGES, 4),
        "wrong languages",
    )
    require(
        len({c["repository_id"] for c in scopes})
        == len({c["repository"].lower() for c in scopes})
        == len(scopes),
        "repeated repository",
    )
    require(
        len({s["repository_id"] for s in (*scopes, *absent)}) == 24,
        "repeated source across cohorts",
    )
    require(
        set(resolved)
        <= {
            (case["repository"], tier, direction)
            for case in scopes
            for tier in TIERS
            for direction in ("missing", "extra")
        },
        "resolved location names an unmeasured project or profile",
    )
    identities = [x[k] for x in absent for k in ("analysis", "task")]
    hashes = []
    for tier in TIERS:
        profile = bundle["profiles"][tier]
        require(set(profile["languages"]) == LANGUAGES, "missing language profile")
        require(
            all(
                m["name"] == "Sonar way " + tier
                and m["builtin"]
                and m["active_keys"] > 0
                for m in profile["languages"].values()
            ),
            "incorrect named profile",
        )
        hashes.append(profile["configuration_sha256"])
        for c in scopes:
            require(set(c["observations"]) == set(TIERS), "partial project")
            observation = c["observations"][tier]
            require(
                observation["configuration_sha256"] == profile["configuration_sha256"],
                "project references a different profile",
            )
            case = {**c, **observation}
            namespace = RULE_NAMESPACES[c["language"]] + ":"
            require(
                all(key.startswith(namespace) for key in observation["parameters"]),
                "rule is outside the indexed language",
            )
            validate_case(case)
            tightened(case, tier, resolved)
            identities.extend(case["evidence"][k] for k in ("analysis", "task"))
    require(
        len(set(hashes)) == len(TIERS) and all(len(h) == 64 for h in hashes),
        "profile fingerprints must differ",
    )
    require(
        len(set(identities)) == 112 and all(identities),
        "missing or reused reference analysis",
    )


def evaluate_profiles(case, report, source, *, resolved):
    def check(tier):
        try:
            observation = tightened(
                {**case, **case["observations"][tier]}, tier, resolved
            )
            return evaluate(observation, report, source)
        except ValueError as error:
            raise ValueError(f"{tier}: {error}") from error

    return {tier: check(tier) for tier in TIERS}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--local-sources", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    data = json.loads(gzip.decompress(FIXTURE.read_bytes()))
    resolved = load_resolutions()
    check_bundle(data, resolved)
    roots = json.loads(args.local_sources.read_bytes()) if args.local_sources else {}
    results = {}
    for case in data["projects"]:
        name = case["repository"]
        try:
            results[name] = scan(
                case,
                args.binary.resolve(strict=True),
                roots[name] if args.local_sources else None,
                partial(evaluate_profiles, resolved=resolved),
            )
        except ValueError as error:
            raise SystemExit(f"{name}: {error}") from error
    totals = {
        tier: dict(sum((Counter(v[tier]) for v in results.values()), Counter()))
        for tier in TIERS
    }
    print(json.dumps(totals, indent=2))
    if args.output:
        args.output.write_text(
            json.dumps({"totals": totals, "projects": results}, indent=2) + "\n"
        )


if __name__ == "__main__":
    main()
