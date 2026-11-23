"""Rebuild the bounded Go gate manifest from archived Community 26.11 responses."""

import argparse
import hashlib
import json
from pathlib import Path


def read(path):
    return json.loads(path.read_bytes())


def require(ok, message):
    if not ok:
        raise ValueError(message)


def profile(root, tier, size):
    before = root / "profiles"
    after = root / "profiles-end"
    raw = (before / "effective-go-page-1.json").read_bytes()
    page = json.loads(raw)
    require(
        (after / "effective-go-page-1.json").read_bytes() == raw,
        "effective profile changed",
    )
    assignment = read(root / "reference/tidwall-match/profiles.json")["profiles"]
    (p,) = (row for row in assignment if row["language"] == "go")
    require(
        p["isBuiltIn"]
        and p["name"] == "Sonar way " + tier
        and p["activeRuleCount"] == size,
        "wrong assigned Go profile",
    )
    detail = read(root / "reference/tidwall-match/active-go-page-1.json")
    require(
        page["total"]
        == detail["total"]
        == size
        == len(page["rules"])
        == len(detail["rules"]),
        "incomplete or unexpected active rule page",
    )
    settings = {}
    for key, activations in page["actives"].items():
        (active,) = (a for a in activations if a["qProfile"] == p["key"])
        params = {x["key"]: x["value"] for x in active["params"]}
        require(len(params) == len(active["params"]), "duplicate parameter")
        settings[key] = params
    rows = {
        r["key"]: {
            "type": r["type"],
            "scope": r["scope"],
            "parameters": settings[r["key"]],
        }
        for r in detail["rules"]
    }
    require(
        len(rows) == size
        and set(settings) == set(rows) == {r["key"] for r in page["rules"]},
        "rule membership differs",
    )
    require(
        rows
        == read(before / "effective.json")["profiles"]["go"]["rules"]
        == read(after / "effective.json")["profiles"]["go"]["rules"],
        "effective rule details differ",
    )
    receipt = read(root / "cohort-receipt.json")
    require(
        receipt["reference"]["server"]["version"] == "26.11.0.134175"
        and receipt["reference_profiles_verified"],
        "wrong server or unverified profile",
    )
    return {
        "name": p["name"],
        "active_count": size,
        "go_rules_page_sha256": hashlib.sha256(raw).hexdigest(),
        "configuration_sha256": receipt["reference_profiles_sha256"],
        "rules": dict(sorted(rows.items())),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    profiles = {
        name: profile(args.capture / folder, name, size)
        for name, folder, size in (
            ("core", ".", 6),
            ("extended", "assigned-extended", 9),
            ("comprehensive", "assigned-comprehensive", 23),
        )
    }
    print(json.dumps({"server": "26.11.0.134175", "profiles": profiles}, indent=2))


if __name__ == "__main__":
    main()
