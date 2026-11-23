"""Compare the shipped catalog with the frozen default profiles, without running analyzers."""

import argparse
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
REFERENCE = HERE / "fixtures" / "community-default-inventory-26.11.json.gz"


def load_reference():
    raw = REFERENCE.read_bytes()
    if (
        hashlib.sha256(raw).hexdigest()
        != "7470099e62f93d1dd26d4b8f3f2282fbf4c12246c4099d293678a0345c1e168e"
    ):
        raise ValueError("Community default profile capture has changed")
    return json.loads(gzip.decompress(raw))


def catalog_keys(directory):
    result = {}
    for path in sorted(directory.glob("*.json")):
        catalog = json.loads(path.read_bytes())
        lang = catalog["language"]
        keys = {row["external_key"] for row in catalog["rules"]}
        if lang in result or len(keys) != len(catalog["rules"]):
            raise ValueError(f"duplicate language or rule in {path.name}")
        if any(row["language"] != lang for row in catalog["rules"]):
            raise ValueError(f"wrong rule language in {path.name}")
        result[lang] = keys
    return result


def compare(profiles, catalogs):
    rows = {}
    for lang, profile in sorted(profiles.items()):
        active = set(profile["rules"])
        recorded = set(profile["catalog_keys_at_capture"])
        if not recorded <= active or len(active) != profile["active_rule_count"]:
            raise ValueError(f"{lang}: inconsistent capture")
        matching = active & catalogs.get(lang, set())
        if lost := sorted(recorded - matching):
            raise ValueError(
                f"{lang}: catalog lost active reference keys: {', '.join(lost)}"
            )
        rows[lang] = {
            "name": profile["language_name"],
            "default": profile["name"],
            "active": len(active),
            "has_catalog": lang in catalogs,
            "matching_keys": len(matching),
            "absent_keys": sorted(active - matching),
            "added_since_capture": sorted(matching - recorded),
        }
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--catalog", type=Path, default=HERE.parents[1] / "catalog/rules"
    )
    args = parser.parse_args()
    reference = load_reference()
    result = compare(reference["profiles"], catalog_keys(args.catalog))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
