"""Rebuild the 26.9 Sonar way type map from the two independent complete rule exports."""

import argparse
import hashlib
import json
from pathlib import Path
import tomllib

from parity import validate_search_page

ROOT = Path(__file__).resolve().parents[2]
VERSION = "26.9.0.129388"
IMAGE = (
    "sonarqube@sha256:c0f1160bccfa435db4168c2d7df69af3c3ea7bfeb87395613014048fb33a68c1"
)
PROFILE = "Sonar way"
LANGS = {
    "csharp": "cs",
    "go": "go",
    "java": "java",
    "javascript": "js",
    "python": "py",
    "ruby": "ruby",
    "rust": "rust",
    "typescript": "ts",
}
TYPES = {"CODE_SMELL", "BUG", "VULNERABILITY", "SECURITY_HOTSPOT"}
TABLE = "community-26.9-sonar-way-types.tsv"
RECEIPT = "community-26.9-sonar-way-inputs.json"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_export(load, folder, prefix, lang, profile):
    source = {}
    seen = set()
    total = size = None
    page = 0
    while True:
        page += 1
        filename = f"{prefix}-{lang}-page-{page}.json"
        data = load(folder / filename, f"{prefix}/{filename}")
        items, total, size, done = validate_search_page(
            data,
            "rules",
            page,
            expected_total=total,
            expected_page_size=size,
            seen_keys=seen,
        )
        require(
            (data["p"], data["ps"], data["total"]) == (page, size, total),
            f"{filename}: inconsistent paging",
        )
        if prefix == "effective":
            require(
                set(data["actives"]) == {r["key"] for r in items},
                "missing activation",
            )
        for rule in items:
            key, typ = rule["key"], rule["type"]
            require(typ in TYPES, f"unknown rule type: {key}")
            if prefix == "active":
                require(rule["lang"] == lang, f"{key}: wrong language")
            else:
                binds = data["actives"][key]
                require(
                    len(binds) == 1 and binds[0]["qProfile"] == profile["key"],
                    f"{key}: wrong activation profile",
                )
            source[key] = typ
        if done:
            break
    require(
        len(list(folder.glob(f"{prefix}-{lang}-page-*.json"))) == page,
        f"{lang}: unexpected page",
    )
    require(total == profile["activeRuleCount"], f"{lang}: wrong active count")
    return source


def audit(capture, effective, environment, catalog, output):
    inputs = {}

    def load(path, label):
        raw = path.read_bytes()
        inputs[label] = digest(raw)
        return json.loads(raw)

    env = load(environment, "reference-environment.json")
    require(
        env["server"]["version"] == VERSION
        and env["server"]["status"] == "UP"
        and env["server_image"]["image"] == IMAGE,
        "wrong reference environment",
    )
    profiles = load(capture / "profiles.json", "metadata/profiles.json")["profiles"]
    result = {}
    rows = []
    for name, lang in LANGS.items():
        matches = [p for p in profiles if p["language"] == lang]
        require(len(matches) == 1, f"{lang}: ambiguous selected profile")
        profile = matches[0]
        require(
            profile["name"] == PROFILE
            and profile["isBuiltIn"] is True
            and profile["isDefault"] is True,
            f"{lang}: unqualified profile",
        )
        exports = []
        for folder, prefix in ((capture, "active"), (effective, "effective")):
            exports.append(read_export(load, folder, prefix, lang, profile))
        active, bound = exports
        require(active == bound, f"{lang}: different active exports")
        native = load(catalog / "rules" / f"{name}.json", f"catalog/rules/{name}.json")
        nr = {r["external_key"]: r["rule_type"] for r in native["rules"]}
        require(
            native["language"] == lang and len(nr) == len(native["rules"]),
            "invalid native catalog",
        )
        differences = {
            k: active[k]
            for k in sorted(nr.keys() & active.keys())
            if nr[k] == "SECURITY_HOTSPOT" and nr[k] != active[k]
        }
        result[name] = {
            "language": lang,
            "profile_key": profile["key"],
            "active": len(active),
            "active_hotspots": sum(t == "SECURITY_HOTSPOT" for t in active.values()),
            "native_hotspot_reclassifications": differences,
            "native_keys_outside_active_profile": len(nr.keys() - active.keys()),
            "active_reference_keys_outside_native_catalog": len(
                active.keys() - nr.keys()
            ),
        }
        rows.extend(
            f"{name}\t{key}\t{active.get(key, 'NOT_ACTIVE')}"
            for key in sorted(active.keys() | nr.keys())
        )
    snapshot = (catalog / "snapshot.toml").read_bytes()
    inputs["catalog/snapshot.toml"] = digest(snapshot)
    catalog_id = tomllib.loads(snapshot.decode())["catalog_sha256"]
    table = "\n".join([f"{VERSION}\t{PROFILE}\t{catalog_id}", *rows, ""]).encode()
    output.mkdir(parents=True, exist_ok=True)
    (output / TABLE).write_bytes(table)
    receipt = {
        "version": VERSION,
        "profile": PROFILE,
        "server_image": IMAGE,
        "native_catalog_sha256": catalog_id,
        "table_sha256": digest(table),
        "profiles": result,
        "inputs_sha256": inputs,
    }
    (output / RECEIPT).write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("capture", "effective", "environment"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--catalog", type=Path, default=ROOT / "catalog")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    audit(**vars(args))


if __name__ == "__main__":
    main()
