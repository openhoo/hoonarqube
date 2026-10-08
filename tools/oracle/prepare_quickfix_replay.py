#!/usr/bin/env python3
"""Extract hash-verified frozen replay inputs and record explicit config migration."""

import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path


def digest(value):
    return hashlib.sha256(value).hexdigest()


def prepare(archive, destination, migrate_ts6=False):
    destination = destination.resolve()
    with gzip.open(archive, "rt") as stream:
        source = json.load(stream)
    receipts = []
    for name, item in source["embedded_replay_files"].items():
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("unsafe embedded replay path")
        path = destination / relative
        if not path.resolve().is_relative_to(destination):
            raise ValueError("embedded replay path escapes destination")
        value = base64.b64decode(item["content"], validate=True)
        if len(value) != item["bytes"] or digest(value) != item["sha256"]:
            raise ValueError("embedded replay content hash/size mismatch")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        receipts.append({"path": name, "bytes": len(value), "sha256": digest(value)})
    migrations = []
    if migrate_ts6:
        path = destination / "quickfix-smoke/run_quickfix_smoke.py"
        value = path.read_text()
        original = '        if isinstance(compiler_options, dict):\n            config["compilerOptions"] = compiler_options\n'
        replacement = (
            "        if isinstance(compiler_options, dict):\n"
            "            compiler_options = dict(compiler_options)\n"
            '            config["compilerOptions"] = compiler_options\n'
            '        config.setdefault("compilerOptions", {})["ignoreDeprecations"] = "6.0"\n'
        )
        if value.count(original) != 1:
            raise ValueError("frozen harness config migration anchor changed")
        path.write_text(value.replace(original, replacement))
        migrations.append(
            {
                "path": str(path.relative_to(destination)),
                "original_sha256": digest(value.encode()),
                "migrated_sha256": digest(path.read_bytes()),
                "change": "Pinned TypeScript 6 configs inheriting baseUrl explicitly "
                "acknowledge deprecation via ignoreDeprecations=6.0; "
                "native diagnostics and gates remain required.",
            }
        )
    receipt = {
        "schema_version": 1,
        "kind": "verified_frozen_quickfix_replay_preparation",
        "archive": str(archive),
        "archive_sha256": digest(archive.read_bytes()),
        "verified_original_files": receipts,
        "explicit_migrations": migrations,
    }
    (destination / "preparation.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--archive",
        type=Path,
        default=Path(__file__).parent / "quickfix-qualification-20260910.json.gz",
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--typescript-6-config", action="store_true")
    args = parser.parse_args()
    result = prepare(args.archive, args.output, args.typescript_6_config)
    print(
        {
            "verified_files": len(result["verified_original_files"]),
            "explicit_migrations": len(result["explicit_migrations"]),
        }
    )


if __name__ == "__main__":
    main()
