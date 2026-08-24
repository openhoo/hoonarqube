#!/usr/bin/env python3
"""Normalize hoonarqube JSON report into {rule: set(lines)} per file."""
import json, sys
report = json.load(open(sys.argv[1]))
out = {}
for f in report.get("files", []):
    path = f["path"]
    out.setdefault(path, {}).setdefault("issues", []).extend(
        {"rule": i["rule_key"], "line": i["range"]["start"]["line"]} for i in f["issues"])
json.dump(out, open(sys.argv[2], "w"), indent=1)
