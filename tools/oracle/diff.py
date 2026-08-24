#!/usr/bin/env python3
"""Three-way parity diff: expected.jsonl vs SQ findings vs hoonarqube findings."""
import json, sys, subprocess
from pathlib import Path

def load_jsonl(p):
    return [json.loads(l) for l in open(p) if l.strip()]

def sq_on(sq_issues, bad_file):
    return sorted(i["line"] for i in sq_issues if i["file"] == bad_file and i.get("line"))

def ours_on(ours, bad_file, key):
    rep = ours.get("files", [])
    for f in rep:
        if f["path"].endswith(bad_file) or f["path"].endswith("/" + bad_file):
            return sorted(i["range"]["start"]["line"] for i in f["issues"] if i["rule_key"] == key)
    return []

def main(lang, proj_dir, sq_json, ours_json, out_path=None):
    exp = load_jsonl(Path(proj_dir) / "expected.jsonl")
    sq = json.load(open(sq_json))
    ours = json.load(open(ours_json))
    rows = []
    for e in exp:
        if e.get("skip"):
            rows.append({"key": e["key"], "status": "SKIPPED", "why": e["skip"]})
            continue
        bad = e["bad"]
        key = e["key"]
        sq_lines = sq_on(sq, bad)
        our_lines = ours_on(ours, bad, key)
        min_exp = e.get("expect_lines_min", 1)
        sq_ok = len(set(sq_lines)) >= min_exp
        our_ok = len(set(our_lines)) >= min_exp
        good = Path(proj_dir) / ("_good".join([bad.rsplit("_bad", 1)[0], "_good"]) if "_bad" in bad else bad.replace("_bad", "_good"))
        # good control: SQ must NOT flag key on good file
        good_name = bad.replace("_bad", "_good")
        sq_good = [i for i in sq if i["file"] == good_name and i["rule"] == key]
        our_good = []
        for f in ours.get("files", []):
            if f["path"].endswith(good_name):
                our_good = [i for i in f["issues"] if i["rule_key"] == key]
        status = "PASS" if (sq_ok and our_ok and not sq_good and not our_good) else (
                 "SQ-MISS" if not sq_ok else ("OURS-MISS" if not our_ok else
                 "GOOD-FIRE" if (sq_good or our_good) else "MISMATCH"))
        rows.append({"key": key, "status": status, "sq": sq_lines, "ours": our_lines,
                     "sq_good_fire": bool(sq_good), "our_good_fire": bool(our_good)})
    json.dump(rows, open(out_path or "/dev/stdout", "w"), indent=1)
    from collections import Counter
    c = Counter(r["status"] for r in rows)
    print(dict(c))

if __name__ == "__main__":
    main(*sys.argv[1:])
