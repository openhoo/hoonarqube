#!/usr/bin/env python3
"""Fetch all issues for one SQ project via pagination."""
import json, sys, urllib.request, urllib.parse, base64

BASE = "http://127.0.0.1:9000"
AUTH = base64.b64encode(b"admin:Orac1e!2026").decode()

def fetch(component):
    issues, page = [], 1
    while True:
        q = urllib.parse.urlencode({"componentKeys": component, "resolved": "false",
                                    "ps": 500, "p": page, "s": "FILE_LINE", "asc": "true"})
        req = urllib.request.Request(f"{BASE}/api/issues/search?{q}")
        req.add_header("Authorization", f"Basic {AUTH}")
        d = json.load(urllib.request.urlopen(req))
        for i in d["issues"]:
            issues.append({
                "rule": i["rule"],
                "line": i.get("line"),
                "message": i.get("message", ""),
                "file": i["component"].split("/")[-1],
            })
        total, ps = d["paging"]["total"], d["paging"]["pageSize"]
        if page * ps >= total or not d["issues"]:
            break
        page += 1
    return issues

if __name__ == "__main__":
    json.dump(fetch(sys.argv[1]), open(sys.argv[2], "w"), indent=1)
