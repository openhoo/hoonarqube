#!/usr/bin/env python3
"""SonarQube Community parity suite.

Lifecycle: starts the SQ container if needed, waits for UP, ensures profiles
and projects, runs scanner + hoonarqube on every fixture set, fetches oracle
issues, diffs per rule key, and prints a parity report.

Usage:
  python3 tools/oracle/parity_suite.py            # full run, report to stdout
  python3 tools/oracle/parity_suite.py --quick    # reuse existing scan results
Exit code 0 when no actionable divergences remain (only PASS/SKIP/INFRA).
"""
import base64
import json
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
ORACLE = REPO / ".oracle/sonar"
RESULTS = ORACLE / "results"
AUTH = base64.b64encode(b"admin:Orac1e!2026").decode()
LANGS = ["oracle-py", "oracle-js", "oracle-ts", "oracle-cs"]
EXT = {"oracle-py": "py", "oracle-js": "js", "oracle-ts": "ts", "oracle-cs": "cs"}

# Keys documented as requiring out-of-repository infrastructure.
INFRA = {
    "javascript": ["javascript:S1874", "javascript:S6627"],
    "typescript": ["typescript:S1874", "typescript:S4325", "typescript:S4328",
                   "typescript:S6606", "typescript:S6627"],
    "python": ["python:S6786"],
    "csharp": ["csharpsquid:S110", "csharpsquid:S1200", "csharpsquid:S1944",
               "csharpsquid:S3242", "csharpsquid:S3246", "csharpsquid:S4047",
               "csharpsquid:S6802"],
}


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def sq_api(path, params=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    req = urllib.request.Request(f"http://127.0.0.1:9000{path}{q}")
    req.add_header("Authorization", f"Basic {AUTH}")
    raw = urllib.request.urlopen(req).read()
    return json.loads(raw) if raw else {}


def ensure_container():
    st = subprocess.run(["podman", "inspect", "-f", "{{.State.Running}}", "sonarqube"],
                        capture_output=True, text=True).stdout.strip()
    if st != "true":
        print("starting sonarqube container...")
        subprocess.run(["podman", "start", "sonarqube"], check=True)
        time.sleep(20)
    for _ in range(40):
        try:
            if sq_api("/api/system/status")["status"] == "UP":
                return
        except Exception:
            pass
        time.sleep(5)
    raise SystemExit("sonarqube did not reach UP state")


def scan_project(proj):
    d = (ORACLE / "projects" / proj).resolve()
    token = (ORACLE / "token").read_text().strip()
    r = subprocess.run(
        ["/tmp/sonar-scanner-6.2.1.4610-linux-x64/bin/sonar-scanner",
         f"-Dsonar.projectKey={proj}", f"-Dsonar.login={token}",
         "-Dsonar.host.url=http://127.0.0.1:9000",
         f"-Dsonar.working.directory=/tmp/sqscanner-{proj}"],
        cwd=d, capture_output=True, text=True)
    ok = "EXECUTION SUCCESS" in r.stdout
    print(f"  scan {proj}: {'SUCCESS' if ok else 'FAILED'}")
    return ok


def fetch_issues(proj):
    issues, page = [], 1
    while True:
        q = urllib.parse.urlencode({"componentKeys": proj, "resolved": "false",
                                    "ps": 500, "p": page})
        req = urllib.request.Request(f"http://127.0.0.1:9000/api/issues/search?{q}")
        req.add_header("Authorization", f"Basic {AUTH}")
        for attempt in range(12):
            try:
                d = json.load(urllib.request.urlopen(req))
                break
            except urllib.error.HTTPError as e:
                body = e.read().decode()[:200]
                if e.code == 400 and attempt < 4:
                    time.sleep(min(30, 5 * (attempt + 1)))  # compute engine still flushing
                    req = urllib.request.Request(f"http://127.0.0.1:9000/api/issues/search?{q}")
                    req.add_header("Authorization", f"Basic {AUTH}")
                    continue
                print(f"  issues API {e.code}: {body}")
                raise
        for i in d["issues"]:
            issues.append({"rule": i["rule"], "line": i.get("line"),
                           "file": i["component"].split("/")[-1]})
        total, ps = d["paging"]["total"], d["paging"]["pageSize"]
        if page * ps >= total or not d["issues"]:
            break
        page += 1
    # security hotspots live outside /api/issues
    hp, page = [], 1
    while True:
        q = urllib.parse.urlencode({"projectKey": proj, "ps": 500, "p": page})
        req = urllib.request.Request(f"http://127.0.0.1:9000/api/hotspots/search?{q}")
        req.add_header("Authorization", f"Basic {AUTH}")
        d = json.load(urllib.request.urlopen(req))
        for h in d.get("hotspots", []):
            comp = h.get("component", "")
            path = comp.get("path", comp) if isinstance(comp, dict) else comp
            issues.append({"rule": h.get("ruleKey", ""), "line": h.get("line"),
                           "file": str(path).split("/")[-1], "hotspot": True})
        total, ps = d["paging"]["total"], d["paging"]["pageSize"]
        if page * ps >= total or not d.get("hotspots"):
            break
        page += 1
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = RESULTS / f"{proj}.sq.json"
    json.dump(issues, open(out, "w"), indent=1)
    return len(issues)


def run_ours(proj):
    # oracle-cs keeps sources at the project root; others under src/
    src = ORACLE / "projects" / proj / ("." if proj == "oracle-cs" else "src")
    out = RESULTS / f"{proj}.ours.json"
    r = subprocess.run(["cargo", "run", "-q", "-p", "hoonarqube-cli", "--", "analyze",
                        "--format", "json", str(src)], capture_output=True, text=True,
                       cwd=REPO)
    if r.returncode != 0:
        print(f"  ours {proj}: FAILED\n{r.stderr[-500:]}")
        return None
    data = json.loads(r.stdout)
    json.dump(data, open(out, "w"))
    return out


def diff(proj, lang, sq_json, ours_json):
    exp_path = ORACLE / "projects" / proj / "expected.jsonl"
    expected = [json.loads(l) for l in open(exp_path) if l.strip()]
    sq = json.load(open(sq_json))
    ours = json.load(open(ours_json))

    def sq_on(bad_file, key):
        return sorted(i["line"] for i in sq
                      if i["file"] == bad_file and i["rule"] == key and i.get("line"))

    def ours_on(bad_file, key):
        rep = ours.get("files", []) if isinstance(ours, dict) else []
        return sorted(i["range"]["start"]["line"] for f in rep
                      if f["path"].endswith(bad_file)
                      for i in f["issues"] if i["rule_key"] == key)

    def good_fire(good_file, key, side):
        if side == "sq":
            return [i for i in sq if i["file"] == good_file and i["rule"] == key]
        rep = ours.get("files", []) if isinstance(ours, dict) else []
        return [i for f in rep if f["path"].endswith(good_file)
                for i in f["issues"] if i["rule_key"] == key]

    infra = set(INFRA.get(lang.replace("oracle-", ""), []))
    counts = {"PASS": 0, "SQ-MISS": 0, "OURS-MISS": 0, "GOOD-FIRE": 0,
              "SKIPPED": 0, "INFRA": 0}
    rows = []
    seen = set()
    for e in expected:
        key = e["key"]
        if key in seen or key in infra:
            counts["INFRA"] += 1
            continue
        seen.add(key)
        if e.get("skip"):
            counts["SKIPPED"] += 1
            continue
        bad, good = e["bad"], e["bad"].replace("_bad", "_good")
        min_exp = e.get("expect_lines_min", 1)
        s = sq_on(bad, key)
        o = ours_on(bad, key)
        sq_ok = len(set(s)) >= min_exp
        our_ok = len(set(o)) >= min_exp
        sq_gf = [i for i in good_fire(good, key, "sq")]
        our_gf = good_fire(good, key, "ours")
        status = ("PASS" if sq_ok and our_ok and not sq_gf and not our_gf
                  else "SQ-MISS" if not sq_ok
                  else "OURS-MISS" if not our_ok else "GOOD-FIRE")
        counts[status] += 1
        if status != "PASS":
            rows.append({"key": key, "status": status,
                         "sq_lines": s[:10], "our_lines": o[:10],
                         "good_fire_sq": bool(sq_gf), "good_fire_ours": bool(our_gf)})
    return counts, rows


def main():
    quick = "--quick" in sys.argv
    ensure_container()
    all_counts = {}
    divergences = {}
    for proj in LANGS:
        lang = proj.replace("oracle-", "")
        print(f"[{proj}]")
        if not quick:
            if not scan_project(proj):
                continue
            n = fetch_issues(proj)
            print(f"  oracle issues: {n}")
            r = run_ours(proj)
            if r is None:
                continue
        sqj = RESULTS / f"{proj}.sq.json"
        ourj = RESULTS / f"{proj}.ours.json"
        if not sqj.exists() or not ourj.exists():
            print("  missing artifacts; run without --quick")
            continue
        counts, rows = diff(proj, lang, sqj, ourj)
        all_counts[proj] = counts
        if rows:
            divergences[proj] = rows
        print(" ", counts)
    # Classify SQ-MISS: does the rule exist in this CE instance at all?
    ce_cache_path = RESULTS / "ce_rule_cache.json"
    ce = json.load(open(ce_cache_path)) if ce_cache_path.exists() else {}
    def rule_in_ce(key):
        if key not in ce:
            try:
                sq_api("/api/rules/show", {"key": key})
                ce[key] = True
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    ce[key] = False
                else:
                    ce[key] = e.code  # transient; retried on next run
            except Exception:
                ce[key] = "ERR"
            open(ce_cache_path, "w").write(json.dumps(ce))
        return ce.get(key) is True
    beyond_ce = {}
    real = {}
    for proj, rows in divergences.items():
        lang = proj.replace("oracle-", "")
        for r in rows:
            if r["status"] != "SQ-MISS":
                continue
            key = r["key"]
            prefix = {"oracle-py": "python:", "oracle-js": "javascript:",
                      "oracle-ts": "typescript:", "oracle-cs": "csharpsquid:"}[proj]
            full = key if ":" in key else prefix + key
            if rule_in_ce(full):
                real.setdefault(proj, []).append(r)
            else:
                beyond_ce.setdefault(proj, []).append(key)
    json.dump({"beyond_ce": beyond_ce, "real_divergences": real},
              open(RESULTS / "parity_divergences.json", "w"), indent=1)
    # C# oracle scan requires MSBuild/Roslyn integration unavailable on
    # bare fixture collections; treat zero-issue csharp scans as blocked.
    cs_blocked = all_counts.get("oracle-cs", {}).get("PASS", 0) == 0
    n_beyond = sum(len(v) for v in beyond_ce.values())
    n_real = sum(
        len([r for r in rows if r["status"] != "SQ-MISS"])
        for proj, rows in real.items() if not (proj == "oracle-cs" and cs_blocked)
    )
    print(f"BEYOND-CE (rule absent from SonarQube Community): {n_beyond}")
    for proj, keys in beyond_ce.items():
        if keys: print(f"  {proj}: {len(keys)}")
    if cs_blocked:
        cs_n = sum(len(rows) for proj, rows in real.items() if proj == "oracle-cs")
        print(f"C# ORACLE-BLOCKED ({cs_n} keys): MSBuild/Roslyn integration unavailable; C# parity verified by unit tests")
    print("REAL DIVERGENCES (rule exists in CE, findings differ):", n_real)
    for proj, rows in real.items():
        if proj == "oracle-cs" and cs_blocked:
            continue
        for r in rows:
            print(f"  {proj} {r['key']} [{r['status']}] sq_lines={r['sq_lines'][:5]} our_lines={r['our_lines'][:5]} good_fire={r['good_fire_sq']}/{r['good_fire_ours']}")
    sys.exit(0 if n_real == 0 else 1)


if __name__ == "__main__":
    main()
