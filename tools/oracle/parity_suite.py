#!/usr/bin/env python3
"""SonarQube Community parity suite.

Lifecycle: starts the SQ container if needed, waits for UP, ensures profiles
and projects, runs scanner + hoonarqube on every fixture set, fetches oracle
issues, diffs per rule key, and prints a parity report.

Usage:
  python3 tools/oracle/parity_suite.py            # full run, report to stdout
  python3 tools/oracle/parity_suite.py --quick    # reuse existing scan results
Exit code 0 only when every frozen catalog rule is an exact PASS.
"""
import base64
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from csharp_oracle import generate_solution

from parity import (
    classify_sq_misses,
    compare_reports,
    counts,
    failure_count,
    parse_report_task,
    validate_oracle_report,
    wait_for_compute_engine,
)

REPO = Path(__file__).resolve().parent.parent.parent
ORACLE = REPO / ".oracle/sonar"
RESULTS = ORACLE / "results"
SONAR_URL = os.environ.get("SONAR_ORACLE_URL", "http://127.0.0.1:9000").rstrip("/")
LANGS = ["oracle-py", "oracle-js", "oracle-ts", "oracle-cs"]
EXT = {"oracle-py": "py", "oracle-js": "js", "oracle-ts": "ts", "oracle-cs": "cs"}
CATALOG_LANGUAGE = {
    "py": "python",
    "js": "javascript",
    "ts": "typescript",
    "cs": "csharp",
}
RESULT_TAG = os.environ.get("SONAR_ORACLE_RESULT_TAG", "")
if RESULT_TAG and not re.fullmatch(r"[a-zA-Z0-9_-]+", RESULT_TAG):
    raise RuntimeError("SONAR_ORACLE_RESULT_TAG may contain only letters, digits, '_' and '-'")

def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kw)


def result_path(project, kind):
    tag = f".{RESULT_TAG}" if RESULT_TAG else ""
    return RESULTS / f"{project}{tag}.{kind}.json"


def auth_header():
    return "Basic " + base64.b64encode(f"{oracle_token()}:".encode()).decode()


def oracle_token():
    token = os.environ.get("SONAR_ORACLE_TOKEN")
    if token is not None:
        return token
    token_path = ORACLE / "token"
    if not token_path.exists():
        raise RuntimeError("set SONAR_ORACLE_TOKEN or create .oracle/sonar/token")
    return token_path.read_text().strip()


def sq_api(path, params=None):
    q = ("?" + urllib.parse.urlencode(params)) if params else ""
    req = urllib.request.Request(f"{SONAR_URL}{path}{q}")
    req.add_header("Authorization", auth_header())
    raw = urllib.request.urlopen(req).read()
    return json.loads(raw) if raw else {}


def ensure_container():
    if SONAR_URL == "http://127.0.0.1:9000":
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
    if proj == "oracle-cs":
        return scan_csharp_project(proj)
    scanner = os.environ.get("SONAR_SCANNER", "sonar-scanner")
    scanner_path = shutil.which(scanner) if os.path.sep not in scanner else scanner
    if not scanner_path or not Path(scanner_path).is_file():
        print(f"  scan {proj}: FAILED (set SONAR_SCANNER)")
        return False
    d = (ORACLE / "projects" / proj).resolve()
    token = oracle_token()
    r = subprocess.run(
        [scanner_path,
         f"-Dsonar.projectKey={proj}", f"-Dsonar.login={token}",
         f"-Dsonar.host.url={SONAR_URL}",
         f"-Dsonar.working.directory=/tmp/sqscanner-{proj}"],
        cwd=d, capture_output=True, text=True)
    ok = "EXECUTION SUCCESS" in r.stdout
    if not ok:
        print(f"  scan {proj}: FAILED")
        return False
    task_file = Path(f"/tmp/sqscanner-{proj}/report-task.txt")
    if not task_file.exists():
        print(f"  scan {proj}: FAILED (missing report-task.txt)")
        return False
    try:
        task_id = parse_report_task(task_file.read_text())["ceTaskId"]
    except ValueError as error:
        print(f"  scan {proj}: FAILED ({error})")
        return False
    status = wait_for_compute_engine(
        task_id,
        lambda value: sq_api("/api/ce/task", {"id": value})
        .get("task", {})
        .get("status"),
        lambda: time.sleep(1),
    )
    if status == "SUCCESS":
        print(f"  scan {proj}: SUCCESS (compute engine complete)")
        return True
    print(f"  scan {proj}: FAILED (compute engine {status})")
    return False


def csharp_begin_command(scanner_path, proj, output_dir, auth_arg):
    return [
        scanner_path,
        "begin",
        f"/k:{proj}",
        f"/d:sonar.host.url={SONAR_URL}",
        f"/d:sonar.projectBaseDir={output_dir}",
        "/d:sonar.scm.exclusions.disabled=true",
        auth_arg,
    ]


def scan_csharp_project(proj):
    scanner = os.environ.get("SONAR_DOTNET_SCANNER", "dotnet-sonarscanner")
    scanner_path = shutil.which(scanner) if os.path.sep not in scanner else scanner
    if not scanner_path or not Path(scanner_path).is_file():
        print("  scan oracle-cs: FAILED (set SONAR_DOTNET_SCANNER)")
        return False
    if not shutil.which("dotnet"):
        print("  scan oracle-cs: FAILED (dotnet SDK missing)")
        return False

    project_dir = (ORACLE / "projects" / proj).resolve()
    token = oracle_token()
    version = str(sq_api("/api/system/status").get("version", ""))
    auth_name = "sonar.login" if version.startswith("9.") else "sonar.token"
    auth_arg = f"/d:{auth_name}={token}"
    fixture_limit_value = os.environ.get("SONAR_CSHARP_FIXTURE_LIMIT")
    try:
        fixture_limit = int(fixture_limit_value) if fixture_limit_value else None
    except ValueError:
        print("  scan oracle-cs: FAILED (SONAR_CSHARP_FIXTURE_LIMIT must be an integer)")
        return False
    with tempfile.TemporaryDirectory(prefix="native-csharp-", dir=REPO / "tools/oracle") as directory:
        output_dir = Path(directory)
        solution, fixture_count = generate_solution(
            project_dir, output_dir, limit=fixture_limit
        )
        begin = subprocess.run(
            csharp_begin_command(scanner_path, proj, output_dir, auth_arg),
            cwd=output_dir,
            capture_output=True,
            text=True,
        )
        if begin.returncode != 0:
            print(f"  scan {proj}: FAILED (native begin)\n{begin.stdout[-500:]}")
            return False
        build = subprocess.run(
            [
                "dotnet",
                "build",
                str(solution),
                "--no-incremental",
                "--disable-build-servers",
            ],
            cwd=output_dir,
            capture_output=True,
            text=True,
        )
        print(
            f"  native build: {fixture_count} isolated fixture project(s), "
            f"exit {build.returncode}"
        )
        end = subprocess.run(
            [scanner_path, "end", auth_arg],
            cwd=output_dir,
            capture_output=True,
            text=True,
        )
        if end.returncode != 0:
            print(f"  scan {proj}: FAILED (native end)\n{end.stdout[-2000:]}")
            return False
        if build.returncode != 0:
            output = (build.stdout + "\n" + build.stderr).strip()
            print(f"  scan {proj}: FAILED (native build)\n{output[-2000:]}")
            return False
        task_file = output_dir / ".sonarqube/out/.sonar/report-task.txt"
        if not task_file.exists():
            print(f"  scan {proj}: FAILED (missing native report-task.txt)")
            return False
        try:
            task_id = parse_report_task(task_file.read_text())["ceTaskId"]
        except ValueError as error:
            print(f"  scan {proj}: FAILED ({error})")
            return False
        status = wait_for_compute_engine(
            task_id,
            lambda value: sq_api("/api/ce/task", {"id": value})
            .get("task", {})
            .get("status"),
            lambda: time.sleep(1),
        )
    if status == "SUCCESS":
        print(f"  scan {proj}: SUCCESS (native compute engine complete)")
        return True
    print(f"  scan {proj}: FAILED (native compute engine {status})")
    return False


def fetch_issues(proj):
    issues, page = [], 1
    while True:
        q = urllib.parse.urlencode({"componentKeys": proj, "resolved": "false",
                                    "ps": 500, "p": page})
        req = urllib.request.Request(f"{SONAR_URL}/api/issues/search?{q}")
        req.add_header("Authorization", auth_header())
        for attempt in range(12):
            try:
                d = json.load(urllib.request.urlopen(req))
                break
            except urllib.error.HTTPError as e:
                body = e.read().decode()[:200]
                if e.code == 400 and attempt < 4:
                    time.sleep(min(30, 5 * (attempt + 1)))  # compute engine still flushing
                    req = urllib.request.Request(f"{SONAR_URL}/api/issues/search?{q}")
                    req.add_header("Authorization", auth_header())
                    continue
                print(f"  issues API {e.code}: {body}")
                raise
        for i in d["issues"]:
            issues.append(canonical_sonar_issue(i, hotspot=False))
        total, ps = d["paging"]["total"], d["paging"]["pageSize"]
        if page * ps >= total or not d["issues"]:
            break
        page += 1
    # security hotspots live outside /api/issues
    hp, page = [], 1
    while True:
        q = urllib.parse.urlencode({"projectKey": proj, "ps": 500, "p": page})
        req = urllib.request.Request(f"{SONAR_URL}/api/hotspots/search?{q}")
        req.add_header("Authorization", auth_header())
        d = json.load(urllib.request.urlopen(req))
        for h in d.get("hotspots", []):
            issues.append(canonical_sonar_issue(h, hotspot=True))
        total, ps = d["paging"]["total"], d["paging"]["pageSize"]
        if page * ps >= total or not d.get("hotspots"):
            break
        page += 1
    RESULTS.mkdir(parents=True, exist_ok=True)
    out = result_path(proj, "sq")
    json.dump(
        {
            "schema_version": 2,
            "project": proj,
            "server": sq_api("/api/system/status"),
            "issues": issues,
        },
        open(out, "w"),
        indent=1,
    )
    return len(issues)


def canonical_sonar_issue(issue, hotspot):
    component = issue.get("component", "")
    path = component.get("path", component) if isinstance(component, dict) else component
    text_range = issue.get("textRange") or {}
    start_line = text_range.get("startLine", issue.get("line"))
    start_column = text_range.get("startOffset")
    end_line = text_range.get("endLine", start_line)
    end_column = text_range.get("endOffset")
    return {
        "rule": issue.get("ruleKey" if hotspot else "rule", ""),
        "file": str(path).replace("\\", "/").rsplit("/", 1)[-1],
        "message": issue.get("message", ""),
        "range": {
            "start": {"line": start_line, "column": start_column},
            "end": {"line": end_line, "column": end_column},
        },
        "hotspot": hotspot,
    }


def run_ours(proj):
    # oracle-cs keeps sources at the project root; others under src/
    src = ORACLE / "projects" / proj / ("." if proj == "oracle-cs" else "src")
    out = result_path(proj, "ours")
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
    project_dir = ORACLE / "projects" / proj
    exp_path = project_dir / "expected.jsonl"
    expected = [json.loads(l) for l in open(exp_path) if l.strip()]
    sq = json.load(open(sq_json))
    ours = json.load(open(ours_json))
    language = CATALOG_LANGUAGE[lang]
    catalog = json.loads((REPO / "catalog/rules" / f"{language}.json").read_text())
    catalog_keys = [rule["external_key"] for rule in catalog["rules"]]
    enterprise_unverified = [
        rule["external_key"]
        for rule in catalog["rules"]
        if rule.get("classification") == "enterprise-unverified"
    ]
    fixture_dir = project_dir if proj == "oracle-cs" else project_dir / "src"
    available_files = [path.name for path in fixture_dir.iterdir() if path.is_file()]
    rows = compare_reports(
        expected,
        sq,
        ours,
        (),
        catalog_keys,
        available_files,
        enterprise_unverified,
    )
    return counts(rows), rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quick", action="store_true", help="reuse cached scan artifacts")
    parser.add_argument(
        "--project",
        action="append",
        choices=LANGS,
        help="run only this oracle project (repeatable)",
    )
    args = parser.parse_args()
    quick = args.quick
    projects = args.project or LANGS
    if not quick:
        ensure_container()
    all_counts = {}
    all_rows = {}
    invalid_artifacts = {}
    blocked_projects = set()
    for proj in projects:
        lang = proj.replace("oracle-", "")
        print(f"[{proj}]")
        if not quick:
            if not scan_project(proj):
                invalid_artifacts[proj] = "oracle scan failed"
                continue
            n = fetch_issues(proj)
            print(f"  oracle issues: {n}")
            r = run_ours(proj)
            if r is None:
                invalid_artifacts[proj] = "hoonarqube analysis failed"
                continue
        sqj = result_path(proj, "sq")
        ourj = result_path(proj, "ours")
        if not sqj.exists() or not ourj.exists():
            print("  missing artifacts; run without --quick")
            invalid_artifacts[proj] = "missing artifacts"
            continue
        try:
            project_counts, rows = diff(proj, lang, sqj, ourj)
            oracle_issues = validate_oracle_report(json.load(open(sqj)))
        except (ValueError, json.JSONDecodeError) as error:
            print(f"  invalid artifact: {error}")
            invalid_artifacts[proj] = str(error)
            continue
        all_counts[proj] = project_counts
        all_rows[proj] = rows
        if proj == "oracle-cs" and not oracle_issues:
            blocked_projects.add(proj)
        print(" ", project_counts)
    # Classify SQ-MISS: does the rule exist in this CE instance at all?
    server_cache_key = hashlib.sha256(SONAR_URL.encode()).hexdigest()[:12]
    ce_cache_path = RESULTS / f"ce_rule_cache.{server_cache_key}.json"
    ce = json.load(open(ce_cache_path)) if ce_cache_path.exists() else {}
    def rule_in_ce(key):
        if key not in ce:
            if quick:
                return None
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
        value = ce.get(key)
        return value if isinstance(value, bool) else None
    beyond_ce = {}
    unverified = {}
    for proj, rows in all_rows.items():
        beyond, unknown = classify_sq_misses(rows, rule_in_ce)
        if beyond:
            beyond_ce[proj] = beyond
        if unknown:
            unverified[proj] = unknown
    divergences = {
        proj: [row for row in rows if row["status"] != "PASS"]
        for proj, rows in all_rows.items()
    }
    final_counts = {proj: counts(rows) for proj, rows in all_rows.items()}
    n_failures = sum(failure_count(rows) for rows in all_rows.values())
    n_failures += len(invalid_artifacts) + len(blocked_projects)
    result_parts = [] if projects == LANGS else projects
    if RESULT_TAG:
        result_parts.append(RESULT_TAG)
    result_name = "parity_divergences"
    if result_parts:
        result_name += "." + ".".join(result_parts)
    result_name += ".json"
    report = {
        "schema_version": 2,
        "result_tag": RESULT_TAG or None,
        "projects": projects,
        "summary": final_counts,
        "failure_count": n_failures,
        "beyond_ce": beyond_ce,
        "oracle_unverified": unverified,
        "enterprise_unverified": {
            proj: [row["key"] for row in rows if row["status"] == "ENTERPRISE_UNVERIFIED"]
            for proj, rows in all_rows.items()
            if any(row["status"] == "ENTERPRISE_UNVERIFIED" for row in rows)
        },
        "invalid_artifacts": invalid_artifacts,
        "blocked_projects": sorted(blocked_projects),
        "divergences": divergences,
    }
    (RESULTS / result_name).write_text(json.dumps(report, indent=1) + "\n")
    # A native scanner run producing no C# findings is invalid evidence.
    cs_blocked = "oracle-cs" in blocked_projects
    n_beyond = sum(len(v) for v in beyond_ce.values())
    n_enterprise_unverified = sum(
        1
        for rows in all_rows.values()
        for row in rows
        if row["status"] == "ENTERPRISE_UNVERIFIED"
    )
    print(f"BEYOND-CE (rule absent from SonarQube Community): {n_beyond}")
    for proj, keys in beyond_ce.items():
        if keys: print(f"  {proj}: {len(keys)}")
    print(f"ENTERPRISE-UNVERIFIED (Community cannot certify): {n_enterprise_unverified}")
    if cs_blocked:
        print("C# ORACLE-BLOCKED: zero Sonar findings; parity is unverified")
    print("PARITY FAILURES:", n_failures)
    for proj, rows in divergences.items():
        for r in rows[:20]:
            print(f"  {proj} {r['key']} [{r['status']}]")
        if len(rows) > 20:
            print(f"  {proj}: {len(rows) - 20} more divergence(s); see {result_name}")
    for proj, reason in invalid_artifacts.items():
        print(f"  {proj} [INVALID_ARTIFACT] {reason}")
    sys.exit(0 if n_failures == 0 else 1)


if __name__ == "__main__":
    main()
