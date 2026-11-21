"""Check persisted public Go results or measure both scanners through their APIs."""

import argparse
import os
import platform
import re
import secrets
import shutil
import statistics
import subprocess
import sys
import time
from pathlib import Path
from tempfile import TemporaryDirectory

from parity import read_json, read_secret_file, write_json_atomic
from public_corpus_capture import verify_checkout
from public_corpus_prepare import prepare_checkout
from public_corpus_summary import canonical_sha, normalized_path, utf16_coordinates
from real_project_suite import Sonar, digest, verify_source

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
from smoke_cli_service import request, running_service  # noqa: E402

PARAMETERS = {
    "go:S1135": {},
    "go:S1186": {},
    "go:S1192": {"threshold": "3"},
    "go:S3776": {"threshold": "15"},
}
RULES = set(PARAMETERS)
SCOPES = {"chi": 14, "mux": 6, "cors": 4, "pflag": 1}
CONTRACT = Path(__file__).with_name("public-go-pipeline-contract.json")
MANIFEST = Path(__file__).with_name("public-corpus-projects-20261120.json")


def elapsed(start):
    return round(time.perf_counter() - start, 6)


def inventory(root, paths):
    files = {}
    for path in paths:
        name = normalized_path(path)
        file = (root / name).resolve(strict=True)
        if not file.is_relative_to(root) or name in files:
            raise ValueError("file escaped the checkout or was indexed twice")
        files[name] = digest(file)
    if not files:
        raise ValueError("empty analysis")
    return files


def contract(files, findings):
    for rule, path, *_ in findings:
        if rule not in RULES or path not in files:
            raise ValueError("finding is outside the agreed scope")
    return {
        "files": len(files),
        "inventory_sha256": canonical_sha(files),
        "primaries": len(findings),
        "primaries_sha256": canonical_sha(sorted(findings, key=repr)),
        "no_todo_gate": "fail" if any(r[0] == "go:S1135" for r in findings) else "pass",
    }


def native(args, row, root, folder, port, token):
    cmd = [
        args.native,
        "analyze",
        *row["sources"],
        "--format",
        "json",
        "--profile",
        "sonar-parity",
    ]
    for pattern in row["exclude"]:
        cmd.extend(["--exclude", pattern])
    t = time.perf_counter()
    with (folder / "native.json").open("wb") as out:
        subprocess.run(cmd, cwd=root, stdout=out, timeout=240, check=True)
    scan = elapsed(t)
    report = read_json(folder / "native.json")
    if not report["project"]["complete"]:
        raise ValueError("incomplete native scan")
    response = request(
        port,
        token,
        "/smoke/analyses",
        {
            "schema_version": 1,
            "branch": folder.name,
            "commit": row["commit"],
            "analyzed_at": "2026-11-20T00:00:00Z",
            "report": report,
        },
    )
    if response["idempotent"] or not response["analysis"]["complete"]:
        raise ValueError("expected newly persisted, complete native analysis")
    detail = "/smoke/analyses/" + str(response["analysis"]["id"])
    stored = request(port, token, detail)["analysis"]["report"]
    found = request(port, token, detail + "/findings")["findings"]
    ready = elapsed(t)
    if len(found) != sum(len(f["issues"]) for f in stored["files"]):
        raise ValueError("native findings index differs from report count")
    parameters = {
        r["key"]: {
            p["key"]: p["default_value"]
            for p in r["parameters"]
            if p["default_value"] is not None
        }
        for r in stored["parity"]["active_rules"]
        if r["key"] in RULES
    }
    if parameters != PARAMETERS:
        raise ValueError("native rule activation or parameters changed")
    files = inventory(root, (f["path"] for f in stored["files"]))
    primaries = []
    for item in found:
        key = item["rule_key"]
        if key in RULES:
            path = normalized_path(item["path"])
            if path not in files:
                raise ValueError("unknown file in native finding")
            lines = re.split(r"\r?\n", (root / path).read_bytes().decode("utf8"))
            primaries.append((key, path, *utf16_coordinates(item, lines)))
    return {
        "scanner_s": scan,
        "readable_s": ready,
        "raw_findings": len(found),
        "contract": contract(files, primaries),
    }


def reference(args, row, root, folder, sonar, token):
    # A random, newly created project has no previous analysis cache.
    key = "hq-go-timing-" + secrets.token_hex(10)
    created = sonar.request(
        "/api/projects/create",
        {"project": key, "name": key, "visibility": "private"},
        post=True,
    )
    if created["project"]["key"] != key:
        raise ValueError("server did not create the requested project")
    try:
        return scan_reference(args, row, root, folder, sonar, token, key)
    finally:
        sonar.request("/api/projects/delete", {"project": key}, post=True)


def scan_reference(args, row, root, folder, sonar, token, key):
    props = {
        "sonar.host.url": args.server,
        "sonar.projectKey": key,
        "sonar.projectVersion": row["commit"],
        "sonar.sources": ",".join(row["sources"]),
        "sonar.exclusions": ",".join(row["exclude"]),
        "sonar.sourceEncoding": "UTF-8",
        "sonar.scm.disabled": "true",
        "sonar.scanner.skipJreProvisioning": "true",
        "sonar.userHome": str(args.scanner_cache),
        "sonar.working.directory": str(folder / "scannerwork"),
    }
    env = {
        **os.environ,
        "PATH": str(args.java.parent) + os.pathsep + os.environ["PATH"],
        "JAVA_HOME": str(args.java.parent.parent),
        "SONAR_TOKEN": token,
    }
    cmd = [
        args.java,
        "-jar",
        args.scanner_jar,
        *[f"-D{k}={v}" for k, v in props.items()],
    ]
    t = time.perf_counter()
    with (folder / "scanner.log").open("wb") as out:
        subprocess.run(
            cmd,
            cwd=root,
            env=env,
            stdout=out,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=240,
        )
    scan = elapsed(t)
    task = wait_for_compute(sonar, key, folder)
    components = sonar.pages(
        "/api/components/tree",
        {"component": key, "qualifiers": "FIL"},
        "components",
        folder,
        "indexed",
    )
    issues = sonar.pages(
        "/api/issues/search",
        {"componentKeys": key, "resolved": "false"},
        "issues",
        folder,
        "findings",
    )
    ready = elapsed(t)
    verify_reference_rules(sonar, key)
    files = inventory(root, (f["path"] for f in components))
    primaries = []
    for issue in issues:
        if issue["rule"] in RULES:
            component = issue["component"]
            if not component.startswith(key + ":"):
                raise ValueError("unexpected reference component")
            span = issue.get("textRange")
            coords = (
                tuple(
                    span[k]
                    for k in ("startLine", "startOffset", "endLine", "endOffset")
                )
                if span
                else (None,) * 4
            )
            primaries.append(
                (issue["rule"], normalized_path(component[len(key) + 1 :]), *coords)
            )
    write_json_atomic(folder / "compute.json", task)
    return {
        "scanner_s": scan,
        "readable_s": ready,
        "raw_findings": len(issues),
        "contract": contract(files, primaries),
    }


def wait_for_compute(sonar, key, folder):
    log = (folder / "scanner.log").read_text()
    if re.search(
        r"\b(?:WARN|ERROR)\b.*(?:failed to parse|parsing error|failed to analyze|unable to parse)",
        log,
        re.I,
    ):
        raise ValueError("scanner reported incomplete source processing")
    tasks = re.findall(r"api/ce/task\?id=([\w-]+)", log)
    if len(set(tasks)) != 1:
        raise ValueError("missing or ambiguous compute task")
    end = time.monotonic() + 180
    while True:
        task = sonar.request("/api/ce/task", {"id": tasks[0]})["task"]
        if (
            task["status"] == "SUCCESS"
            and task["componentKey"] == key
            and task.get("analysisId")
        ):
            return task
        if task["status"] not in {"PENDING", "IN_PROGRESS"} or time.monotonic() >= end:
            write_json_atomic(folder / "failed-compute.json", task)
            raise ValueError(f"compute did not finish successfully: {task['status']}")
        time.sleep(0.1)


def verify_reference_rules(sonar, key):
    profiles = sonar.request(
        "/api/qualityprofiles/search", {"language": "go", "project": key}
    )["profiles"]
    if len(profiles) != 1:
        raise ValueError("ambiguous Go profile")
    profile = profiles[0]["key"]
    parameters = {}
    for rule in sorted(RULES):
        data = sonar.request(
            "/api/rules/search",
            {
                "qprofile": profile,
                "activation": "true",
                "rule_key": rule,
                "f": "actives,params",
            },
        )
        matches = [r for r in data["rules"] if r["key"] == rule]
        active = [
            a for a in data.get("actives", {}).get(rule, []) if a["qProfile"] == profile
        ]
        if len(matches) != 1 or len(active) != 1:
            raise ValueError(f"inactive or ambiguous rule: {rule}")
        defaults = {
            p["key"]: p["defaultValue"]
            for p in matches[0].get("params", [])
            if "defaultValue" in p
        }
        defaults.update({p["key"]: p["value"] for p in active[0].get("params", [])})
        parameters[rule] = defaults
    if parameters != PARAMETERS:
        raise ValueError("reference rule activation or parameters changed")


def compare(name, a, b):
    if b != read_json(CONTRACT)[name]:
        raise ValueError(
            f"{name}: result changed from the independent pinned reference"
        )
    compare_persisted(name, a, b)


def compare_persisted(name, actual, expected):
    if actual != expected:
        missing = object()
        fields = [
            key
            for key in sorted(actual.keys() | expected.keys())
            if actual.get(key, missing) != expected.get(key, missing)
        ]
        raise ValueError(f"{name}: persisted output differs in {', '.join(fields)}")
    if actual["primaries"] != SCOPES[name] or actual["no_todo_gate"] != (
        "fail" if name == "chi" else "pass"
    ):
        raise ValueError(f"{name}: unexpected pinned finding count or no-TODO result")


def pinned_rows():
    selected = [r for r in read_json(MANIFEST)["captures"] if r["name"] in SCOPES]
    rows = {r["name"]: r for r in selected}
    if rows.keys() != SCOPES.keys() or len(rows) != len(selected):
        raise ValueError("incomplete or duplicate pinned Go inventory")
    return rows


def check_persisted(args, rows):
    contract_file = args.expected_contract or CONTRACT
    expected = read_json(contract_file)
    if expected.keys() != rows.keys():
        raise ValueError("expected contract must cover every pinned Go project")
    prepared = {n: prepare_checkout(args.output, row) for n, row in rows.items()}
    results = {}
    with TemporaryDirectory(dir=args.output) as service_dir:
        token = secrets.token_urlsafe(40)
        with running_service(args.service, Path(service_dir), token) as port:
            for name, row in prepared.items():
                folder = args.output / name
                folder.mkdir()
                root = verify_checkout(row)
                actual = native(args, row, root, folder, port, token)["contract"]
                verify_checkout(row)
                compare_persisted(name, actual, expected[name])
                results[name] = {"commit": row["commit"], **actual}
                print(
                    f"{name}: {actual['files']} persisted files, "
                    f"{actual['primaries']} primaries, no-TODO {actual['no_todo_gate']}",
                    flush=True,
                )
    write_json_atomic(
        args.output / "result.json",
        {"expected_contract_sha256": digest(contract_file), "projects": results},
    )


def pinned_checkout(args, name, row):
    if shutil.disk_usage(args.output).free < 5 * 1024**3:
        raise OSError("less than 5 GiB free")
    root = verify_source({**row, "path": str(args.sources / name)})
    if (
        subprocess.check_output(
            ["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True
        ).strip()
        != row["tree"]
    ):
        raise ValueError("source tree mismatch")
    if subprocess.check_output(
        ["git", "ls-files", "--others", "--exclude-standard"], cwd=root
    ):
        raise ValueError("untracked public source")
    return root


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    for flag in ("output", "native", "service"):
        p.add_argument("--" + flag, type=Path, required=True)
    timing_paths = ("sources", "java", "scanner-jar", "scanner-cache", "token-file")
    for flag in timing_paths:
        p.add_argument("--" + flag, type=Path)
    p.add_argument("--server")
    p.add_argument("--rounds", type=int, default=3)
    p.add_argument(
        "--check-persisted",
        action="store_true",
        help="fetch pinned sources and check the candidate service without Sonar",
    )
    p.add_argument(
        "--expected-contract",
        type=Path,
        help="override the reference contract in check mode for a negative control",
    )
    args = p.parse_args()
    if not args.check_persisted:
        missing = [
            "--" + flag
            for flag in (*timing_paths, "server")
            if not getattr(args, flag.replace("-", "_"))
        ]
        if missing:
            p.error(f"timing mode requires {', '.join(missing)}")
        if args.expected_contract:
            p.error("--expected-contract requires --check-persisted")
        if args.rounds < 1:
            p.error("need at least one measured round")
    for k, v in vars(args).items():
        if isinstance(v, Path):
            setattr(args, k, v.resolve())
    return args


def measure(args, rows):
    token = read_secret_file(args.token_file).strip()
    sonar = Sonar(args.server, token)
    samples = {n: [] for n in rows}
    result = {
        "rule_parameters": PARAMETERS,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "java": subprocess.check_output(
            [args.java, "--version"], text=True
        ).splitlines()[0],
        "sonar_version": sonar.request("/api/system/status")["version"],
        "binary_sha256": {
            k: digest(getattr(args, k)) for k in ("native", "service", "scanner_jar")
        },
        "sources": {
            n: {k: r[k] for k in ("repository", "commit", "tree", "sources", "exclude")}
            for n, r in rows.items()
        },
        "samples": samples,
    }
    with TemporaryDirectory(dir=args.output) as service_dir:
        user_token = secrets.token_urlsafe(40)
        with running_service(args.service, Path(service_dir), user_token) as port:
            for i in range(args.rounds + 1):
                for j, (name, row) in enumerate(rows.items()):
                    root = pinned_checkout(args, name, row)
                    folder = args.output / f"{name}-{i}"
                    folder.mkdir()
                    order = (
                        ("native", "sonar") if (i + j) % 2 == 0 else ("sonar", "native")
                    )
                    record = {"round": i, "measured": i > 0, "order": list(order)}
                    for side in order:
                        record[side] = (
                            reference(args, row, root, folder, sonar, token)
                            if side == "sonar"
                            else native(args, row, root, folder, port, user_token)
                        )
                    compare(
                        name, record["native"]["contract"], record["sonar"]["contract"]
                    )
                    if (
                        samples[name]
                        and samples[name][0]["sonar"]["contract"]
                        != record["sonar"]["contract"]
                    ):
                        raise ValueError("result changed between rounds")
                    samples[name].append(record)
                    write_json_atomic(args.output / "progress.json", result)
                    print(
                        name,
                        i,
                        [record[s]["readable_s"] for s in ("native", "sonar")],
                        flush=True,
                    )
    result["median_readable_s"] = {
        n: {
            s: statistics.median(r[s]["readable_s"] for r in records if r["measured"])
            for s in ("native", "sonar")
        }
        for n, records in samples.items()
    }
    write_json_atomic(args.output / "result.json", result)


def main():
    args = parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    rows = pinned_rows()
    if args.check_persisted:
        check_persisted(args, rows)
    else:
        measure(args, rows)


if __name__ == "__main__":
    main()
