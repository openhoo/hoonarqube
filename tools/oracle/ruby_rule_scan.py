"""Stage verified public Ruby blobs and require a complete native scan of that scope."""

from collections import Counter
import json
import re
import subprocess

from public_contract import require, safe_path, stage


def pinned_source(case, scratch, local_repo):
    safe_path(case["repository"])
    require(case["repository"].count("/") == 1, "invalid project name")
    for field in ("commit", "tree"):
        require(re.fullmatch("[0-9a-f]{40}", case[field]), f"invalid {field}")
    for path in case["files"]:
        safe_path(path)
    return stage(case, scratch, local_repo)


def analyze(source, files, binary):
    run = subprocess.run(
        [
            binary,
            "analyze",
            *sorted(files),
            "--format",
            "json",
            "--profile",
            "sonar-parity",
        ],
        cwd=source,
        timeout=180,
        capture_output=True,
        check=False,
    )
    if run.returncode:
        detail = run.stderr.decode(errors="replace").strip().splitlines()
        raise ValueError(f"analyzer exit {run.returncode}: " + "; ".join(detail[:4]))
    report = json.loads(run.stdout)
    require(
        report["project"]["complete"] and not report["parity"]["rule_set_violations"],
        "incomplete scan",
    )
    for rows in (report["files"], report["project"]["files"]):
        require(
            Counter(f["path"] for f in rows) == Counter(files.keys()),
            "different file scope",
        )
    return report
