"""Assigned service gate, CLI decision and restart checks for public directory scopes."""

import json
import secrets
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from smoke_cli_service import request, running_service  # noqa: E402


def require(ok, message):
    if not ok:
        raise ValueError(message)


def scan(cli, repo, paths, extra):
    args = [
        cli,
        "analyze",
        *paths,
        "--profile",
        "sonar-parity",
        "--format",
        "json",
        *extra,
    ]
    p = subprocess.run(args, cwd=repo, capture_output=True, timeout=30)
    return p.returncode, json.loads(p.stdout)


def assigned(service, db, policy, rev, cases):
    token = secrets.token_urlsafe(32)
    receipts = {}
    with running_service(service, db, token) as port:
        response = request(
            port,
            token,
            "/smoke/gate-policy",
            {"schema_version": 1, "expected_version": 0, "config": policy},
            method="PUT",
        )
        require(response["policy"]["version"] == 1, "assigned policy version")
        for name, (report, gate, code) in cases.items():
            row = request(
                port,
                token,
                "/smoke/analyses",
                {
                    "schema_version": 1,
                    "branch": name,
                    "commit": rev,
                    "analyzed_at": "2026-11-23T00:00:00Z",
                    "report": report,
                },
            )
            require(
                row["analysis"]["gate_policy_version"] == 1
                and row["analysis"]["gate"] == gate,
                f"{name}: assigned gate",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    ROOT / "scripts/check_project_gate.py",
                    "--project",
                    "smoke",
                    "--branch",
                    name,
                    "--commit",
                    rev,
                ],
                input=json.dumps(row).encode(),
                capture_output=True,
                timeout=15,
            )
            require(
                proc.returncode == code and b"Project gate version" in proc.stdout,
                f"{name}: CI result",
            )
            receipts[name] = row["analysis"]["id"]
    with running_service(service, db, token) as port:
        for name, ident in receipts.items():
            require(
                request(port, token, f"/smoke/analyses/{ident}/gate") == cases[name][1],
                f"{name}: restart changed the decision",
            )
