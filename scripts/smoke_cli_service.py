"""Exercise the CLI and service binaries through their public interfaces."""

import argparse
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
from contextlib import contextmanager
from http.client import HTTPConnection
from pathlib import Path


def request(port, token, path, body=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        connection.request(
            "GET" if body is None else "POST",
            "/api/v1/projects" + path,
            body=None if body is None else json.dumps(body),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise RuntimeError(f"{path}: HTTP {response.status}: {response.read()!r}")
        return json.load(response)
    finally:
        connection.close()


@contextmanager
def running_service(binary, work, token):
    with socket.socket() as available:
        available.bind(("127.0.0.1", 0))
        port = available.getsockname()[1]
    env = {
        **os.environ,
        "HOONARQUBE_SERVICE_BIND": f"127.0.0.1:{port}",
        "HOONARQUBE_SERVICE_DB": str(work / "service.sqlite3"),
        "HOONARQUBE_SERVICE_CREDENTIALS": json.dumps(
            [{"user_id": "smoke", "token": token, "projects": {"smoke": "admin"}}]
        ),
    }
    with subprocess.Popen([binary], cwd=work, env=env) as process:
        try:
            deadline = time.monotonic() + 10
            while True:
                if process.poll() is not None:
                    raise RuntimeError(
                        f"service exited before becoming ready: {process.returncode}"
                    )
                try:
                    request(port, token, "")
                    break
                except ConnectionRefusedError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError(
                            "service did not accept connections within 10 seconds"
                        )
                    time.sleep(0.05)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def smoke(bin_dir, work):
    filename = "sample.py"
    (work / filename).write_text(
        "# TODO add retry logic\nvalue = 1\n", encoding="utf-8"
    )
    report = json.loads(
        subprocess.check_output(
            [
                bin_dir / "hoonarqube",
                "analyze",
                "--profile",
                "sonar-parity",
                "--format",
                "json",
                filename,
            ],
            cwd=work,
            timeout=30,
        )
    )
    if not report["project"]["complete"]:
        raise RuntimeError("fixture scan is incomplete")

    token = secrets.token_urlsafe(32)
    service = bin_dir / "hoonarqube-service"
    analyses = "/smoke/analyses"
    body = {
        "schema_version": 1,
        "branch": "main",
        "commit": "smoke",
        "analyzed_at": "2026-01-01T00:00:00Z",
        "report": report,
    }
    with running_service(service, work, token) as port:
        first = request(port, token, analyses, body)
        if first["idempotent"] or not first["analysis"]["complete"]:
            raise RuntimeError(
                "fresh report was not recorded as a complete new analysis"
            )
        analysis_id = first["analysis"]["id"]

    with running_service(service, work, token) as port:
        detail = f"{analyses}/{analysis_id}"
        if request(port, token, detail)["analysis"]["report"] != report:
            raise RuntimeError("report changed across the service restart")
        findings = request(port, token, detail + "/findings")["findings"]
        if not any(
            f["path"] == filename and f["rule_key"] == "python:S1135" for f in findings
        ):
            raise RuntimeError(
                "expected TODO finding is missing from the service index"
            )
        replay = request(port, token, analyses, body)
        if not replay["idempotent"] or replay["analysis"]["id"] != analysis_id:
            raise RuntimeError("retry did not resolve to the original analysis")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "bin_dir",
        type=Path,
        help="directory containing hoonarqube and hoonarqube-service",
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as directory:
        smoke(args.bin_dir.resolve(strict=True), Path(directory))
    print("CLI report, persisted analysis, finding and idempotent retry verified")
