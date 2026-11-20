"""Compare service findings reads using real CLI --assessment reports on loopback."""

import argparse
import hashlib
import json
import secrets
import statistics
import tempfile
import time
from http.client import HTTPConnection
from pathlib import Path

from smoke_cli_service import running_service


def request(port, token, path, body=None):
    connection = HTTPConnection("127.0.0.1", port, timeout=120)
    try:
        connection.request(
            "GET" if body is None else "POST",
            "/api/v1/projects/smoke" + path,
            body=None if body is None else json.dumps(body),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        raw = response.read()
        if response.status != 200:
            raise RuntimeError(f"{path}: HTTP {response.status}: {raw[:160]!r}")
        return raw
    finally:
        connection.close()


def seed(port, token, report):
    """Store the real report plus a replay of the same bytes as a second analysis."""
    context = report["assessment"]["context"]
    if not report["project"]["complete"]:
        raise ValueError("provide a complete CLI --assessment report")
    commits = [
        context.get("source_revision") or "benchmark-original",
        "benchmark-replay",
    ]
    if commits[0] == commits[1]:
        raise ValueError("reserved benchmark replay name is already in use")
    ids = []
    for i, commit in enumerate(commits):
        if i:
            # The replay uses a controlled commit label; do not claim a real second revision.
            context.pop("source_revision", None)
        envelope = {
            "schema_version": 1,
            "branch": "main",
            "commit": commit,
            "analyzed_at": f"2026-01-0{i + 1}T12:00:00Z",
            "report": report,
        }
        raw = request(port, token, "/analyses", envelope)
        ids.append(json.loads(raw)["analysis"]["id"])
    findings = json.loads(request(port, token, f"/analyses/{ids[0]}/findings"))[
        "findings"
    ]
    selected = [f for f in findings if not f["ambiguous"] and f["kind"] == "finding"][
        :12
    ]
    if not selected:
        raise ValueError("the report has no unambiguous reviewable findings")
    for item in selected:
        request(
            port,
            token,
            "/reviews",
            {
                "schema_version": 1,
                "analysis_id": ids[0],
                "identity": item["identity"],
                "kind": "finding",
                "state": "accepted",
                "reason": "benchmark review",
                "expected_version": 0,
            },
        )
    return ids, len(selected)


def measure(port, token, analysis_id, expected_count, iterations):
    path = f"/analyses/{analysis_id}/findings"
    warm = request(port, token, path)
    findings = json.loads(warm)["findings"]
    if sum("review" in f for f in findings) != expected_count:
        raise ValueError(f"{path}: expected {expected_count} reviewed findings")
    samples = []
    for _ in range(iterations):
        begin = time.perf_counter_ns()
        raw = request(port, token, path)
        samples.append((time.perf_counter_ns() - begin) / 1_000_000)
        if raw != warm:
            raise RuntimeError("response changed between readings")
    return hashlib.sha256(warm).hexdigest(), len(findings), samples


def compare(report_path, baseline, candidate, iterations):
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        token = secrets.token_urlsafe(32)
        data = report_path.read_bytes()
        with running_service(baseline, work, token) as port:
            ids, count = seed(port, token, json.loads(data))
        result = {"input_sha256": hashlib.sha256(data).hexdigest(), "reviewed": count}
        # Both optimized binaries open the same database; no writes during timing.
        for label, binary in [
            ("candidate", candidate),
            ("baseline", baseline),
            ("baseline", baseline),
            ("candidate", candidate),
        ]:
            with running_service(binary, work, token) as port:
                for case, analysis_id in zip(("direct", "inherited"), ids, strict=True):
                    digest, size, samples = measure(
                        port, token, analysis_id, count, iterations
                    )
                    row = result.setdefault(
                        case, {"response_sha256": digest, "findings": size}
                    )
                    if row["response_sha256"] != digest:
                        raise RuntimeError(
                            f"{report_path}: different {case} response on {label}"
                        )
                    row.setdefault(label + "_ms", []).extend(samples)
        for case in ("direct", "inherited"):
            for label in ("baseline", "candidate"):
                result[case][label + "_median_ms"] = statistics.median(
                    result[case][label + "_ms"]
                )
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, type=Path)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--iterations", default=11, type=int)
    parser.add_argument("reports", nargs="+", type=Path)
    args = parser.parse_args()
    if args.iterations < 1 or len({p.name for p in args.reports}) != len(args.reports):
        parser.error("use at least one iteration and distinct report filenames")
    results = {
        p.name: compare(
            p,
            args.baseline.resolve(strict=True),
            args.candidate.resolve(strict=True),
            args.iterations,
        )
        for p in args.reports
    }
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
