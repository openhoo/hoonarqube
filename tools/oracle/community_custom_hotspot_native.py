"""Replay native Java and Yjs scans and the native review service against public Git objects."""

import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path

from community_custom_hotspot import (
    ARCHIVE,
    BASE,
    BASE_ID,
    CONTROL,
    CONTROL_HASH,
    HEAD,
    RULE,
    SOURCE,
    SOURCE_HASH,
    load,
    require,
    verify,
)
from community_hotspot_replay import (
    CONDITION,
    check_gate,
    reject,
    request,
    service_clients,
)
from community_scm_period import descriptor, run_case
from public_corpus_prepare import GIT_ENV

YBASE = "3dc67e075bad9760c178f51e0a40083e3aabcf85"
YHEAD = "20913920310f4b1f4dbbd088f3a29b00f1592fe7"
YFILE = "src/SpecHelper.js"
YPINS = {
    YBASE: "78e27a5cb87fcc0505848525df02aa92ed0615867748f8919ab20ffd534fb051",
    YHEAD: "f454e2365014f9ee02e4168f48f905a27803f6fd0dbeccbd1a58cfee9e7ddb39",
}


def git(root, *args):
    return subprocess.check_output(
        ["git", "-c", "core.hooksPath=/dev/null", "-C", root, *args],
        env=GIT_ENV,
        timeout=180,
    )


def clone_at(root, source, base, head, paths):
    git(
        root.parent,
        "clone",
        "--quiet",
        "--no-checkout",
        "--shared",
        "--",
        str(source.resolve(strict=True)),
        str(root),
    )
    require(
        git(root, "rev-parse", "--is-shallow-repository").strip() == b"false",
        "need full local clone",
    )
    require(
        git(root, "rev-parse", head + "^").decode().strip() == base, "wrong Git parents"
    )
    git(root, "sparse-checkout", "init", "--no-cone")
    git(root, "sparse-checkout", "set", "--no-cone", *["/" + p for p in paths])


def source_hash(repo, rev, path):
    return hashlib.sha256(git(repo, "show", rev + ":" + path)).hexdigest()


def unknown(cli, root, args, expected_status, fragment):
    result = subprocess.run(
        [cli, *args], cwd=root, capture_output=True, text=True, timeout=60, check=False
    )
    require(
        result.returncode == expected_status and fragment in result.stderr,
        "custom-profile capability changed",
    )
    return result.returncode


def java_case(cli, source, work, data):
    root = work / "apache"
    work.mkdir()
    clone_at(root, source, BASE, HEAD, [SOURCE, CONTROL])
    require(
        source_hash(root, BASE, CONTROL)
        == source_hash(root, HEAD, CONTROL)
        == CONTROL_HASH
        and source_hash(root, HEAD, SOURCE) == SOURCE_HASH,
        "Apache source differs",
    )
    selection = descriptor(data["head-gate"]["projectStatus"]["period"], BASE_ID, BASE)
    code, report, _ = run_case(
        cli, root, work, [str(Path(SOURCE).parent)], BASE, HEAD, selection, [CONDITION]
    )
    require(
        code == 0
        and {
            m["path"]
            for m in report["project"]["files"]
            if m["classification"] == "source" and m["status"] == "complete"
        }
        == {CONTROL, SOURCE},
        "wrong native Java inventory",
    )
    counted = [
        issue
        for file in report["files"]
        for issue in file["issues"]
        if issue["rule_key"] == RULE
    ]
    require(not counted, "custom Java rule now supported; requalify this comparison")
    result = check_gate(report["assessment"]["gate"], None, "no_value")
    profile = data["custom-profile"]["profiles"][0]["name"]
    return {
        "source": SOURCE,
        "custom_rule_issues": len(counted),
        "native_gate": result,
        "unknown_rule_exit": unknown(
            cli, root, ["rules", "info", RULE], 1, "unknown rule"
        ),
        "unknown_profile_exit": unknown(
            cli, root, ["analyze", SOURCE, "--profile", profile], 2, "unknown profile"
        ),
    }


def yjs_case(cli, source, work):
    root = work / "yjs"
    work.mkdir()
    clone_at(root, source, YBASE, YHEAD, [YFILE])
    require(
        all(source_hash(root, rev, YFILE) == pin for rev, pin in YPINS.items()),
        "Yjs source differs",
    )
    # This independent native test chooses the analysis time itself. It does
    # not claim a Community analysis for Yjs.
    ts = int(git(root, "show", "-s", "--format=%ct", YBASE)) * 1000 + 1000
    selection = {
        "analysis_id": "native-test-selected-yjs-parent",
        "revision": YBASE,
        "timestamp_ms": ts,
    }
    code, report, _ = run_case(
        cli, root, work, [YFILE], YBASE, YHEAD, selection, [CONDITION]
    )
    require(
        code == 1 and [f["path"] for f in report["files"]] == [YFILE],
        "wrong native Yjs inventory",
    )
    check_gate(report["assessment"]["gate"], 0, "fail")
    issues = report["files"][0]["issues"]
    classified = [
        (issues[m["issue_index"]], m["status"])
        for m in report["assessment"]["new_code"]["findings"]
    ]
    require(
        sorted(
            (issue["range"]["start"]["line"], state)
            for issue, state in classified
            if issue["rule_key"] == "javascript:S2245"
        )
        == [(35, "new"), (84, "existing"), (95, "existing"), (114, "existing")],
        "expected one new RNG finding on line 35 and three existing controls",
    )
    return report


def gates(port, reader, route, pct):
    verdict = "pass" if pct == 100 else "fail"
    return {
        "live": check_gate(request(port, reader, route + "/gate"), pct, verdict),
        "historical": check_gate(
            request(port, reader, route)["analysis"]["gate"], 0, "fail"
        ),
    }


def review(port, token, analysis_id, identity, state, version):
    return request(
        port,
        token,
        "/smoke/reviews",
        {
            "schema_version": 1,
            "analysis_id": analysis_id,
            "identity": identity,
            "kind": "hotspot",
            "state": state,
            "reason": "Review of test randomness in the public Yjs test helper",
            "expected_version": version,
        },
    )


def service_case(service, work, report):
    work.mkdir()
    start, ingest, roles = service_clients(service, work)
    with start() as port:
        row = ingest(port, report, "main", YHEAD)
        analysis_id = row["id"]
        route = f"/smoke/analyses/{analysis_id}"
        states = {"initial": gates(port, roles["reader"], route, 0)}
        items = request(port, roles["reader"], route + "/findings")["findings"]
        selected = [
            f
            for f in items
            if f["kind"] == "hotspot"
            and f["rule_key"] == "javascript:S2245"
            and f["path"] == YFILE
            and f["range"]["start"]["line"] == 35
        ]
        require(
            len(selected) == 1 and not selected[0]["ambiguous"],
            "unresolved review identity",
        )
        identity = selected[0]["identity"]
        reject(
            lambda: review(port, roles["reader"], analysis_id, identity, "safe", 0), 403
        )
        states["reader_denied"] = gates(port, roles["reader"], route, 0)
        event = review(port, roles["reviewer"], analysis_id, identity, "safe", 0)[
            "review"
        ]
        require(
            (event["updated_by"], event["version"]) == ("reviewer", 1),
            "wrong review audit",
        )
        reject(
            lambda: review(port, roles["reviewer"], analysis_id, identity, "safe", 0),
            409,
        )
        states["reviewed"] = gates(port, roles["reader"], route, 100)
    with start() as port:
        states["restart"] = gates(port, roles["reader"], route, 100)
        event = review(port, roles["reviewer"], analysis_id, identity, "to_review", 1)[
            "review"
        ]
        require(
            (event["updated_by"], event["version"]) == ("reviewer", 2),
            "wrong reopening audit",
        )
        states["reopened"] = gates(port, roles["reader"], route, 0)
    return states


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("scanner", "service", "apache", "yjs"):
        parser.add_argument("--" + key, type=Path, required=True)
    parser.add_argument(
        "--capture", type=Path, default=Path(__file__).with_name("fixtures") / ARCHIVE
    )
    args = parser.parse_args()
    data = load(args.capture)
    stages = verify(data)
    cli = args.scanner.resolve(strict=True)
    service = args.service.resolve(strict=True)
    with tempfile.TemporaryDirectory() as temp:
        work = Path(temp).resolve(strict=True)
        java = java_case(cli, args.apache, work / "java", data)
        report = yjs_case(cli, args.yjs, work / "js")
        result = service_case(service, work / "service", report)
    print(
        json.dumps(
            {"community_java": stages, "native_java": java, "native_yjs": result},
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
