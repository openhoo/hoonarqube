"""Replay the Community 26.11 Web gate on the complete pinned Haml tree.

Usage: community_web_duplication.py BIN_DIR [--source VERIFIED_EXTRACT] [--one-decimal]
Only source bytes are read; project code and project configuration never execute.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from smoke_cli_service import request, running_service

REF = json.loads((Path(__file__).parent / "fixtures/haml-web-duplication-2611.json").read_bytes())
PROFILE = "community-26.11-web-duplication"
XHTML = "test/haml/results/standard.xhtml"
ERB = "test/haml/erb/standard.erb"
RUBY = "lib/haml.rb"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sources(source):
    spec = REF["blobs"]
    if source:
        names = {p.relative_to(source).as_posix() for p in source.rglob("*") if p.is_file()}
        require(names == set(spec) and not any(p.is_symlink() for p in source.rglob("*")), "input tree differs")
        data = {name: (source / name).read_bytes() for name in names}
    else:
        url = "https://codeload.github.com/haml/haml/tar.gz/" + REF["commit"]
        with urllib.request.urlopen(url, timeout=60) as response:
            raw = response.read(16 * 1024 * 1024 + 1)
        require(len(raw) <= 16 * 1024 * 1024, "unexpected archive size")
        data = {}
        prefix = "haml-" + REF["commit"] + "/"
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for entry in archive:
                if entry.isdir():
                    continue
                name = entry.name.removeprefix(prefix)
                require(entry.name.startswith(prefix) and name in spec and name not in data
                        and entry.isfile() and 0 <= entry.size < 2 * 1024 * 1024, "unexpected member")
                data[name] = archive.extractfile(entry).read()
    require(data.keys() == spec.keys(), "missing public file")
    tree = {}
    for name, content in data.items():
        mode, blob, digest = spec[name]
        require(hashlib.sha256(content).hexdigest() == digest and git_hash("blob", content) == blob, name)
        branch = tree
        for part in Path(name).parts[:-1]:
            branch = branch.setdefault(part, {})
        branch[Path(name).name] = (mode, blob)
    require(tree_hash(tree) == REF["tree"], "Git tree identity differs")
    return data


def git_hash(kind, data):
    return hashlib.sha1(f"{kind} {len(data)}\0".encode() + data).hexdigest()


def tree_hash(nodes):
    body = bytearray()
    for name, value in sorted(nodes.items(), key=lambda kv: kv[0] + ("/" if isinstance(kv[1], dict) else "")):
        mode, digest = ("40000", tree_hash(value)) if isinstance(value, dict) else value
        body.extend(f"{mode} {name}\0".encode() + bytes.fromhex(digest))
    return git_hash("tree", body)


def stage(root, files):
    root.mkdir()
    for name, data in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return root


def invoke(binary, cwd, paths, config, extras=(), profile=PROFILE):
    with tempfile.TemporaryDirectory() as home:
        args = [binary, "analyze", *paths, "--profile", profile, "--format", "json", *extras]
        if config is not None:
            args.extend(["--quality-gate", config])
        run = subprocess.run(args, cwd=cwd, env={"HOME": home, "PATH": home, "LC_ALL": "C"},
                             capture_output=True, timeout=90)
    require(run.stdout.startswith(b"{"), f"invalid scanner output: exit {run.returncode}")
    return run.returncode, json.loads(run.stdout)


def lines(report):
    result = {}
    for group in report["project"]["duplications"]:
        for value in group["occurrences"]:
            result.setdefault(str(Path(value["path"])), set()).update(range(value["start_line"], value["end_line"] + 1))
    return result


def check_reference(report, ref):
    project = report["project"]
    actual = {str(Path(row["path"])): row["metrics"]["lines"] for row in project["files"] if row["status"] == "complete"}
    require(report["schema_version"] == 2 and project["measurement_scope"] == PROFILE
            and project["complete"] and not project["warnings"] and actual == ref["files"], "file inventory differs")
    expected = {p: {line for low, high in ranges for line in range(low, high + 1)}
                for p, ranges in ref["line_ranges"].items()}
    dup = project["duplication"]
    require(lines(report) == expected and project["metrics"]["lines"] == ref["physical_lines"]
            and dup["duplicated_lines"] == ref["duplicated_lines"]
            and f"{dup['duplicated_lines_density']:.1f}" == ref["density"], "per-file duplication differs")


def service_check(bins, tmp, raw, gate, config, expected):
    token = secrets.token_urlsafe(32)
    with running_service(bins / "hoonarqube-service", tmp, token) as port:
        assignment = request(port, token, "/smoke/gate-policy",
                             {"schema_version": 1, "expected_version": 0, "config": config}, method="PUT")
        require(assignment["policy"]["version"] == 1, "incorrect policy assignment")
        row = request(port, token, "/smoke/analyses", {"schema_version": 1, "branch": "main",
                      "commit": REF["commit"], "analyzed_at": "2026-11-23T00:00:00Z", "report": raw})
        if raw["project"]["complete"] and raw["project"]["metrics"]["files"] == 25:
            for mutation in ("wrong-version", "missing-scope", "wrong-family", "incorrect-density"):
                changed = json.loads(json.dumps(raw))
                if mutation == "wrong-version":
                    changed["schema_version"] = 1
                elif mutation == "missing-scope":
                    del changed["project"]["measurement_scope"]
                elif mutation == "wrong-family":
                    changed["files"][0]["language"] = "ruby"
                else:
                    changed["project"]["duplication"]["duplicated_lines_density"] = 50.0
                try:
                    request(port, token, "/smoke/analyses", {"schema_version": 1, "branch": "main",
                            "commit": mutation, "analyzed_at": "2026-11-23T00:00:00Z", "report": changed})
                except RuntimeError as err:
                    require("HTTP 400" in str(err), f"unexpected rejection: {mutation}")
                else:
                    raise ValueError(f"corrupted report accepted: {mutation}")
        require(row["analysis"]["gate_policy_version"] == 1 and row["analysis"]["gate"] == gate, "assigned gate differs")
        proc = subprocess.run([sys.executable, ROOT / "scripts/check_project_gate.py", "--project", "smoke",
                               "--branch", "main", "--commit", REF["commit"],
                               *(["--policy-version","1"] if config["conditions"][0].get("precision")=="one_decimal" else [])],
                              input=json.dumps(row), text=True, capture_output=True, timeout=20)
        require(proc.returncode == expected and "Project gate version 1:" in proc.stdout + proc.stderr,
                "CI helper differs")
    with running_service(bins / "hoonarqube-service", tmp, token) as port:
        again = request(port, token, f"/smoke/analyses/{row['analysis']['id']}/gate")
        require(again == gate, "persisted decision differs")


def run(options):
    bins = options.binary_dir.resolve()
    public = sources(options.source)
    cfg = {"schema_version": 1, "conditions": [{"scope": "overall", "metric": "duplicated_lines_density",
            "operator": "lte", "threshold": 3.0}]}
    if options.one_decimal:
        cfg["conditions"][0]["precision"] = "one_decimal"
    with tempfile.TemporaryDirectory() as work:
        t = Path(work)
        policy = t / "policy.json"
        policy.write_text(json.dumps(cfg))
        whole = stage(t / "whole", public)
        twins = stage(t / "twins", {**{f"{side}/{name}": public[src] for side in ("a", "b")
                          for name, src in (("one.xhtml", XHTML), ("two.erb", ERB))}, RUBY: public[RUBY]})
        one = stage(t / "one", {"view.erb": public[ERB], RUBY: public[RUBY]})
        internal = stage(t / "internal", {"long.xhtml": public[XHTML] + b"\n" + public[XHTML], RUBY: public[RUBY]})
        for label, base, paths, extra in [
                ("whole", whole, ["."], []), ("exclude-xhtml", whole, ["."], ["--exclude", "**/*.xhtml"]),
                ("explicit-erb", one, ["view.erb", RUBY], []), ("public-twins", twins, ["."], []),
                ("internal", internal, ["."], [])]:
            ref = REF["cases"][label]
            rc, scan = invoke(bins / "hoonarqube", base, paths, policy, extra)
            raw_exit, raw = invoke(bins / "hoonarqube", base, paths, None, extra)
            check_reference(scan, ref)
            check_reference(raw, ref)
            expected = 0 if ref["gate"] == "OK" else 1
            gate = scan["assessment"]["gate"]
            require(raw_exit == 0 and rc == expected and gate["status"] == ("pass" if rc == 0 else "fail"),
                    "wrong gate decision")
            if options.one_decimal:
                require(gate["conditions"][0]["actual"] == float(ref["density"]), "wrong precision")
            db = t / ("db-" + label)
            db.mkdir()
            service_check(bins, db, raw, gate, cfg, rc)
            print(label, len(ref["files"]), ref["duplicated_lines"], ref["density"], rc, flush=True)
        # A native Ruby profile still measures the source; this scoped Web profile has no denominator.
        rc, ruby = invoke(bins / "hoonarqube", whole, [RUBY], policy)
        require(rc == 2 and ruby["assessment"]["gate"]["status"] == "unavailable", "Ruby-only scope passed")
        _, native = invoke(bins / "hoonarqube", whole, [RUBY], None, profile="sonar-parity")
        require(any(f["language"] == "ruby" for f in native["files"]), "native Ruby was removed")
        # Every unqualified input and policy is checked independently by the CLI and the assigned service.
        for name, files, extras, mixed in [
                ("other", {"view.erb": public[ERB], "a.py": b"pass\n"}, [], False),
                ("encoding", {"view.erb": b"\xc3\xa9"}, [], False),
                ("binary", {"view.erb": b"abc\x00"}, [], False),
                ("threshold", {"view.erb": public[ERB]}, ["--duplication-min-lines","1"], False),
                ("test", {"view.erb": public[ERB]}, ["--test-include", "**/*.erb"], False),
                ("cpd-exclude", {"view.erb": public[ERB]}, ["--duplication-exclude","**/*.erb"], False),
                ("issues", {"view.erb": public[ERB]}, [], True)]:
            pwd = stage(t / name, files)
            selected = json.loads(json.dumps(cfg))
            if mixed:
                selected["conditions"].append({"scope":"overall","metric":"issues","operator":"lte","threshold":0})
            policy.write_text(json.dumps(selected))
            rc, scan = invoke(bins / "hoonarqube", pwd, ["."], policy, extras)
            _, raw = invoke(bins / "hoonarqube", pwd, ["."], None, extras)
            gate = scan["assessment"]["gate"]
            require(rc == 2 and gate["status"] == "unavailable", name)
            db = t / ("db-" + name)
            db.mkdir()
            service_check(bins, db, raw, gate, selected, rc)
            print(name, "unavailable", rc, flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary_dir", type=Path)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--one-decimal", action="store_true")
    run(parser.parse_args())
