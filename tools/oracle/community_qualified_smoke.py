"""Check strict gate selection and scanner provenance offline with real binaries."""

import argparse
import json
from pathlib import Path
import tempfile

from community_detector_controls import ROOT
from community_qualified_violations import CONDITIONS, decisions, git, with_service
from community_scm_period import check, scan


def commit(repo):
    git(repo, "add", "--all")
    git(
        repo,
        "-c",
        "user.name=Qualification",
        "-c",
        "user.email=qa@example.invalid",
        "-c",
        "commit.gpgSign=false",
        "commit",
        "-qm",
        "source fixture",
    )


def baseline_controls(cli, repo, paths, opts):
    original = opts[1].read_bytes()
    for reason in ("incomplete", "wrong members"):
        base = json.loads(original)
        if reason == "incomplete":
            base["parity"]["completeness"] = "incomplete"
        else:
            base["parity"]["active_rules"].pop()
        opts[1].write_text(json.dumps(base))
        code, report = scan(cli, repo, paths, *opts)
        check(code == 2, "unqualified baseline did not block: " + reason)
        conds = decisions(
            report["assessment"]["gate"], [("pass", 0), ("unavailable", None)]
        )
        check("baseline scanner" in conds[1]["diagnostic"], "wrong baseline diagnostic")


def scenarios(bin_dir, work):
    go = ROOT / ".oracle/sonar/projects/oracle-go/src"
    repo = work / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    (repo / "app.go").write_bytes((go / "s100_good.go").read_bytes())
    (repo / "ui.js").write_text("export const original = 1;\n")
    commit(repo)
    config = work / "gate.json"
    config.write_text(json.dumps({"schema_version": 1, "conditions": CONDITIONS}))
    cli = bin_dir / "hoonarqube"
    paths = {"go": ["app.go"], "mixed": ["app.go", "ui.js"]}
    opts = {}
    for label, files in paths.items():
        base = work / (label + ".json")
        code, _ = scan(cli, repo, files, "--write-baseline", base)
        check(code == 0, "baseline failed")
        opts[label] = ["--baseline", base, "--quality-gate", config]

    code, clean = scan(cli, repo, paths["go"], *opts["go"])
    passed = ("pass", 0)
    check(code == 0, "clean Go did not pass")
    decisions(clean["assessment"]["gate"], [passed, passed])
    baseline_controls(cli, repo, paths["go"], opts["go"])
    (repo / "app.go").write_bytes((go / "s100_bad.go").read_bytes())
    commit(repo)
    code, mixed = scan(cli, repo, paths["mixed"], *opts["mixed"])
    conds = mixed["assessment"]["gate"]["conditions"]
    check(
        code == 2 and conds[0]["actual"] >= 1, "undetected Go violation in mixed scope"
    )
    blocked = [("fail", conds[0]["actual"]), ("unavailable", None)]
    decisions(mixed["assessment"]["gate"], blocked)
    check(
        "javascript:S7724" in conds[1]["diagnostic"],
        "untouched JavaScript not qualified",
    )
    with_service(
        bin_dir / "hoonarqube-service",
        work,
        {"go_clean": (clean, [passed, passed]), "mixed": (mixed, blocked)},
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bin_dir", type=Path)
    with tempfile.TemporaryDirectory() as tmp:
        scenarios(parser.parse_args().bin_dir.resolve(strict=True), Path(tmp).resolve())
