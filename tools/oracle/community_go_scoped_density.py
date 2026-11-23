"""Validate the narrow overall measure without treating a partial project as complete."""

from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from public_contract import require


def paths(rows, expected):
    """Bind distinct native records to exactly the original indexed paths."""
    require(isinstance(rows, list), "missing file evidence")
    result = {}
    for row in rows:
        path = row["path"]
        require(isinstance(path, str) and path.startswith("./"), "invalid native path")
        key = path[2:]
        require(
            key in expected and key not in result, f"unexpected file evidence: {path}"
        )
        result[key] = row
    require(result.keys() == expected, "missing file evidence")
    return result


def check_go(report, go, limits):
    rows = paths(report["files"], go)
    for p, row in rows.items():
        n = row["metrics"]["lines"]
        require(
            row["language"] == "go" and type(n) is int and n == limits[p],
            f"invalid Go source measurement: {p}",
        )
    return rows


@dataclass(frozen=True)
class Evidence:
    counts: dict
    docker: dict
    denominator: int

    @property
    def go_roots(self):
        return sorted("./" + p for p in self.counts)

    @property
    def numerator(self):
        return sum(self.counts.values())


def primary(case, report, source, limits):
    ref = case["community"]
    indexed = set(ref["indexed_files"])
    go = {p for p in limits if p.endswith(".go")}
    docker = {p for p in limits if PurePosixPath(p).name == "Dockerfile"}
    require(
        go
        and docker
        and go | docker == indexed
        and len(indexed) == len(ref["indexed_files"])
        and docker == set(case["allowed_residual"]["missing_files"]),
        "whole-tree evidence is outside the frozen Go/Docker inventory",
    )

    project = report["project"]
    require(
        project.get("partial_rule_selection") is None
        and project["complete"] is False
        and project["roots"] == ["."]
        and project["duplication"] is None
        and project["duplications"] == [],
        "expected an incomplete project with a separate overall measure",
    )
    scoped = project.get("docker_duplication")
    require(
        isinstance(scoped, dict), "whole-tree Docker duplication evidence unavailable"
    )
    inventory = paths(project["files"], indexed)
    full_go = check_go(report, go, limits)
    counts = {}
    for p, row in paths(scoped["go_files"], go).items():
        inv = inventory[p]
        n = row["duplicated_lines"]
        require(
            type(n) is int
            and 0 <= n <= limits[p]
            and inv["classification"] == "source"
            and inv["status"] == "complete"
            and inv["reason"] is None
            and inv["duplication"] is None
            and inv["metrics"] == full_go[p]["metrics"],
            f"invalid whole-tree Go evidence: {p}",
        )
        counts[p] = n
    total = scoped["go_duplicated_lines"]
    require(
        type(total) is int and total == sum(counts.values()),
        "wrong whole-tree Go total",
    )
    docker_lines = {}
    for p, row in paths(scoped["dockerfiles"], docker).items():
        raw = (source / p).read_bytes()
        lines = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n").count(b"\n") + 1
        inv = inventory[p]
        require(
            type(row["bytes"]) is type(row["lines"]) is int
            and (row["bytes"], row["lines"]) == (len(raw), lines)
            and inv["classification"] == "source"
            and inv["status"] == "unsupported"
            and inv["reason"] == "language is unsupported"
            and inv["metrics"] is None
            and inv["duplication"] is None,
            f"invalid Dockerfile evidence: {p}",
        )
        docker_lines[p] = lines
    require(
        sorted(project["warnings"])
        == sorted(f"./{p}: language is unsupported" for p in docker),
        "unexplained whole-tree warning",
    )
    metrics = project["metrics"]
    go_lines = sum(limits[p] for p in go)
    denominator = go_lines + sum(docker_lines.values())
    require(
        type(metrics["lines"]) is type(metrics["files"]) is int
        and (metrics["lines"], metrics["files"]) == (go_lines, len(go))
        and denominator == ref["lines"],
        "wrong whole-tree denominator",
    )
    return Evidence(counts, docker_lines, denominator)


def verify_line_map(report, evidence, limits, measured, marked):
    go = evidence.counts.keys()
    require(
        measured == go and report["project"].get("partial_rule_selection") is None,
        "incomplete supplemental Go scope",
    )
    source_rows = check_go(report, go, limits)
    inv = paths(report["project"]["files"], go)
    require(
        report["project"]["metrics"]["lines"] == sum(limits[p] for p in go)
        and report["project"]["metrics"]["files"] == len(go),
        "wrong supplemental Go denominator",
    )
    mapped = Counter(p for p, _ in marked)
    for p, row in inv.items():
        n = row["duplication"]["duplicated_lines"]
        require(
            type(n) is int
            and n == mapped[p] == evidence.counts[p]
            and row["classification"] == "source"
            and row["reason"] is None
            and row["metrics"] == source_rows[p]["metrics"],
            f"supplemental locations disagree with whole-tree file evidence: {p}",
        )
