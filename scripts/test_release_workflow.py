"""Release workflow gating contracts.

Evaluates the real `if:` conditions from .github/workflows/release.yml with a
minimal GitHub-expression subset (==, !=, !, &&, dotted identifiers, and
quoted string literals) so dispatch combinations can be asserted offline.
"""

import re
import unittest
from pathlib import Path

WORKFLOW = (
    Path(__file__).resolve().parent.parent / ".github" / "workflows" / "release.yml"
)


def _job_condition(text: str, job_id: str) -> str:
    match = re.search(rf"^  {re.escape(job_id)}:\s*$", text, re.MULTILINE)
    if match is None:
        raise AssertionError(f"job {job_id} not found in release.yml")
    tail = text[match.end() :]
    next_job = re.search(r"^  [a-zA-Z-]+:\s*$", tail, re.MULTILINE)
    body = tail[: next_job.start()] if next_job else tail
    folded = re.search(r"^    if: >-\n((?:      .*\n?)+)", body, re.MULTILINE)
    if folded:
        return " ".join(line.strip() for line in folded.group(1).splitlines())
    inline = re.search(r"^    if: (.+)$", body, re.MULTILINE)
    if inline:
        return inline.group(1).strip()
    raise AssertionError(f"job {job_id} has no if condition")


def _lookup(context: dict, name: str):
    value = context
    for part in name.split("."):
        value = value[part]
    return value


def _clause(clause: str, context: dict) -> bool:
    clause = clause.strip()
    negated = clause.startswith("!")
    if negated:
        clause = clause[1:].strip()
    if " == " in clause:
        left, right = clause.split(" == ", 1)
        result = _term(left, context) == _term(right, context)
    elif " != " in clause:
        left, right = clause.split(" != ", 1)
        result = _term(left, context) != _term(right, context)
    else:
        result = bool(_term(clause, context))
    return not result if negated else result


def _term(term: str, context: dict):
    term = term.strip()
    if term in ("true", "false"):
        return term == "true"
    if len(term) >= 2 and term[0] == term[-1] and term[0] in "'\"":
        return term[1:-1]
    return _lookup(context, term)


def evaluate(condition: str, context: dict) -> bool:
    clauses = condition.split("&&")
    return all(_clause(clause, context) for clause in clauses)


class ReleaseWorkflowGating(unittest.TestCase):
    def setUp(self):
        self.text = WORKFLOW.read_text(encoding="utf-8")

    def test_rebuild_assets_skips_dry_run_dispatches(self):
        condition = _job_condition(self.text, "rebuild-assets")
        self.assertIn("!inputs.dry_run", condition)
        base = {
            "github": {
                "event_name": "workflow_dispatch",
                "ref_name": "main",
            },
            "inputs": {"tag": "v0.8.2", "dry_run": True},
        }
        self.assertFalse(evaluate(condition, base))
        dry_run_disabled = {
            "github": base["github"],
            "inputs": {"tag": "v0.8.2", "dry_run": False},
        }
        self.assertTrue(evaluate(condition, dry_run_disabled))
        no_tag = {
            "github": base["github"],
            "inputs": {"tag": "", "dry_run": False},
        }
        self.assertFalse(evaluate(condition, no_tag))

    def test_rebuild_assets_still_uploads_assets_for_real_rebuilds(self):
        condition = _job_condition(self.text, "rebuild-assets")
        self.assertIn("gh release upload", self.text)
        job = self.text[self.text.index("  rebuild-assets:") :]
        job = job[: job.index("\njobs:") if "\njobs:" in job else len(job)]
        self.assertRegex(job, r"Upload release assets")


if __name__ == "__main__":
    unittest.main()
