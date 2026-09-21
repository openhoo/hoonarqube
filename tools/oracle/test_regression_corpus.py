"""Acceptance corpus for the public analyzer regressions fixed in #787-#793.

Each ``issue-<N>/`` directory under
``.oracle/sonar/projects/oracle-regressions/`` holds the verbatim minimal
fixture from the linked public issue plus ``expected-findings.jsonl``: the
complete pinned finding multiset the fixed analyzer must emit for that
fixture under the ``sonar-parity`` profile. Rows use the canonical oracle
finding identity ``(rule, file, message, start_line, start_column,
end_line, end_column)`` — the same normalized tuple ``parity.py`` compares
against SonarQube captures — so a regression reappears as an exact
rule/path/range/message mismatch, never as a count-only drift.

Pinned rows cover every emitted finding, including unrelated rules the
fixtures legitimately trigger (for example ``S1451`` license headers and
``csharpsquid`` namespace/static suggestions). For the false-positive
fixtures (#788-#791, #793) the regressed rule is therefore absent from the
pin; for #787 exactly one ``javascript:S5852`` row is pinned; for #792 the
reference-aligned ``S5843`` score stays below the threshold so that rule is
absent. ``issue-791`` pins an empty file because the fixed analyzer emits
no findings at all for it.

No SonarQube reference capture exists for these fixtures and none is
fabricated: this suite compares native output against the pinned
expectations only.
"""

import json
import os
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path


ORACLE_DIR = Path(__file__).resolve().parent
REPO = ORACLE_DIR.parent.parent
CORPUS = REPO / ".oracle" / "sonar" / "projects" / "oracle-regressions"
sys.path.insert(0, str(ORACLE_DIR))

from parity import _finding, hoonarqube_findings, read_jsonl  # noqa: E402
from parity_suite import _native_report_complete  # noqa: E402


# Exact issue -> regressed-rule mapping. The pinned finding multiset is the
# authoritative expectation; this map documents which rule's reappearance or
# disappearance each fixture guards and is asserted explicitly.
REGRESSED_RULES = {
    "issue-787": "javascript:S5852",
    "issue-788": "typescript:S3972",
    "issue-789": "csharpsquid:S1118",
    "issue-790": "typescript:S7060",
    "issue-791": "python:S1226",
    "issue-792": "javascript:S5843",
    "issue-793": "csharpsquid:S2629",
}

# Issues whose post-fix expectation still contains the regressed rule
# (exactly one deduplicated finding); every other issue must not emit it.
EXPECTED_REGRESSED_HITS = {"issue-787": 1}

CATALOG_BY_PREFIX = {
    "csharpsquid": "csharp",
    "go": "go",
    "java": "java",
    "javascript": "javascript",
    "python": "python",
    "ruby": "ruby",
    "rust": "rust",
    "typescript": "typescript",
}

ANALYZE_TIMEOUT_SECONDS = 120


def _executable() -> str:
    configured = os.environ.get("HOONARQUBE_EXECUTABLE")
    if configured:
        path = Path(configured)
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(
                f"HOONARQUBE_EXECUTABLE is not a regular file: {configured}"
            )
        return str(path)
    subprocess.run(
        ["cargo", "build", "-q", "-p", "hoonarqube-cli"],
        cwd=REPO,
        check=True,
    )
    return str(REPO / "target" / "debug" / "hoonarqube")


def _catalog_keys() -> set[str]:
    keys: set[str] = set()
    for language in set(CATALOG_BY_PREFIX.values()):
        catalog = json.loads(
            (REPO / "catalog" / "rules" / f"{language}.json").read_text()
        )
        keys.update(rule["external_key"] for rule in catalog["rules"])
    return keys


def _pinned_findings(issue_dir: Path) -> list[tuple[object, ...]]:
    pin_path = issue_dir / "expected-findings.jsonl"
    rows = read_jsonl(pin_path)
    findings = []
    for index, row in enumerate(rows):
        context = f"{pin_path.name} row {index}"
        if not isinstance(row, dict):
            raise ValueError(f"{context} must be an object")
        findings.append(
            _finding(
                rule=row["rule"],
                file=row["file"],
                message=row["message"],
                range_value=row.get("range"),
                context=context,
                allow_absent_range=False,
            )
        )
    return findings


def _analyze(executable: str, issue_dir: Path) -> dict[str, object]:
    completed = subprocess.run(
        [
            executable,
            "analyze",
            "--profile",
            "sonar-parity",
            "--format",
            "json",
            ".",
        ],
        cwd=issue_dir,
        capture_output=True,
        text=True,
        timeout=ANALYZE_TIMEOUT_SECONDS,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"hoonarqube analyze failed in {issue_dir.name} "
            f"(exit {completed.returncode}): {completed.stderr.strip()}"
        )
    return json.loads(completed.stdout)


def _issue_dirs() -> list[Path]:
    return sorted(
        path
        for path in CORPUS.iterdir()
        if path.is_dir() and path.name.startswith("issue-")
    )


class RegressionCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.executable = _executable()
        cls.catalog_keys = _catalog_keys()

    def test_corpus_covers_every_linked_issue(self):
        issue_names = [path.name for path in _issue_dirs()]
        self.assertEqual(issue_names, sorted(REGRESSED_RULES))
        for issue_dir in _issue_dirs():
            with self.subTest(issue=issue_dir.name):
                self.assertTrue(
                    (issue_dir / "expected-findings.jsonl").is_file(),
                    "missing pinned expectations",
                )
                fixtures = [
                    path.name
                    for path in issue_dir.iterdir()
                    if path.is_file() and path.name != "expected-findings.jsonl"
                ]
                self.assertTrue(fixtures, "missing fixture source")
                pinned = _pinned_findings(issue_dir)
                self.assertEqual(
                    len(pinned),
                    len(set(pinned)),
                    "duplicate pinned finding identity",
                )
                for finding in pinned:
                    rule, file_name = finding[0], finding[1]
                    self.assertIn(rule, self.catalog_keys, rule)
                    self.assertIn(file_name, fixtures, file_name)

    def test_issue_787_single_deduplicated_s5852(self):
        self._assert_issue("issue-787")

    def test_issue_788_no_s3972_on_else_clause(self):
        self._assert_issue("issue-788")

    def test_issue_789_no_s1118_on_instance_class(self):
        self._assert_issue("issue-789")

    def test_issue_790_no_s7060_on_package_import(self):
        self._assert_issue("issue-790")

    def test_issue_791_no_s1226_on_augmented_assignment(self):
        self._assert_issue("issue-791")

    def test_issue_792_no_s5843_at_reference_score(self):
        self._assert_issue("issue-792")

    def test_issue_793_no_s2629_on_constant_template(self):
        self._assert_issue("issue-793")

    def _assert_issue(self, issue_name: str) -> None:
        issue_dir = CORPUS / issue_name
        report = _analyze(self.executable, issue_dir)
        self.assertTrue(
            _native_report_complete(report),
            f"native analysis of {issue_name} is incomplete",
        )
        expected = Counter(_pinned_findings(issue_dir))
        actual = Counter(hoonarqube_findings(report))
        self.assertEqual(
            actual,
            expected,
            f"{issue_name} finding multiset drifted; "
            f"missing={sorted(expected - actual)} "
            f"extra={sorted(actual - expected)}",
        )
        regressed = REGRESSED_RULES[issue_name]
        regressed_hits = sum(
            count for finding, count in actual.items() if finding[0] == regressed
        )
        self.assertEqual(
            regressed_hits,
            EXPECTED_REGRESSED_HITS.get(issue_name, 0),
            f"{issue_name} regressed rule {regressed} emitted "
            f"{regressed_hits} finding(s)",
        )


if __name__ == "__main__":
    unittest.main()
