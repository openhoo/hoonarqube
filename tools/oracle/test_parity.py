import os
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

from parity import (
    build_hoonarqube_security_evidence,
    canonical_sonar_issue,
    canonical_sonar_security_issue,
    classify_sq_misses,
    compare_reports,
    compare_security_evidence,
    counts,
    failure_count,
    input_paths_sha256,
    parse_report_task,
    read_json,
    read_secret_file,
    validate_oracle_report,
    validate_search_page,
    validate_security_evidence,
    wait_for_compute_engine,
    write_json_atomic,
)


RULE = "python:S112"
BAD = "s112_bad.py"
GOOD = "s112_good.py"
MESSAGE = "Replace this generic exception class with a more specific one."


def oracle_issue(
    *, file=BAD, line=1, column=10, end_column=21, message=MESSAGE, rule=RULE
):
    return {
        "rule": rule,
        "file": file,
        "message": message,
        "range": {
            "start": {"line": line, "column": column},
            "end": {"line": line, "column": end_column},
        },
    }


def ours_issue(**overrides):
    issue = oracle_issue(**overrides)
    return {
        "rule_key": issue["rule"],
        "message": issue["message"],
        "range": issue["range"],
    }


def oracle_report(*issues):
    return {"schema_version": 2, "issues": list(issues)}


def ours_report(*issues, file=BAD):
    return {"files": [{"path": f"/fixture/{file}", "issues": list(issues)}]}


def security_finding(
    *,
    rule=RULE,
    file="src/security.py",
    message="unsafe input",
    kind="VULNERABILITY",
    line=1,
    flow_locations=None,
    secondary_locations=None,
    status="OPEN",
    resolution=None,
    assignee=None,
    flow_available=True,
    secondary_available=True,
    primary_range_available=True,
):
    range_value = {
        "start": {"line": line, "column": 0},
        "end": {"line": line, "column": 4},
    }
    flow_locations = [] if flow_locations is None else flow_locations
    secondary_locations = [] if secondary_locations is None else secondary_locations
    return {
        "rule": rule,
        "file": file,
        "message": message,
        "range": range_value,
        "detector": {
            "kind": kind,
            "flows": flow_locations,
            "secondary_locations": secondary_locations,
            "flow_evidence_available": flow_available,
            "secondary_location_evidence_available": secondary_available,
            "primary_range_evidence_available": primary_range_available,
        },
        "review": {
            "status": status,
            "resolution": resolution,
            "assignee": assignee,
            "available": True,
        },
    }


def security_report(*findings, project="oracle-py", source="test", edition="community"):
    return {
        "schema_version": 1,
        "project": project,
        "source": source,
        "edition": edition,
        "findings": list(findings),
        "limits": [],
    }


def expectation(**overrides):
    row = {"key": RULE, "bad": BAD, "good": GOOD, "expect_lines_min": 1}
    row.update(overrides)
    return row


class StrictParityTests(unittest.TestCase):
    def test_upstream_unverified_still_requires_our_bad_and_clean_good(self):
        expected = [
            {
                "key": "rust:S1",
                "bad": "s1_bad.rs",
                "upstream_unverified": "current upstream lint id is incompatible",
            }
        ]
        ours = ours_report(
            ours_issue(rule="rust:S1", file="s1_bad.rs", message="ours"),
            file="s1_bad.rs",
        )
        rows = compare_reports(expected, oracle_report(), ours)
        self.assertEqual(rows[0]["status"], "UPSTREAM_UNVERIFIED")
        self.assertEqual(failure_count(rows), 0)

        missed = compare_reports(
            expected, oracle_report(), ours_report(file="s1_bad.rs")
        )
        self.assertEqual(missed[0]["status"], "OURS_MISS")
        self.assertEqual(failure_count(missed), 1)

        malformed = compare_reports(
            [
                {
                    "key": "rust:S1",
                    "bad": "s1_bad.rs",
                    "upstream_unverified": True,
                }
            ],
            oracle_report(),
            ours,
        )
        self.assertEqual(malformed[0]["status"], "INVALID_EXPECTATION")
        self.assertEqual(failure_count(malformed), 1)

    def compare(self, expected, sonar, ours, infra=None):
        return compare_reports(expected, sonar, ours, infra)

    def test_incomplete_native_report_cannot_pass_matching_findings(self):
        ours = ours_report(ours_issue())
        ours["schema_version"] = 1
        ours["project"] = {
            "complete": False,
            "warnings": ["source inventory failed"],
        }
        rows = self.compare(
            [expectation()],
            oracle_report(oracle_issue()),
            ours,
        )
        self.assertEqual(rows[0]["observed_status"], "PASS")
        self.assertEqual(rows[0]["status"], "ORACLE_UNVERIFIED")
        self.assertEqual(rows[0]["native_status"], "INCOMPLETE")
        self.assertEqual(rows[0]["native_complete"], False)
        self.assertEqual(
            rows[0]["reason"],
            "native project analysis is incomplete: source inventory failed",
        )
        self.assertEqual(rows[0]["ours_bad"], rows[0]["sonar_bad"])
        self.assertEqual(failure_count(rows), 1)

    def test_incomplete_empty_native_report_is_not_zero_finding_pass(self):
        ours = {
            "schema_version": 1,
            "files": [],
            "project": {
                "complete": False,
                "warnings": ["no source files could be analyzed"],
            },
        }
        rows = self.compare([expectation()], oracle_report(), ours)
        self.assertEqual(rows[0]["status"], "ORACLE_UNVERIFIED")
        self.assertEqual(rows[0]["observed_status"], "BOTH_MISS")
        self.assertEqual(failure_count(rows), 1)

    def test_exact_finding_multiset_passes(self):
        rows = self.compare(
            [expectation()], oracle_report(oracle_issue()), ours_report(ours_issue())
        )
        self.assertEqual(rows[0]["status"], "PASS")
        self.assertEqual(counts(rows), {"PASS": 1})
        self.assertEqual(failure_count(rows), 0)

    def test_different_location_fails_even_when_both_sides_meet_minimum(self):
        rows = self.compare(
            [expectation()],
            oracle_report(oracle_issue(line=1)),
            ours_report(ours_issue(line=2)),
        )
        self.assertEqual(rows[0]["status"], "BAD_MISMATCH")
        self.assertEqual(failure_count(rows), 1)

    def test_different_message_fails(self):
        rows = self.compare(
            [expectation()],
            oracle_report(oracle_issue()),
            ours_report(ours_issue(message="Different message")),
        )
        self.assertEqual(rows[0]["status"], "BAD_MISMATCH")

    def test_extra_bad_finding_fails(self):
        rows = self.compare(
            [expectation()],
            oracle_report(oracle_issue()),
            ours_report(ours_issue(), ours_issue(line=2)),
        )
        self.assertEqual(rows[0]["status"], "BAD_MISMATCH")

    def test_incidental_findings_are_part_of_exact_rule_comparison(self):
        incidental = "s999_bad.py"
        ours = {
            "files": [
                {"path": BAD, "issues": [ours_issue()]},
                {"path": incidental, "issues": [ours_issue()]},
            ]
        }
        rows = compare_reports(
            [expectation()],
            oracle_report(oracle_issue()),
            ours,
            catalog_keys=[RULE],
            available_files=[BAD, GOOD, incidental],
        )
        self.assertEqual(rows[0]["status"], "BAD_MISMATCH")
        self.assertEqual(rows[0]["ours_other"][0]["message"], MESSAGE)

    def test_uncontracted_rules_and_unknown_files_are_invalid_artifacts(self):
        rows = compare_reports(
            [expectation()],
            oracle_report(
                oracle_issue(rule="python:S999"), oracle_issue(file="unknown.py")
            ),
            ours_report(),
            catalog_keys=[RULE],
            available_files=[BAD, GOOD],
        )
        invalid = [row for row in rows if row["status"] == "INVALID_ARTIFACT"]
        self.assertEqual(len(invalid), 2)
        self.assertTrue(
            any("absent from oracle contract" in row["reason"] for row in invalid)
        )
        self.assertTrue(any("unknown fixture" in row["reason"] for row in invalid))

    def test_each_missing_side_and_both_missing_are_distinct_failures(self):
        ours_missing = self.compare(
            [expectation()], oracle_report(oracle_issue()), ours_report()
        )
        sonar_missing = self.compare(
            [expectation()], oracle_report(), ours_report(ours_issue())
        )
        both_missing = self.compare([expectation()], oracle_report(), ours_report())
        self.assertEqual(ours_missing[0]["status"], "OURS_MISS")
        self.assertEqual(sonar_missing[0]["status"], "SQ_MISS")
        self.assertEqual(both_missing[0]["status"], "BOTH_MISS")
        self.assertEqual(failure_count(ours_missing + sonar_missing + both_missing), 3)

    def test_enterprise_rules_require_local_evidence_but_never_pass_community_oracle(
        self,
    ):
        rows = compare_reports(
            [expectation()],
            oracle_report(),
            ours_report(ours_issue()),
            enterprise_unverified={RULE},
        )
        self.assertEqual(rows[0]["status"], "ENTERPRISE_UNVERIFIED")
        self.assertEqual(failure_count(rows), 0)

        local_miss = compare_reports(
            [expectation()],
            oracle_report(),
            ours_report(),
            enterprise_unverified={RULE},
        )
        self.assertEqual(local_miss[0]["status"], "OURS_MISS")

    def test_positive_oracle_and_local_good_control_findings_fail(self):
        sonar_good = self.compare(
            [expectation()],
            oracle_report(oracle_issue(), oracle_issue(file=GOOD)),
            ours_report(ours_issue()),
        )
        ours_good = {
            "files": [
                {"path": f"/fixture/{BAD}", "issues": [ours_issue()]},
                {"path": f"/fixture/{GOOD}", "issues": [ours_issue()]},
            ]
        }
        local_good = self.compare(
            [expectation()], oracle_report(oracle_issue()), ours_good
        )
        self.assertEqual(sonar_good[0]["status"], "GOOD_FIRE")
        self.assertEqual(local_good[0]["status"], "GOOD_FIRE")

    def test_skip_and_infra_are_explicit_fail_closed_gaps(self):
        reason = "GraphQL semantic model unavailable"
        rows = self.compare(
            [
                expectation(skip="config"),
                expectation(key="python:S6786", infra=reason),
            ],
            oracle_report(),
            ours_report(),
            infra={"python:S6786": reason},
        )
        self.assertEqual([row["status"] for row in rows], ["SKIPPED", "INFRA"])
        self.assertEqual(failure_count(rows), 2)

    def test_infra_self_classification_requires_exact_central_approval(self):
        declared = expectation(infra="invented exception")
        unapproved = self.compare([declared], oracle_report(), ours_report())
        self.assertEqual(unapproved[0]["status"], "INVALID_EXPECTATION")
        self.assertIn("unapproved", unapproved[0]["reason"])

        mismatched = self.compare(
            [declared],
            oracle_report(),
            ours_report(),
            infra={RULE: "approved reason"},
        )
        self.assertEqual(mismatched[0]["status"], "INVALID_EXPECTATION")
        self.assertIn("does not match", mismatched[0]["reason"])

        malformed = self.compare(
            [expectation(infra=True)],
            oracle_report(),
            ours_report(),
            infra={RULE: "approved reason"},
        )
        self.assertEqual(malformed[0]["status"], "INVALID_EXPECTATION")

    def test_duplicate_and_malformed_expectations_fail(self):
        rows = self.compare(
            [
                expectation(),
                expectation(),
                {"bad": BAD},
                expectation(key="python:S113", bad="x.py", good="x.py"),
            ],
            oracle_report(oracle_issue()),
            ours_report(ours_issue()),
        )
        self.assertEqual(rows[0]["status"], "PASS")
        self.assertEqual(
            [row["status"] for row in rows[1:]],
            [
                "INVALID_EXPECTATION",
                "INVALID_EXPECTATION",
                "INVALID_EXPECTATION",
            ],
        )

    def test_catalog_and_fixture_contract_fails_closed(self):
        rows = compare_reports(
            [expectation(), expectation(key="python:extra")],
            oracle_report(oracle_issue()),
            ours_report(ours_issue()),
            catalog_keys={RULE, "python:missing"},
            available_files={BAD},
        )
        self.assertEqual(
            [(row["key"], row["status"], row.get("reason")) for row in rows],
            [
                (RULE, "INVALID_EXPECTATION", f"good fixture does not exist: {GOOD}"),
                (
                    "python:extra",
                    "INVALID_EXPECTATION",
                    "expectation key is absent from frozen catalog",
                ),
                (
                    "python:missing",
                    "INVALID_EXPECTATION",
                    "catalog key has no oracle expectation",
                ),
            ],
        )
        self.assertEqual(failure_count(rows), 3)

    def test_legacy_line_only_artifacts_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "schema 2 required"):
            validate_oracle_report([{"rule": RULE, "file": BAD, "line": 1}])

    def test_oracle_project_identity_is_checked_when_expected(self):
        report = {"schema_version": 2, "project": "oracle-py", "issues": []}
        self.assertEqual(
            validate_oracle_report(report, expected_project="oracle-py"), []
        )
        with self.assertRaisesRegex(ValueError, "project must be 'oracle-js'"):
            validate_oracle_report(report, expected_project="oracle-js")

    def test_search_page_validation_rejects_truncated_or_unstable_evidence(self):
        first = {
            "issues": [{"key": "one"}],
            "paging": {"pageIndex": 1, "pageSize": 1, "total": 2},
        }
        self.assertEqual(
            validate_search_page(first, "issues", 1),
            (first["issues"], 2, 1, False),
        )
        with self.assertRaisesRegex(ValueError, "returned 0 items, expected 1"):
            validate_search_page(
                {
                    "issues": [],
                    "paging": {"pageIndex": 2, "pageSize": 1, "total": 2},
                },
                "issues",
                2,
                expected_total=2,
                expected_page_size=1,
            )
        with self.assertRaisesRegex(ValueError, "pageSize must be positive"):
            validate_search_page(
                {
                    "issues": [],
                    "paging": {"pageIndex": 1, "pageSize": 0, "total": 0},
                },
                "issues",
                1,
            )
        with self.assertRaisesRegex(ValueError, "item 0 must be an object"):
            validate_search_page(
                {
                    "issues": ["not-an-object"],
                    "paging": {"pageIndex": 1, "pageSize": 1, "total": 1},
                },
                "issues",
                1,
            )
        with self.assertRaisesRegex(ValueError, "total changed"):
            validate_search_page(
                {
                    "issues": [{"key": "two"}],
                    "paging": {"pageIndex": 2, "pageSize": 1, "total": 3},
                },
                "issues",
                2,
                expected_total=2,
                expected_page_size=1,
            )
        for page in (0, -1, True):
            with (
                self.subTest(page=page),
                self.assertRaisesRegex(ValueError, "positive integer"),
            ):
                validate_search_page({}, "issues", page)

    def test_search_page_rejects_missing_or_duplicate_issue_identity(self):
        for items in [
            [{}],
            [{"key": ""}],
            [{"key": 7}],
            [{"key": "same"}, {"key": "same"}],
        ]:
            with self.subTest(items=items), self.assertRaisesRegex(ValueError, "key"):
                validate_search_page(
                    {
                        "issues": items,
                        "paging": {
                            "pageIndex": 1,
                            "pageSize": len(items),
                            "total": len(items),
                        },
                    },
                    "issues",
                    1,
                )

    def test_search_page_keeps_distinct_ids_and_rejects_without_mutating_seen_keys(
        self,
    ):
        seen = {"existing"}
        items = [{"key": "fresh"}, {"key": "existing"}]
        payload = {
            "issues": items,
            "paging": {"pageIndex": 1, "pageSize": 2, "total": 2},
        }
        with self.assertRaisesRegex(ValueError, "duplicate.*key"):
            validate_search_page(payload, "issues", 1, seen_keys=seen)
        self.assertEqual(seen, {"existing"})
        items[1] = {"key": "another"}
        self.assertEqual(
            validate_search_page(payload, "issues", 1, seen_keys=seen)[0], items
        )
        self.assertEqual(seen, {"existing", "fresh", "another"})

    def test_malformed_findings_and_ranges_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "oracle issue 0 must be an object"):
            compare_reports(
                [expectation()], oracle_report("not-an-issue"), ours_report()
            )
        malformed_range = oracle_issue()
        malformed_range["range"] = {"start": {"line": 1, "column": "10"}}
        with self.assertRaisesRegex(ValueError, "start and end objects"):
            compare_reports(
                [expectation()], oracle_report(malformed_range), ours_report()
            )
        malformed_local = ours_issue()
        malformed_local["rule_key"] = None
        with self.assertRaisesRegex(ValueError, "rule_key must be a string"):
            compare_reports(
                [expectation()], oracle_report(), ours_report(malformed_local)
            )
        partial_range = oracle_issue()
        partial_range["range"]["end"]["column"] = None
        with self.assertRaisesRegex(ValueError, "complete or file-level"):
            compare_reports(
                [expectation()], oracle_report(partial_range), ours_report()
            )
        inverted_range = oracle_issue(line=2)
        inverted_range["range"]["end"]["line"] = 1
        with self.assertRaisesRegex(ValueError, "ends before it starts"):
            compare_reports(
                [expectation()], oracle_report(inverted_range), ours_report()
            )

    def test_duplicate_fixture_names_and_non_object_expectations_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "duplicate available fixture"):
            compare_reports(
                [expectation()],
                oracle_report(),
                ours_report(),
                available_files=[BAD, BAD],
            )
        rows = compare_reports(["not-an-expectation"], oracle_report(), ours_report())
        self.assertEqual(rows[0]["status"], "INVALID_EXPECTATION")
        self.assertEqual(rows[0]["reason"], "expectation must be an object")

    def test_local_report_rejects_duplicate_paths_and_basename_collisions(self):
        duplicate = {
            "files": [
                {"path": "/fixtures/a.py", "issues": []},
                {"path": "/fixtures/a.py", "issues": []},
            ]
        }
        collision = {
            "files": [
                {"path": "/one/a.py", "issues": []},
                {"path": "/two/a.py", "issues": []},
            ]
        }
        with self.assertRaisesRegex(ValueError, "duplicate hoonarqube"):
            compare_reports([expectation()], oracle_report(), duplicate)
        with self.assertRaisesRegex(ValueError, "basename collision"):
            compare_reports([expectation()], oracle_report(), collision)

    def test_sonar_api_issue_normalization_is_strict(self):
        issue = {
            "rule": RULE,
            "component": "oracle-py:src/s112_bad.py",
            "message": MESSAGE,
            "textRange": {
                "startLine": 2,
                "startOffset": 3,
                "endLine": 2,
                "endOffset": 8,
            },
        }
        normalized = canonical_sonar_issue(
            issue, hotspot=False, expected_project="oracle-py"
        )
        self.assertEqual(normalized["file"], BAD)
        with self.assertRaisesRegex(ValueError, "line-only"):
            canonical_sonar_issue(
                {**issue, "textRange": None, "line": 2}, hotspot=False
            )
        with self.assertRaisesRegex(ValueError, "message"):
            canonical_sonar_issue(
                {key: value for key, value in issue.items() if key != "message"},
                hotspot=False,
            )

    def test_strict_json_io_rejects_nonstandard_constants_and_writes_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact.json"
            path.write_text('{"value": NaN}\n')
            with self.assertRaisesRegex(ValueError, "non-standard JSON"):
                read_json(path)
            path.write_text('{"value": 1, "value": 2}\n')
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                read_json(path)
            write_json_atomic(path, {"value": 1}, indent=1)
            self.assertEqual(read_json(path), {"value": 1})
            self.assertEqual(list(Path(directory).glob("*.tmp")), [])

    @unittest.skipUnless(os.name == "posix", "POSIX permission contract")
    def test_secret_files_reject_broad_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = root / "token"
            token.write_text("secret\n")
            token.chmod(0o600)
            self.assertEqual(read_secret_file(token), "secret\n")

            token.chmod(0o640)
            with self.assertRaisesRegex(RuntimeError, "group/other access"):
                read_secret_file(token)

            token.chmod(0o600)
            link = root / "token-link"
            link.symlink_to(token)
            with self.assertRaisesRegex(RuntimeError, "securely open"):
                read_secret_file(link)

    def test_input_fingerprint_is_order_stable_and_rejects_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.txt"
            second = root / "second.txt"
            first.write_text("one")
            second.write_text("two")
            self.assertEqual(
                input_paths_sha256(root, [first, second]),
                input_paths_sha256(root, [second, first]),
            )
            link = root / "link.txt"
            link.symlink_to(first)
            with self.assertRaisesRegex(ValueError, "must not be a symlink"):
                input_paths_sha256(root, [link])

    def test_file_level_zero_sentinel_matches_absent_sonar_range(self):
        sonar = oracle_report(
            {
                "rule": RULE,
                "file": BAD,
                "message": MESSAGE,
                "range": None,
            }
        )
        ours = ours_report(
            {
                "rule_key": RULE,
                "message": MESSAGE,
                "range": {
                    "start": {"line": 0, "column": 0},
                    "end": {"line": 0, "column": 0},
                },
            }
        )
        rows = self.compare([expectation()], sonar, ours)
        self.assertEqual(rows[0]["status"], "PASS")

    def test_sq_miss_availability_classification_uses_gate_status_names(self):
        rows = [
            {"key": "python:absent", "status": "SQ_MISS"},
            {"key": "python:absent-both", "status": "BOTH_MISS"},
            {"key": "python:present", "status": "SQ_MISS"},
            {"key": "python:present-both", "status": "BOTH_MISS"},
            {"key": "python:unknown", "status": "SQ_MISS"},
            {"key": "python:unknown-both", "status": "BOTH_MISS"},
            {"key": "python:other", "status": "OURS_MISS"},
        ]
        availability = {
            "python:absent": False,
            "python:absent-both": False,
            "python:present": True,
            "python:present-both": True,
            "python:unknown": None,
            "python:unknown-both": None,
        }

        beyond, unknown = classify_sq_misses(rows, availability.get)

        self.assertEqual(beyond, ["python:absent", "python:absent-both"])
        self.assertEqual(unknown, ["python:unknown", "python:unknown-both"])
        self.assertEqual(
            [row["status"] for row in rows],
            [
                "BEYOND_CE",
                "BEYOND_CE",
                "SQ_MISS",
                "BOTH_MISS",
                "ORACLE_UNVERIFIED",
                "ORACLE_UNVERIFIED",
                "OURS_MISS",
            ],
        )
        self.assertEqual(failure_count(rows), 7)

    def test_security_detector_evidence_compares_kind_flows_ranges_and_duplicates(self):
        location = {
            "file": "src/input.py",
            "message": "source",
            "range": {
                "start": {"line": 2, "column": 0},
                "end": {"line": 2, "column": 4},
            },
        }
        secondary = {
            "file": "src/sink.py",
            "message": "sink",
            "range": {
                "start": {"line": 8, "column": 1},
                "end": {"line": 8, "column": 5},
            },
        }
        finding = security_finding(
            flow_locations=[[location]],
            secondary_locations=[secondary],
        )
        self.assertEqual(
            compare_security_evidence(
                security_report(finding),
                security_report(finding),
                expected_project="oracle-py",
            )["status"],
            "PASS",
        )
        for changed in (
            {
                **finding,
                "detector": {**finding["detector"], "kind": "SECURITY_HOTSPOT"},
            },
            {
                **finding,
                "detector": {
                    **finding["detector"],
                    "flows": [
                        [
                            {
                                **location,
                                "range": {
                                    **location["range"],
                                    "end": {"line": 3, "column": 4},
                                },
                            }
                        ]
                    ],
                },
            },
            {
                **finding,
                "detector": {
                    **finding["detector"],
                    "secondary_locations": [
                        secondary,
                        {**secondary, "file": "src/other.py"},
                    ],
                },
            },
            {
                **finding,
                "range": {
                    **finding["range"],
                    "start": {"line": 4, "column": 0},
                    "end": {"line": 4, "column": 4},
                },
            },
        ):
            with self.subTest(changed=changed):
                result = compare_security_evidence(
                    security_report(finding),
                    security_report(changed),
                    expected_project="oracle-py",
                )
                self.assertEqual(result["status"], "BAD_MISMATCH")
        duplicate = compare_security_evidence(
            security_report(finding, finding),
            security_report(finding),
            expected_project="oracle-py",
        )
        self.assertEqual(duplicate["status"], "BAD_MISMATCH")
        self.assertEqual(duplicate["detector"]["missing"][0]["count"], 1)

    def test_security_availability_metadata_does_not_create_detector_mismatch(self):
        sonar = security_finding(flow_available=False, secondary_available=False)
        ours = security_finding(flow_available=True, secondary_available=False)
        result = compare_security_evidence(
            security_report(sonar),
            security_report(ours),
            expected_project="oracle-py",
        )
        self.assertEqual(result["status"], "SECURITY_EVIDENCE_UNAVAILABLE")
        self.assertEqual(result["detector"]["missing"], [])
        self.assertEqual(result["detector"]["extra"], [])

    def test_security_known_flow_mismatch_stays_bad_with_other_evidence_unavailable(
        self,
    ):
        source = {
            "file": "src/input.py",
            "message": "source",
            "range": {
                "start": {"line": 2, "column": 0},
                "end": {"line": 2, "column": 4},
            },
        }
        sonar = security_finding(
            flow_locations=[[source]],
            flow_available=True,
            secondary_available=False,
            primary_range_available=False,
        )
        sonar["range"] = None
        ours_source = {**source, "message": "different source"}
        ours = security_finding(
            flow_locations=[[ours_source]],
            flow_available=True,
            secondary_available=False,
            primary_range_available=False,
        )
        ours["range"] = None
        result = compare_security_evidence(
            security_report(sonar),
            security_report(ours),
            expected_project="oracle-py",
        )
        self.assertEqual(result["status"], "BAD_MISMATCH")
        self.assertEqual(result["detector"]["missing"][0]["count"], 1)
        self.assertEqual(result["detector"]["extra"][0]["count"], 1)

    def test_security_wildcard_matching_reassigns_ambiguous_rows(self):
        source_a = {
            "file": "src/input.py",
            "message": "source A",
            "range": {
                "start": {"line": 2, "column": 0},
                "end": {"line": 2, "column": 4},
            },
        }
        source_b = {**source_a, "message": "source B"}
        sonar = [
            security_finding(
                flow_locations=[[source_a]],
                flow_available=True,
                secondary_available=False,
            ),
            security_finding(flow_available=False, secondary_available=False),
        ]
        ours = [
            security_finding(
                flow_locations=[[source_b]],
                flow_available=True,
                secondary_available=False,
            ),
            security_finding(flow_available=False, secondary_available=False),
        ]
        result = compare_security_evidence(
            security_report(*sonar),
            security_report(*ours),
            expected_project="oracle-py",
        )
        self.assertEqual(result["status"], "SECURITY_EVIDENCE_UNAVAILABLE")
        self.assertEqual(result["detector"]["missing"], [])
        self.assertEqual(result["detector"]["extra"], [])

    def test_security_flow_without_location_message_is_explicitly_unavailable(self):
        issue = {
            "rule": "python:S2077",
            "ruleKey": "python:S2077",
            "type": "VULNERABILITY",
            "component": "oracle-py:src/input.py",
            "message": "Make sure that formatting this SQL query is safe here.",
            "textRange": {
                "startLine": 4,
                "endLine": 4,
                "startOffset": 4,
                "endOffset": 39,
            },
            "flows": [
                {
                    "locations": [
                        {
                            "component": "oracle-py:src/input.py",
                            "textRange": {
                                "startLine": 4,
                                "endLine": 4,
                                "startOffset": 19,
                                "endOffset": 38,
                            },
                            "msgFormattings": [],
                        }
                    ]
                }
            ],
            "status": "OPEN",
            "resolution": None,
            "assignee": None,
        }
        evidence = canonical_sonar_security_issue(
            issue, hotspot=False, expected_project="oracle-py"
        )
        self.assertEqual(evidence["range"]["start"], {"line": 4, "column": 4})
        self.assertEqual(evidence["detector"]["flows"], [])
        self.assertFalse(evidence["detector"]["flow_evidence_available"])
        malformed = {
            **issue,
            "flows": [
                {
                    "locations": [
                        {
                            **issue["flows"][0]["locations"][0],
                            "msg": "source",
                            "textRange": {
                                "startLine": 0,
                                "startOffset": 0,
                                "endLine": 1,
                                "endOffset": 1,
                            },
                        }
                    ]
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "text range lines must be positive"):
            canonical_sonar_security_issue(
                malformed, hotspot=False, expected_project="oracle-py"
            )

    def test_security_review_state_is_exposed_but_not_detector_equality(self):
        finding = security_finding(status="OPEN", resolution=None, assignee=None)
        reviewed = security_finding(
            status="RESOLVED", resolution="FIXED", assignee="reviewer"
        )
        result = compare_security_evidence(
            security_report(finding),
            security_report(reviewed),
            expected_project="oracle-py",
        )
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["review"]["ours"][0]["review"]["status"], "RESOLVED")
        self.assertEqual(result["review"]["ours"][0]["review"]["assignee"], "reviewer")

    def test_security_evidence_rejects_missing_fields_and_project_mismatch(self):
        finding = security_finding()
        malformed = security_report(finding)
        del malformed["findings"][0]["detector"]["flows"]
        with self.assertRaisesRegex(ValueError, "detector missing fields.*flows"):
            validate_security_evidence(malformed, expected_project="oracle-py")
        with self.assertRaisesRegex(ValueError, "project must be 'oracle-py'"):
            validate_security_evidence(
                security_report(finding, project="other-project"),
                expected_project="oracle-py",
            )

    def test_security_paths_are_project_relative_not_basename_only(self):
        first = security_finding(file="src/one/security.py")
        second = security_finding(file="src/two/security.py")
        result = compare_security_evidence(
            security_report(first, second),
            security_report(security_finding(file="security.py")),
            expected_project="oracle-py",
        )
        self.assertEqual(result["status"], "BAD_MISMATCH")
        self.assertEqual(len(result["detector"]["missing"]), 2)

    def test_unavailable_security_evidence_never_becomes_pass(self):
        finding = security_finding(
            flow_available=False,
            secondary_available=False,
            primary_range_available=False,
        )
        finding["range"] = None
        result = compare_security_evidence(
            security_report(finding),
            security_report(finding),
            expected_project="oracle-py",
        )
        self.assertEqual(result["status"], "SECURITY_EVIDENCE_UNAVAILABLE")
        self.assertIn("detector evidence is incomplete", " ".join(result["limits"]))

    def test_local_ir_empty_flows_are_materialized_explicitly(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "src" / "security.py"
            path.parent.mkdir()
            path.write_text("raise Exception()\n")
            report = {
                "files": [
                    {
                        "path": str(path),
                        "issues": [
                            {
                                "rule_key": RULE,
                                "message": MESSAGE,
                                "range": {
                                    "start": {"line": 1, "column": 0},
                                    "end": {"line": 1, "column": 4},
                                },
                            }
                        ],
                    }
                ]
            }
            artifact = build_hoonarqube_security_evidence(
                report,
                project="oracle-py",
                rule_types={RULE: "VULNERABILITY"},
                project_root=root,
            )
        self.assertEqual(artifact["findings"][0]["detector"]["flows"], [])
        self.assertTrue(artifact["findings"][0]["detector"]["flow_evidence_available"])
        self.assertEqual(artifact["findings"][0]["file"], "src/security.py")

    def test_report_task_requires_compute_engine_identity(self):
        task = parse_report_task("projectKey=oracle-py\nceTaskId=task-123\n")
        self.assertEqual(task["ceTaskId"], "task-123")
        with self.assertRaisesRegex(ValueError, "lacks ceTaskId"):
            parse_report_task("projectKey=oracle-py\n")
        with self.assertRaisesRegex(ValueError, "duplicate ceTaskId"):
            parse_report_task("ceTaskId=one\nceTaskId=two\n")
        with self.assertRaisesRegex(ValueError, "projectKey must be 'oracle-js'"):
            parse_report_task(
                "projectKey=oracle-py\nceTaskId=one\n",
                expected_project="oracle-js",
            )

    def test_compute_engine_waits_for_commit_and_fails_closed(self):
        statuses = iter(["PENDING", "IN_PROGRESS", "SUCCESS"])
        pauses = []
        status = wait_for_compute_engine(
            "task-123",
            lambda _task: next(statuses),
            lambda: pauses.append(True),
            attempts=3,
        )
        self.assertEqual(status, "SUCCESS")
        self.assertEqual(len(pauses), 2)

        failed = wait_for_compute_engine(
            "task-123", lambda _task: "FAILED", lambda: None, attempts=1
        )
        timed_out = wait_for_compute_engine(
            "task-123", lambda _task: "PENDING", lambda: None, attempts=2
        )
        self.assertEqual(failed, "FAILED")
        self.assertEqual(timed_out, "TIMEOUT")
        with self.assertRaisesRegex(ValueError, "invalid compute engine status"):
            wait_for_compute_engine(
                "task-123", lambda _task: None, lambda: None, attempts=1
            )


if __name__ == "__main__":
    unittest.main()
