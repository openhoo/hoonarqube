"""A partial tree can prove one gate; separate Go locations cannot rescue a bad gate."""

import copy
from decimal import Decimal
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import community_go_whole_trees as tree


class ScopedDocker(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.source = Path(tmp.name)
        (self.source / "Dockerfile").write_bytes(b"A\rB\r\n")
        self.limits = {"a.go": 10, "b.go": 20, "Dockerfile": 2, "README": 1}
        self.case = {
            "repository": "example/test",
            "commit": "1" * 40,
            "tree": "2" * 40,
            "community": {
                "analysis": "fake",
                "indexed_files": ["a.go", "b.go", "Dockerfile"],
                "lines": 33,
                "density": "9.1",
                "status": "ERROR",
                "duplicated_line_count": 3,
                "duplicated_lines": {"a.go": "2-3", "b.go": "4"},
            },
            "allowed_residual": {
                "density_delta": "0.0",
                "missing_files": ["Dockerfile"],
                "missing_lines": {},
                "extra_lines": {},
            },
        }
        counts = {"a.go": 2, "b.go": 1}
        files = [
            {"path": "./" + p, "language": "go", "metrics": {"lines": self.limits[p]}}
            for p in counts
        ]
        rows = [
            {
                "path": r["path"],
                "classification": "source",
                "status": "complete",
                "metrics": r["metrics"],
                "duplication": None,
                "reason": None,
            }
            for r in files
        ]
        docker = {
            "path": "./Dockerfile",
            "classification": "source",
            "status": "unsupported",
            "reason": "language is unsupported",
            "metrics": None,
            "duplication": None,
        }
        policy = {
            **tree.POLICY["conditions"][0],
            "actual": Decimal("9.1"),
            "status": "fail",
        }
        self.full = {
            "assessment": {"gate": {"status": "fail", "conditions": [policy]}},
            "files": files,
            "project": {
                "roots": ["."],
                "complete": False,
                "metrics": {"lines": 30, "files": 2},
                "warnings": ["./Dockerfile: language is unsupported"],
                "files": rows + [docker],
                "duplication": None,
                "duplications": [],
                "docker_duplication": {
                    "go_files": [
                        {"path": "./" + p, "duplicated_lines": n}
                        for p, n in counts.items()
                    ],
                    "go_duplicated_lines": 3,
                    "dockerfiles": [{"path": "./Dockerfile", "bytes": 5, "lines": 3}],
                },
            },
        }
        self.supp = {
            "files": files,
            "project": {
                "roots": ["./a.go", "./b.go"],
                "complete": True,
                "warnings": [],
                "metrics": {"lines": 30, "files": 2},
                "files": [
                    {**r, "duplication": {"duplicated_lines": counts[r["path"][2:]]}}
                    for r in rows
                ],
                "duplication": {"duplicated_lines": 3, "duplicated_lines_density": 10},
                "duplications": [
                    {
                        "occurrences": [
                            {"path": "./a.go", "start_line": 2, "end_line": 3},
                            {"path": "./b.go", "start_line": 4, "end_line": 4},
                        ]
                    }
                ],
            },
        }

    def replay(self, full, code, run):
        return tree.scoped_replay(self.case, full, code, self.source, self.limits, run)

    def test_provenance_and_scope(self):
        run = Mock(return_value=(self.supp, 0))
        result = self.replay(self.full, 1, run)
        run.assert_called_once_with(["./a.go", "./b.go"])
        self.assertEqual(result["regressions"], [])
        self.assertEqual(result["line_map_source"], "explicit_indexed_go_files")
        self.assertEqual(result["gate_source"], "whole_tree")
        self.assertEqual((result["duplicated_lines"], result["overall_lines"]), (3, 33))
        self.assertEqual((result["cli_exit"], result["cli_gate_status"]), (1, "fail"))

    def test_false_green_unavailable_wrong_gate_or_missing_evidence_never_launches_line_scan(
        self,
    ):
        for label, code, change in [
            ("wrong exit", 0, lambda r: None),
            ("false green", 0, lambda r: r["assessment"]["gate"].update(status="pass")),
            (
                "unavailable",
                2,
                lambda r: r["assessment"]["gate"].update(status="unavailable"),
            ),
            (
                "wrong actual",
                1,
                lambda r: r["assessment"]["gate"]["conditions"][0].update(actual=8),
            ),
            (
                "wrong policy",
                1,
                lambda r: r["assessment"]["gate"]["conditions"][0].update(scope="new"),
            ),
            ("no scoped measure", 1, lambda r: r["project"].pop("docker_duplication")),
            (
                "missing count",
                1,
                lambda r: r["project"]["docker_duplication"]["go_files"].pop(),
            ),
            (
                "wrong total",
                1,
                lambda r: r["project"]["docker_duplication"].update(
                    go_duplicated_lines=0
                ),
            ),
            (
                "missing Dockerfile",
                1,
                lambda r: r["project"]["docker_duplication"]["dockerfiles"].clear(),
            ),
            (
                "wrong bytes",
                1,
                lambda r: r["project"]["docker_duplication"]["dockerfiles"][0].update(
                    bytes=4
                ),
            ),
            (
                "wrong lines",
                1,
                lambda r: r["project"]["docker_duplication"]["dockerfiles"][0].update(
                    lines=2
                ),
            ),
            (
                "file status",
                1,
                lambda r: r["project"]["files"][0].update(status="excluded"),
            ),
            (
                "unexplained warning",
                1,
                lambda r: r["project"]["warnings"].append("missing input"),
            ),
            (
                "partial profile",
                1,
                lambda r: r["project"].update(partial_rule_selection={}),
            ),
        ]:
            with self.subTest(label=label):
                bad = copy.deepcopy(self.full)
                change(bad)
                run = Mock()
                with self.assertRaises(ValueError):
                    self.replay(bad, code, run)
                run.assert_not_called()

    def test_default_mode_gates_the_same_tree_before_requesting_go_lines(self):
        plain = {k: v for k, v in self.full.items() if k != "assessment"}
        with (
            patch.object(tree, "stage", return_value=(self.source, self.limits)),
            patch.object(
                tree, "scan", side_effect=[(plain, 2), (self.full, 1), (self.supp, 0)]
            ) as scan,
        ):
            self.assertEqual(tree.replay(self.case, "binary")["regressions"], [])
            calls = [c.args for c in scan.call_args_list]
            self.assertEqual(
                [c[1] for c in calls], [["."], ["."], ["./a.go", "./b.go"]]
            )
            self.assertEqual([c[2] for c in calls], [self.source] * 3)
            self.assertEqual([c[4] is not None for c in calls], [False, True, False])

        changed = copy.deepcopy(self.full)
        changed["project"]["docker_duplication"]["go_duplicated_lines"] = 0
        with (
            patch.object(tree, "stage", return_value=(self.source, self.limits)),
            patch.object(tree, "scan", side_effect=[(plain, 2), (changed, 1)]) as scan,
            self.assertRaisesRegex(ValueError, "changed the original analysis"),
        ):
            tree.replay(self.case, "binary")
        self.assertEqual(scan.call_count, 2)

    def test_unpinned_go_or_other_indexed_source_is_not_an_eligible_partial_tree(self):
        for path in ("extra.go", "README"):
            with self.subTest(path=path):
                limits = {**self.limits, path: 5}
                case = copy.deepcopy(self.case)
                if path == "README":
                    case["community"]["indexed_files"].append(path)
                with self.assertRaisesRegex(ValueError, "outside the frozen"):
                    tree.docker_scope.primary(case, self.full, self.source, limits)

    def test_incorrect_supplemental_roots_counts_or_marked_locations(self):
        for label, change in [
            ("wrong roots", lambda r: r["project"]["roots"].append(".")),
            ("missing source", lambda r: r["files"].pop()),
            (
                "unknown file",
                lambda r: r["project"]["files"][0].update(path="./README"),
            ),
            (
                "forged per-file count",
                lambda r: r["project"]["files"][0]["duplication"].update(
                    duplicated_lines=1
                ),
            ),
        ]:
            with self.subTest(label=label):
                bad = copy.deepcopy(self.supp)
                change(bad)
                with self.assertRaises(ValueError):
                    self.replay(self.full, 1, Mock(return_value=(bad, 0)))
        bad = copy.deepcopy(self.full)
        a, b = bad["project"]["docker_duplication"]["go_files"]
        a["duplicated_lines"], b["duplicated_lines"] = 1, 2
        with self.assertRaisesRegex(ValueError, "disagree with whole-tree file"):
            self.replay(bad, 1, Mock(return_value=(self.supp, 0)))
        self.supp["project"]["duplications"][0]["occurrences"][0].update(
            start_line=3, end_line=4
        )
        row = self.replay(self.full, 1, Mock(return_value=(self.supp, 0)))
        self.assertEqual(row["regressions"], ["duplicated line locations"])

    def test_only_two_frozen_source_inventories_index_dockerfiles(self):
        projects = json.loads(tree.MANIFEST.read_bytes())["projects"]
        self.assertEqual(
            {
                c["repository"]
                for c in projects
                if any(
                    Path(p).name == "Dockerfile"
                    for p in c["community"]["indexed_files"]
                )
            },
            {"sony/sonyflake", "pelletier/go-toml"},
        )
