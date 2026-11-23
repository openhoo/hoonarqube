"""Whole-tree identity, precise line sets, missing measurements and threshold controls."""

import copy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import community_go_whole_trees as tree


def example():
    limits = {"a.go": 120, "b.go": 120}
    reference = {
        "repository": "example/project",
        "commit": "1" * 40,
        "tree": "2" * 40,
        "community": {
            "analysis": "example",
            "density": "3.0",
            "status": "OK",
            "lines": 200,
            "indexed_files": list(limits),
            "duplicated_line_count": 6,
            "duplicated_lines": {"a.go": "10-12", "b.go": "20-22"},
        },
        "allowed_residual": {
            "density_delta": "0.0",
            "missing_files": [],
            "missing_lines": {},
            "extra_lines": {},
        },
    }
    native = {
        "complete": True,
        "roots": ["."],
        "warnings": [],
        "files": [{"path": "./" + p, "status": "complete"} for p in limits],
        "duplications": [
            {
                "occurrences": [
                    {"path": "./a.go", "start_line": 10, "end_line": 12},
                    {"path": "./b.go", "start_line": 20, "end_line": 22},
                ]
            }
        ],
        "duplication": {"duplicated_lines": 6, "duplicated_lines_density": 3.0},
        "metrics": {"lines": 200},
    }
    return reference, native, limits


class TreeIdentity(unittest.TestCase):
    def test_one_changed_added_or_removed_blob_fails_with_complete_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repository"
            repo.mkdir()
            tree.git(repo, "init", "--quiet", "--template=")
            (repo / ".github").mkdir()
            files = {
                ".github/notes (draft).txt": b"original",
                "run.sh": b"plain data, not a script",
            }
            for path, body in files.items():
                (repo / path).write_bytes(body)
            (repo / "run.sh").chmod(0o755)
            tree.git(repo, "add", ".")
            tree.git(
                repo,
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@invalid.example",
                "commit",
                "-qm",
                "fixture",
            )
            commit = tree.git(repo, "rev-parse", "HEAD").decode().strip()
            oid = tree.git(repo, "rev-parse", "HEAD^{tree}").decode().strip()
            hashes = {p: hashlib.sha256(b).hexdigest() for p, b in files.items()}
            pin = {
                "repository": "example/project",
                "commit": commit,
                "tree": oid,
                "tracked": {
                    "files": len(files),
                    "bytes": sum(map(len, files.values())),
                    "sha256": tree.inventory_hash(hashes),
                },
            }
            mirror = repo / ".git"
            with tempfile.TemporaryDirectory(dir=root) as dst:
                source, _ = tree.stage(pin, Path(dst), mirror)
                self.assertEqual(
                    {
                        p.relative_to(source).as_posix(): p.read_bytes()
                        for p in source.rglob("*")
                        if p.is_file()
                    },
                    files,
                )
                self.assertFalse((source / "run.sh").stat().st_mode & 0o111)
            variants = [
                ({**hashes, "run.sh": "0" * 64}, 2),
                ({".github/notes (draft).txt": hashes[".github/notes (draft).txt"]}, 1),
                ({**hashes, "extra": hashes["run.sh"]}, 3),
            ]
            for inventory, count in variants:
                with (
                    self.subTest(count=count),
                    tempfile.TemporaryDirectory(dir=root) as dst,
                ):
                    bad = copy.deepcopy(pin)
                    bad["tracked"].update(
                        files=count, sha256=tree.inventory_hash(inventory)
                    )
                    with self.assertRaisesRegex(
                        ValueError, "complete source bytes|tree inventory"
                    ):
                        tree.stage(bad, Path(dst), mirror)
            with (
                tempfile.TemporaryDirectory(dir=root) as dst,
                self.assertRaisesRegex(ValueError, "wrong tree"),
            ):
                tree.stage({**pin, "tree": "f" * 40}, Path(dst), mirror)
            with (
                tempfile.TemporaryDirectory(dir=root) as dst,
                self.assertRaises(subprocess.CalledProcessError),
            ):
                tree.stage({**pin, "commit": "f" * 40}, Path(dst), mirror)

    def test_dangerous_or_aliased_tree_entries_are_not_materialized(self):
        sha = b"1" * 40
        for path in (
            b".git/config",
            b".GiT",
            b"../escape",
            b"/relative",
            b"x//y",
            b"foo.",
            b"NUL.txt",
            b"x\\y",
            b"a\n",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                tree.safe_tree_path(path.decode())
        for metadata in (
            b"120000 blob " + sha + b" 1",
            b"160000 commit " + sha + b" -",
        ):
            with self.assertRaisesRegex(ValueError, "non-regular"):
                tree.tree_entries(metadata + b"\tordinary\0")
        row = b"100644 blob " + sha + b" 1\t"
        for listing in (
            row + b"foo\0" + row + b"FOO\0",
            row + b"folder/file\0",
            b"040000 tree " + sha + b" -\tempty\0",
        ):
            with self.assertRaises(ValueError):
                tree.tree_entries(listing)


class Measurement(unittest.TestCase):
    def test_relation_only_companion_is_checked_but_does_not_count(self):
        reference, project, limits = example()
        companion = {"path": "./a.go", "start_line": 60, "end_line": 62, "relation_only": True}
        project["duplications"][0]["occurrences"].append(companion)
        self.assertEqual(tree.compare(reference, project, limits)["regressions"], [])
        companion["relation_only"] = "true"
        with self.assertRaisesRegex(ValueError, "invalid duplication relation flag"):
            tree.compare(reference, project, limits)

    def test_unchanged_density_cannot_hide_a_line_shift(self):
        ref, project, limits = example()
        self.assertEqual(tree.compare(ref, project, limits)["regressions"], [])
        occurrence = project["duplications"][0]["occurrences"][0]
        occurrence.update(start_line=11, end_line=13)
        actual = tree.compare(ref, project, limits)
        self.assertEqual(actual["regressions"], ["duplicated line locations"])
        self.assertEqual(
            (actual["missing_lines"], actual["extra_lines"]),
            ({"a.go": "10"}, {"a.go": "13"}),
        )
        allowance = ref["allowed_residual"]
        allowance.update(missing_lines={"a.go": "10"}, extra_lines={"a.go": "13"})
        self.assertEqual(tree.compare(ref, project, limits)["regressions"], [])
        occurrence.update(start_line=9, end_line=11)
        self.assertIn(
            "duplicated line locations",
            tree.compare(ref, project, limits)["regressions"],
        )
        occurrence.update(start_line=10, end_line=12)
        self.assertEqual(tree.compare(ref, project, limits)["regressions"], [])

    def test_missing_file_and_unavailable_metrics_do_not_turn_green(self):
        ref, project, limits = example()
        ref["community"]["indexed_files"].append("c.go")
        limits["c.go"] = 1
        self.assertIn(
            "indexed files", tree.compare(ref, project, limits)["regressions"]
        )
        project["duplication"]["duplicated_lines_density"] = None
        with self.assertRaisesRegex(ValueError, "missing numeric measure"):
            tree.compare(ref, project, limits)

    def test_threshold_changes_decision_and_fake_cli_success_fails(self):
        ref, project, limits = example()
        self.assertEqual(
            tree.compare(ref, project, limits)["candidate_density_decision"], "OK"
        )
        project["metrics"]["lines"] = 196
        project["duplication"]["duplicated_lines_density"] = 100 * 6 / 196
        result = tree.compare(ref, project, limits)
        self.assertEqual(result["candidate_density"], "3.1")
        self.assertIn("gate decision", result["regressions"])
        cond = {**tree.POLICY["conditions"][0], "status": "fail", "actual": 3.1}
        report = {"assessment": {"gate": {"status": "fail", "conditions": [cond]}}}
        tree.verify_gate(report, 1, result)
        with self.assertRaisesRegex(ValueError, "exit/status"):
            tree.verify_gate(report, 0, result)
        with self.assertRaisesRegex(ValueError, "exit/status"):
            tree.verify_gate(
                {"assessment": {"gate": {"status": "unavailable", "conditions": []}}},
                2,
                result,
            )
        cond["scope"] = "new"
        with self.assertRaisesRegex(ValueError, "assigned condition"):
            tree.verify_gate(report, 1, result)

    def test_physical_line_membership_and_metric_agreement(self):
        ref, project, limits = example()
        with self.assertRaisesRegex(ValueError, "invalid lines"):
            tree.expand({"a.go": "9-11,11-12"}, limits)
        with self.assertRaisesRegex(ValueError, "invalid lines"):
            tree.expand({"a.go": "5-121"}, limits)
        project["duplication"]["duplicated_lines"] = 5
        with self.assertRaisesRegex(ValueError, "total and duplicated line locations"):
            tree.compare(ref, project, limits)
        project["duplication"]["duplicated_lines"] = 6
        project["duplications"][0]["occurrences"][0]["end_line"] = 121
        with self.assertRaisesRegex(ValueError, "invalid duplicated lines"):
            tree.compare(ref, project, limits)

    def test_frozen_cohort_is_not_a_single_file_sample(self):
        manifest = json.loads(tree.MANIFEST.read_bytes())
        projects = manifest["projects"]
        self.assertEqual(
            (
                len(projects),
                sum(c["tracked"]["files"] for c in projects),
                sum(c["tracked"]["bytes"] for c in projects),
            ),
            (32, 1701, 18464062),
        )
        self.assertEqual(
            sum(c["community"]["duplicated_line_count"] for c in projects), 9633
        )
        self.assertEqual(len({c["community"]["analysis"] for c in projects}), 32)
        self.assertEqual(
            sum(not Decimal(c["allowed_residual"]["density_delta"]) for c in projects),
            31,
        )
        self.assertEqual(
            sum(
                not any(
                    c["allowed_residual"][k] for k in ("missing_lines", "extra_lines")
                )
                for c in projects
            ),
            32,
        )


if __name__ == "__main__":
    unittest.main()
