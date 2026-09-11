import copy
import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))

import metric_oracle as oracle


class FakeApi:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def get(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        key = (path, tuple(sorted((params or {}).items())))
        value = self.responses.get(key)
        if value is None:
            raise AssertionError(f"unexpected API call {path} {params}")
        return copy.deepcopy(value)


def response_key(path, params):
    return (path, tuple(sorted(params.items())))


def complete_reference_case(*, density_state="PRESENT", lines=20):
    project_metrics = {
        "lines": lines,
        "ncloc": 10,
        "comment_lines": 2,
        "duplicated_lines": 4,
        "duplicated_blocks": 2,
        "duplicated_files": 2,
        "duplicated_lines_density": 20.0,
    }
    project_states = {metric: "PRESENT" for metric in oracle.METRIC_KEYS}
    project_states["duplicated_lines_density"] = density_state
    file_metrics = {
        "lines": 10,
        "ncloc": 5,
        "comment_lines": 1,
        "duplicated_lines": 4,
        "duplicated_blocks": 1,
        "duplicated_files": 1,
        "duplicated_lines_density": 40.0,
    }
    return {
        "id": "case",
        "language": "python",
        "status": "COMPLETE",
        "project": {"metrics": project_metrics, "metric_states": project_states},
        "files": {
            "files": [
                {
                    "path": "src/a.py",
                    "metrics": file_metrics,
                    "metric_states": {
                        metric: "PRESENT" for metric in oracle.METRIC_KEYS
                    },
                }
            ]
        },
    }


class MetricOracleTests(unittest.TestCase):
    def test_real_corpus_manifest_validates(self):
        corpus, root = oracle.load_corpus(
            Path(__file__).parent / "fixtures/metrics/corpus.json"
        )
        self.assertEqual(corpus["schema_version"], 1)
        self.assertEqual(len(corpus["cases"]), 17)
        self.assertEqual(
            {case["language"] for case in corpus["cases"]},
            set(oracle.SUPPORTED_LANGUAGES),
        )
        self.assertTrue(
            {
                "threshold-python-99",
                "threshold-python-100",
                "threshold-python-101",
                "java-statements-9",
                "java-statements-10",
                "java-statements-11",
                "java-structure-ranges",
            }
            <= {case["id"] for case in corpus["cases"]}
        )
        self.assertEqual(root.name, "metrics")

    def test_source_inventory_hashes_crlf_bytes_without_normalizing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "unicode.py").write_bytes("# café\r\nvalue = 1\r\n".encode())
            inventory = oracle.source_inventory(root)
            self.assertEqual(inventory["file_count"], 1)
            self.assertEqual(
                inventory["files"][0]["bytes"], len((root / "unicode.py").read_bytes())
            )
            self.assertNotEqual(
                inventory["files"][0]["sha256"],
                __import__("hashlib")
                .sha256("# café\nvalue = 1\n".encode())
                .hexdigest(),
            )

    def test_density_zero_is_present_when_physical_denominator_exists(self):
        component = {
            "key": "project",
            "measures": [
                {"metric": "lines", "value": "4"},
                {"metric": "ncloc", "value": "0"},
                {"metric": "duplicated_lines_density", "value": "0.0"},
            ],
        }
        normalized = oracle.normalize_component_measures(component, project=True)
        self.assertEqual(normalized["metrics"]["duplicated_lines_density"], 0.0)
        self.assertEqual(
            normalized["metric_states"]["duplicated_lines_density"], "PRESENT"
        )

    def test_density_absence_is_no_denominator_only_for_empty_project(self):
        normalized = oracle.normalize_component_measures(
            {"key": "empty", "measures": []}, project=True
        )
        self.assertEqual(normalized["metrics"]["duplicated_lines_density"], None)
        self.assertEqual(
            normalized["metric_states"]["duplicated_lines_density"], "NO_DENOMINATOR"
        )

    def test_file_measure_fetch_requires_consistent_pagination_and_collects_all_metrics(
        self,
    ):
        project = "project"
        params1 = {
            "component": project,
            "metricKeys": ",".join(oracle.METRIC_KEYS),
            "qualifiers": "FIL",
            "ps": 1,
            "p": 1,
        }
        params2 = dict(params1, p=2)
        api = FakeApi(
            {
                response_key("/api/measures/component_tree", params1): {
                    "paging": {"pageIndex": 1, "pageSize": 1, "total": 2},
                    "components": [
                        {
                            "key": "project:src/a.py",
                            "name": "a.py",
                            "path": "src/a.py",
                            "qualifier": "FIL",
                            "language": "py",
                            "measures": [{"metric": "lines", "value": "1"}],
                        }
                    ],
                },
                response_key("/api/measures/component_tree", params2): {
                    "paging": {"pageIndex": 2, "pageSize": 1, "total": 2},
                    "components": [
                        {
                            "key": "project:src/b.py",
                            "name": "b.py",
                            "path": "src/b.py",
                            "qualifier": "FIL",
                            "language": "py",
                            "measures": [
                                {"metric": "lines", "value": "2"},
                                {"metric": "duplicated_lines", "value": "0"},
                            ],
                        }
                    ],
                },
            }
        )
        result = oracle.fetch_file_measures(api, project, page_size=1)
        self.assertEqual(result["paging"]["total"], 2)
        self.assertEqual(len(result["paging"]["pages"]), 2)
        self.assertEqual(
            [row["path"] for row in result["files"]], ["src/a.py", "src/b.py"]
        )
        self.assertEqual(result["files"][1]["metrics"]["duplicated_lines"], 0)
        self.assertEqual(len(api.calls), 2)

    def test_duplicate_normalization_preserves_line_ranges_and_references(self):
        payload = {
            "duplications": [
                {
                    "blocks": [
                        {"from": 7, "size": 3, "_ref": "1"},
                        {"from": 11, "size": 3, "_ref": "2"},
                    ]
                }
            ],
            "files": {
                "1": {"key": "project:src/a.py", "name": "src/a.py"},
                "2": {"key": "project:src/b.py", "name": "src/b.py"},
            },
        }
        result = oracle.normalize_duplicate_payload(payload, project_key="project")
        self.assertEqual(
            [
                (row["path"], row["start_line"], row["end_line"])
                for row in result["occurrences"]
            ],
            [("src/a.py", 7, 9), ("src/b.py", 11, 13)],
        )
        self.assertNotIn("start_byte", result["occurrences"][0])

    def test_compare_maps_absolute_native_paths_and_all_file_metrics(self):
        reference = complete_reference_case()
        native = {
            "project": {
                "complete": True,
                "metrics": {
                    "lines": 20,
                    "code_lines": 10,
                    "comment_lines": 2,
                },
                "duplication": {
                    "duplicated_lines": 4,
                    "duplicated_blocks": 2,
                    "duplicated_files": 2,
                    "duplicated_lines_density": 20.0,
                },
                "files": [
                    {
                        "path": "/tmp/fixture/src/a.py",
                        "metrics": {"lines": 10, "code_lines": 5, "comment_lines": 1},
                        "duplication": {
                            "duplicated_lines": 4,
                            "duplicated_blocks": 1,
                            "duplicated_files": 1,
                            "duplicated_lines_density": 40.0,
                        },
                    }
                ],
            }
        }
        result = oracle.compare_reference_case(reference, native)
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertEqual({row["status"] for row in result["metrics"]}, {"EXACT"})
        file_rows = [row for row in result["files"] if row["path"] == "src/a.py"]
        self.assertEqual(len(file_rows), 1)
        self.assertEqual(len(file_rows[0]["metrics"]), len(oracle.METRIC_KEYS))
        self.assertEqual({row["status"] for row in file_rows[0]["metrics"]}, {"EXACT"})
        self.assertEqual(result["duplication_occurrences"]["status"], "UNVERIFIED")

    def test_compare_ignores_unmeasured_excluded_inventory_roots(self):
        reference = complete_reference_case()
        native = {
            "project": {
                "complete": True,
                "metrics": reference["project"]["metrics"],
                "duplication": reference["project"]["metrics"],
                "files": [
                    {
                        "path": "src/a.py",
                        "classification": "source",
                        "status": "complete",
                        "metrics": {"lines": 10, "code_lines": 5, "comment_lines": 1},
                        "duplication": {
                            "duplicated_lines": 4,
                            "duplicated_blocks": 1,
                            "duplicated_files": 1,
                            "duplicated_lines_density": 40.0,
                        },
                    },
                    {
                        "path": "excluded",
                        "classification": "excluded",
                        "status": "excluded",
                        "metrics": None,
                        "duplication": None,
                    },
                    {
                        "path": "vendor",
                        "classification": "vendor",
                        "status": "excluded",
                        "metrics": None,
                        "duplication": None,
                    },
                    {
                        "path": "src/unmatched.py",
                        "classification": "source",
                        "status": "complete",
                        "metrics": None,
                        "duplication": None,
                    },
                    {
                        "path": "tests/out-of-scope.py",
                        "classification": "test",
                        "status": "complete",
                        "metrics": {
                            "lines": 2,
                            "code_lines": 1,
                            "comment_lines": 1,
                        },
                        "duplication": None,
                    },
                ],
            }
        }
        result = oracle.compare_reference_case(reference, native)
        paths = {row["path"] for row in result["files"]}
        self.assertNotIn("native:excluded", paths)
        self.assertNotIn("native:vendor", paths)
        self.assertIn("native:src/unmatched.py", paths)
        unmatched = next(
            row for row in result["files"] if row["path"] == "native:src/unmatched.py"
        )
        self.assertIn("native:tests/out-of-scope.py", paths)
        self.assertTrue(
            any(metric["status"] == "DIFFERENT" for metric in unmatched["metrics"])
        )
        unmatched_test = next(
            row
            for row in result["files"]
            if row["path"] == "native:tests/out-of-scope.py"
        )
        self.assertTrue(
            any(metric["status"] == "DIFFERENT" for metric in unmatched_test["metrics"])
        )

    def test_incomplete_native_report_is_unverified_not_zero(self):
        result = oracle.compare_reference_case(
            complete_reference_case(), {"project": {"complete": False, "metrics": {}}}
        )
        self.assertEqual(result["status"], "UNVERIFIED")
        self.assertTrue(all(row["status"] == "UNVERIFIED" for row in result["metrics"]))
        self.assertTrue(
            all(row["native"]["state"] == "INCOMPLETE" for row in result["metrics"])
        )

    def test_no_denominator_states_compare_without_coercing_to_zero(self):
        reference = complete_reference_case(density_state="NO_DENOMINATOR", lines=0)
        reference["project"]["metrics"]["duplicated_lines_density"] = None
        native = {
            "project": {
                "complete": True,
                "metrics": {"lines": 0, "code_lines": 0, "comment_lines": 0},
                "duplication": {
                    "duplicated_lines": 0,
                    "duplicated_blocks": 0,
                    "duplicated_files": 0,
                    "duplicated_lines_density": None,
                },
                "files": [],
            }
        }
        result = oracle.compare_reference_case(reference, native)
        density = next(
            row for row in result["metrics"] if row["metric"] == oracle.DENSITY_METRIC
        )
        self.assertEqual(density["status"], "EXACT")
        self.assertEqual(density["reference"]["state"], "NO_DENOMINATOR")
        self.assertEqual(density["native"]["state"], "NO_DENOMINATOR")

    def test_reference_artifact_requires_server_image_digest_and_rejects_credentials(
        self,
    ):
        artifact = {
            "schema_version": 1,
            "kind": oracle.REFERENCE_KIND,
            "corpus": {
                "id": "corpus",
                "schema_version": 1,
                "manifest": "corpus.json",
                "manifest_sha256": "c" * 64,
            },
            "server_url": "http://127.0.0.1:19084",
            "server": {
                "id": "server",
                "version": "26.8",
                "status": "UP",
                "image_digest": "sha256:" + "a" * 64,
                "plugins": [{"key": "python", "version": "5.27"}],
            },
            "scanner": {
                "image": "scanner@sha256:" + "b" * 64,
                "image_digest": "sha256:" + "b" * 64,
            },
            "metric_keys": list(oracle.METRIC_KEYS),
            "cases": [],
        }
        oracle.validate_reference_artifact(artifact)
        artifact["scanner"]["sonar.token"] = "must-not-persist"
        with self.assertRaises(ValueError):
            oracle.validate_reference_artifact(artifact)
        del artifact["scanner"]["sonar.token"]
        artifact["server"]["image_digest"] = None
        with self.assertRaises(ValueError):
            oracle.validate_reference_artifact(artifact)


if __name__ == "__main__":
    unittest.main()
