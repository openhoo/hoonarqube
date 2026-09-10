import json
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest import mock


ORACLE_DIR = Path(__file__).resolve().parent
if str(ORACLE_DIR) not in sys.path:
    sys.path.insert(0, str(ORACLE_DIR))

import security_evidence  # noqa: E402


FIXTURE_KEY = "python:S9000"
FLOW_NAME = "cross_file_flow"


def _fixture_case(*, description, filename, source, expected_target):
    return {
        "description": description,
        "files": {filename: source},
        "sources": [filename],
        "native_args": [],
        "sonar_properties": {},
        "expected_target": expected_target,
    }


@contextmanager
def _temporary_fixture():
    manifest = {
        "schema_version": security_evidence.FIXTURE_SCHEMA_VERSION,
        "language": "python",
        "rules": [
            {
                "key": FIXTURE_KEY,
                "rationale": "temporary fixture for collector regressions",
                "cases": {
                    "attack": _fixture_case(
                        description="fixture attack",
                        filename="attack.py",
                        source="value = input()\n",
                        expected_target=True,
                    ),
                    "safe": _fixture_case(
                        description="fixture safe control",
                        filename="safe.py",
                        source="value = int(input())\n",
                        expected_target=False,
                    ),
                    "near_miss": _fixture_case(
                        description="fixture near miss",
                        filename="near_miss.py",
                        source="value = input()\nprint(value)\n",
                        expected_target=False,
                    ),
                },
                "flow_cases": [
                    {
                        "name": FLOW_NAME,
                        "description": "a valid flow spanning two source files",
                        "files": {
                            "helper.py": "def load(value):\n    return value\n",
                            "entry.py": "from helper import load\nload(input())\n",
                        },
                        "sources": ["helper.py", "entry.py"],
                        "native_args": [],
                        "sonar_properties": {},
                        "expected_target": False,
                    }
                ],
            }
        ],
    }
    with tempfile.TemporaryDirectory() as directory:
        directory = Path(directory)
        manifest_path = directory / "python.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifests = security_evidence.load_security_fixture_manifests(directory)
        fixtures = security_evidence.load_security_fixtures(directory)
        yield directory, manifests, fixtures, fixtures[FIXTURE_KEY]


def _catalog_row(key=FIXTURE_KEY):
    return {
        "key": key,
        "language": "python",
        "rule_type": "VULNERABILITY",
        "classification": "community-base",
        "sensor_ownership": {
            "server_security_sensor": security_evidence.COMMUNITY_PLUGIN_KEY["python"]
        },
        "context": {"server_sensor": {}, "limits": []},
        "edition": {},
    }


@contextmanager
def _isolated_build_inputs(manifests, fixtures, rows):
    with (
        mock.patch.object(
            security_evidence,
            "load_security_fixture_manifests",
            return_value=manifests,
        ),
        mock.patch.object(
            security_evidence, "load_security_fixtures", return_value=fixtures
        ),
        mock.patch.object(
            security_evidence, "_catalog_security_rows", return_value=rows
        ),
    ):
        yield


class SecurityFixtureMaterializationTests(unittest.TestCase):
    def test_selected_multifile_flow_retains_fixture_scope(self):
        with _temporary_fixture() as (_directory, manifests, fixtures, fixture):
            flow = fixture["flow_cases"][0]
            with tempfile.TemporaryDirectory() as directory:
                sources, materialized = security_evidence._materialize_fixture_files(
                    Path(directory), flow
                )
                self.assertEqual(sources, flow["sources"])
                self.assertEqual(set(materialized), set(flow["files"]))
                for path, data in materialized.items():
                    self.assertEqual((Path(directory) / path).read_bytes(), data)

            row = _catalog_row()
            with _isolated_build_inputs(manifests, fixtures, [row]):
                artifact = security_evidence.build_artifact(execute=[FIXTURE_KEY])

        self.assertEqual(artifact["execution"]["selected_keys"], [FIXTURE_KEY])
        matrix = artifact["reference_environment"]["community_execution"][0]
        self.assertIn(FLOW_NAME, matrix["case_names"])
        result = next(item for item in matrix["cases"] if item["case"] == FLOW_NAME)
        self.assertEqual(result["source"]["sources"], flow["sources"])
        self.assertEqual(
            {item["path"] for item in result["source"]["files"]},
            set(flow["files"]),
        )

    def test_materialization_rejects_paths_that_escape_fixture_root(self):
        cases = [
            {
                "files": {"../escape.py": "outside = True\n"},
                "sources": ["../escape.py"],
            },
            {
                "files": {"inside.py": "inside = True\n"},
                "sources": ["../escape.py"],
            },
        ]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "materialized"
                outside = Path(directory) / "escape.py"
                with self.assertRaises(ValueError):
                    security_evidence._materialize_fixture_files(root, case)
                self.assertFalse(outside.exists())


class SecurityArtifactRegressionTests(unittest.TestCase):
    def test_reference_api_failure_is_incomplete_not_negative_control(self):
        with _temporary_fixture() as (_directory, manifests, fixtures, _fixture):
            row = _catalog_row()
            base = "https://reference.example"
            server = {
                "url": base,
                "status": "UP",
                "edition": "Community",
                "plugins": [{"key": security_evidence.COMMUNITY_PLUGIN_KEY["python"]}],
            }
            with tempfile.TemporaryDirectory() as directory:
                token_file = Path(directory) / "token"
                token_file.write_text("fixture-token\n", encoding="utf-8")
                token_file.chmod(0o600)
                with (
                    _isolated_build_inputs(manifests, fixtures, [row]),
                    mock.patch.object(
                        security_evidence, "_server_metadata", return_value=server
                    ),
                    mock.patch.object(
                        security_evidence,
                        "_server_rule_metadata",
                        side_effect=RuntimeError("rule endpoint failed"),
                    ),
                ):
                    artifact = security_evidence.build_artifact(
                        base=base, token_file=token_file, execute=[FIXTURE_KEY]
                    )

        self.assertEqual(artifact["reference_environment"]["status"], "available")
        matrix = artifact["reference_environment"]["community_execution"][0]
        self.assertEqual(matrix["contract_status"], "INCOMPLETE")
        self.assertFalse(matrix["negative_control_claimed"])
        self.assertTrue(matrix["cases"])
        for result in matrix["cases"]:
            self.assertEqual(result["status"], "incomplete")
            self.assertIsNone(result["outcome"]["comparison"])
            self.assertFalse(result["outcome"]["negative_control_claimed"])

    def test_language_selection_fails_closed_when_fixture_inventory_is_incomplete(self):
        with _temporary_fixture() as (_directory, _manifests, fixtures, _fixture):
            rows = [_catalog_row(), _catalog_row("python:S9001")]
            with self.assertRaises(ValueError):
                security_evidence._resolve_execution_keys(
                    ["python"], None, rows, {FIXTURE_KEY: fixtures[FIXTURE_KEY]}
                )


if __name__ == "__main__":
    unittest.main()
