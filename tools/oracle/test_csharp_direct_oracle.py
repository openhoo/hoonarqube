import json
import tempfile
import unittest
from pathlib import Path

from csharp_direct_oracle import catalog_rule_ids, sarif_issues


class CSharpDirectOracleTests(unittest.TestCase):
    def test_reads_roslyn_sarif_and_normalizes_columns(self):
        report = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "S1905",
                            "message": "Remove this unnecessary cast to 'bool'.",
                            "locations": [
                                {
                                    "resultFile": {
                                        "uri": "file:///tmp/s1905_bad.cs",
                                        "region": {
                                            "startLine": 9,
                                            "startColumn": 22,
                                            "endLine": 9,
                                            "endColumn": 26,
                                        },
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "CS0168",
                            "message": "compiler warning",
                            "locations": [],
                        },
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.sarif"
            path.write_text(json.dumps(report))

            issues = sarif_issues([path])

        self.assertEqual(
            issues,
            [
                {
                    "rule": "csharpsquid:S1905",
                    "file": "s1905_bad.cs",
                    "message": "Remove this unnecessary cast to 'bool'.",
                    "range": {
                        "start": {"line": 9, "column": 21},
                        "end": {"line": 9, "column": 25},
                    },
                    "hotspot": False,
                }
            ],
        )

    def test_reads_standard_sarif_and_excludes_generated_stubs(self):
        report = {
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "S100",
                            "message": {"text": "Rename this method."},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "source%20file.cs"},
                                        "region": {
                                            "startLine": 2,
                                            "startColumn": 3,
                                            "endLine": 2,
                                            "endColumn": 7,
                                        },
                                    }
                                }
                            ],
                        },
                        {
                            "ruleId": "S1144",
                            "message": "generated",
                            "locations": [
                                {
                                    "resultFile": {
                                        "uri": "OracleStubs.g.cs",
                                        "region": {
                                            "startLine": 1,
                                            "startColumn": 1,
                                            "endLine": 1,
                                            "endColumn": 2,
                                        },
                                    }
                                }
                            ],
                        },
                    ]
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.sarif"
            path.write_text(json.dumps(report))
            issues = sarif_issues([path])
        self.assertEqual(issues[0]["file"], "source file.cs")
        self.assertEqual(len(issues), 1)

    def test_catalog_rule_ids_are_external_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "csharp.json"
            path.write_text(
                json.dumps(
                    {
                        "rules": [
                            {"external_key": "csharpsquid:S200"},
                            {"external_key": "csharpsquid:S100"},
                        ]
                    }
                )
            )
            self.assertEqual(catalog_rule_ids(path), ["S100", "S200"])


if __name__ == "__main__":
    unittest.main()
