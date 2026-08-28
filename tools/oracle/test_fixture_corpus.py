import json
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent.parent
PROJECTS = {
    "oracle-py": ("python", "src"),
    "oracle-js": ("javascript", "src"),
    "oracle-ts": ("typescript", "src"),
    "oracle-cs": ("csharp", "."),
    "oracle-go": ("go", "src"),
    "oracle-rust": ("rust", "src"),
}


class FixtureCorpusTests(unittest.TestCase):
    def test_declared_expectations_are_unique_catalog_rules_with_real_controls(self):
        for project, (language, source_relative) in PROJECTS.items():
            with self.subTest(project=project):
                project_dir = REPO / ".oracle/sonar/projects" / project
                rows = [
                    json.loads(line)
                    for line in (project_dir / "expected.jsonl").read_text().splitlines()
                    if line.strip()
                ]
                keys = [row.get("key") for row in rows]
                self.assertEqual(len(keys), len(set(keys)), "duplicate expectation key")

                catalog = json.loads(
                    (REPO / "catalog/rules" / f"{language}.json").read_text()
                )
                catalog_keys = {rule["external_key"] for rule in catalog["rules"]}
                self.assertTrue(set(keys) <= catalog_keys, "non-catalog expectation key")

                source_dir = project_dir / source_relative
                available = {path.name for path in source_dir.iterdir() if path.is_file()}
                for row in rows:
                    if row.get("skip") or row.get("infra"):
                        continue
                    bad = row.get("bad")
                    self.assertIsInstance(bad, str, row["key"])
                    good = row.get("good", bad.replace("_bad", "_good"))
                    self.assertIn(bad, available, row["key"])
                    self.assertIn(good, available, row["key"])


if __name__ == "__main__":
    unittest.main()
