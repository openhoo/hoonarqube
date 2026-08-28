#!/usr/bin/env python3
"""Strict three-way parity diff: expectations vs SonarQube vs hoonarqube."""

import json
import sys
from pathlib import Path

from parity import compare_reports, counts, failure_count


REPO = Path(__file__).resolve().parent.parent.parent
CATALOG_LANGUAGE = {
    "py": "python",
    "python": "python",
    "js": "javascript",
    "javascript": "javascript",
    "ts": "typescript",
    "typescript": "typescript",
    "cs": "csharp",
    "csharp": "csharp",
}


def load_jsonl(path):
    return [json.loads(line) for line in open(path) if line.strip()]


def main(lang, project_dir, sonar_json, ours_json, out_path=None):
    language = CATALOG_LANGUAGE[lang]
    project_dir = Path(project_dir)
    expected = load_jsonl(project_dir / "expected.jsonl")
    sonar = json.load(open(sonar_json))
    ours = json.load(open(ours_json))
    catalog = json.loads((REPO / "catalog/rules" / f"{language}.json").read_text())
    catalog_keys = [rule["external_key"] for rule in catalog["rules"]]
    fixture_dir = project_dir if language == "csharp" else project_dir / "src"
    available_files = [path.name for path in fixture_dir.iterdir() if path.is_file()]
    rows = compare_reports(
        expected,
        sonar,
        ours,
        catalog_keys=catalog_keys,
        available_files=available_files,
    )
    json.dump(rows, open(out_path or "/dev/stdout", "w"), indent=1)
    print(counts(rows))
    return failure_count(rows)


if __name__ == "__main__":
    sys.exit(0 if main(*sys.argv[1:]) == 0 else 1)
