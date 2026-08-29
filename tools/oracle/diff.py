#!/usr/bin/env python3
"""Strict three-way parity diff: expectations vs SonarQube vs hoonarqube."""

import argparse
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
    "go": "go",
    "rs": "rust",
    "rust": "rust",
}


def load_jsonl(path):
    return [
        json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()
    ]


def main(lang, project_dir, sonar_json, ours_json, out_path=None):
    language = CATALOG_LANGUAGE[lang]
    project_dir = Path(project_dir)
    expected = load_jsonl(project_dir / "expected.jsonl")
    sonar = json.loads(Path(sonar_json).read_text())
    ours = json.loads(Path(ours_json).read_text())
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
    rendered = json.dumps(rows, indent=1) + "\n"
    if out_path:
        Path(out_path).write_text(rendered)
        print(counts(rows))
    else:
        sys.stdout.write(rendered)
        print(counts(rows), file=sys.stderr)
    return failure_count(rows)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("language", choices=sorted(CATALOG_LANGUAGE))
    parser.add_argument("project_dir", type=Path)
    parser.add_argument("sonar_json", type=Path)
    parser.add_argument("ours_json", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    failures = main(
        args.language,
        args.project_dir,
        args.sonar_json,
        args.ours_json,
        args.output,
    )
    sys.exit(0 if failures == 0 else 1)
