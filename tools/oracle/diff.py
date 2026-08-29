#!/usr/bin/env python3
"""Strict three-way parity diff: expectations vs SonarQube vs hoonarqube."""

import argparse
import json
import sys
from pathlib import Path

from parity import (
    compare_reports,
    counts,
    failure_count,
    load_infra_boundaries,
    read_json,
    read_jsonl,
    validate_oracle_report,
    write_json_atomic,
)


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
SOURCE_SUFFIX = {
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "csharp": ".cs",
    "go": ".go",
    "rust": ".rs",
}


def main(lang, project_dir, sonar_json, ours_json, out_path=None):
    try:
        language = CATALOG_LANGUAGE[lang]
    except KeyError as error:
        raise ValueError(f"unsupported oracle language: {lang}") from error
    project_dir = Path(project_dir)
    expected = read_jsonl(project_dir / "expected.jsonl")
    sonar = read_json(sonar_json)
    ours = read_json(ours_json)
    validate_oracle_report(sonar, expected_project=project_dir.name)
    catalog = read_json(REPO / "catalog/rules" / f"{language}.json")
    if not isinstance(catalog, dict) or not isinstance(catalog.get("rules"), list):
        raise ValueError(f"{language} catalog must contain a rules list")
    catalog_keys = []
    enterprise_unverified = []
    for index, rule in enumerate(catalog["rules"]):
        if not isinstance(rule, dict):
            raise ValueError(f"{language} catalog rule {index} must be an object")
        key = rule.get("external_key")
        if not isinstance(key, str) or not key:
            raise ValueError(
                f"{language} catalog rule {index} external_key must be a string"
            )
        catalog_keys.append(key)
        classification = rule.get("classification")
        if classification == "enterprise-unverified":
            enterprise_unverified.append(key)
    fixture_dir = project_dir if language == "csharp" else project_dir / "src"
    suffix = SOURCE_SUFFIX[language]
    available_files = [
        path.name for path in fixture_dir.rglob(f"*{suffix}") if path.is_file()
    ]
    rows = compare_reports(
        expected,
        sonar,
        ours,
        infra=load_infra_boundaries(REPO / "catalog/infra-boundaries.json"),
        catalog_keys=catalog_keys,
        available_files=available_files,
        enterprise_unverified=enterprise_unverified,
    )
    rendered = json.dumps(rows, indent=1) + "\n"
    if out_path:
        write_json_atomic(out_path, rows, indent=1)
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
