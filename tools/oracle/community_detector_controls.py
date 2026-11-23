"""Run the native positive and clean controls claimed by the strict Community gate."""

import argparse
import collections
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "catalog/reference"
MANIFEST = REFERENCE / "community-26.9-detector-controls.tsv"
KINDS = {"VULNERABILITY", "BUG", "CODE_SMELL"}


def require(valid, message):
    if not valid:
        raise ValueError(message)


def required_rules():
    rows = (REFERENCE / "community-26.9-sonar-way-types.tsv").read_text().splitlines()
    return {
        (lang, key)
        for lang, key, kind in (r.split("\t") for r in rows[1:])
        if kind in KINDS
    }


def source(directory, name, digest):
    require(
        Path(name).name == name and name not in ("", ".", ".."), "invalid fixture name"
    )
    blob = (directory / name).read_bytes()
    require(hashlib.sha256(blob).hexdigest() == digest, f"fixture changed: {name}")
    return blob


def exercise(cli, lang, key, fixtures):
    bad, bad_sha, clean, clean_sha = fixtures
    require(bad != clean and bad_sha != clean_sha, f"{key}: controls are identical")
    fixture_language = {"javascript": "js"}.get(lang, lang)
    directory = ROOT / ".oracle/sonar/projects" / ("oracle-" + fixture_language) / "src"
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for name, digest in ((bad, bad_sha), (clean, clean_sha)):
            (work / name).write_bytes(source(directory, name, digest))
        run = subprocess.run(
            [cli, "analyze", "--profile", "sonar-parity", "--json", bad, clean],
            cwd=work,
            capture_output=True,
            check=True,
            timeout=30,
        )
    report = json.loads(run.stdout)
    findings = {
        f["path"]: {i["rule_key"] for i in f["issues"]} for f in report["files"]
    }
    require(
        report["project"]["complete"] and set(findings) == {bad, clean},
        f"{key}: incomplete scope",
    )
    require(
        key in findings[bad] and key not in findings[clean], f"{key}: controls failed"
    )


def verify(cli):
    active = required_rules()
    seen = set()
    counts = collections.Counter()
    for row in MANIFEST.read_text().splitlines():
        lang, key, *fixtures = row.split("\t")
        pair = (lang, key)
        require(
            len(fixtures) == 4 and pair in active and pair not in seen,
            f"invalid row: {key}",
        )
        seen.add(pair)
        exercise(cli, lang, key, fixtures)
        counts[lang] += 1
    require(seen, "empty control inventory")
    print(
        json.dumps(
            {
                "controls": counts,
                "manifest_sha256": hashlib.sha256(MANIFEST.read_bytes()).hexdigest(),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scanner", type=Path)
    verify(parser.parse_args().scanner.resolve(strict=True))
