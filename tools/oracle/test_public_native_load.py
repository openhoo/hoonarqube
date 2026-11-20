"""Reject output drift and check the published resource statistics independently."""

import csv
import hashlib
import json
import math
from pathlib import Path
import statistics
import sys
import tempfile
import unittest

from parity import read_json
from public_corpus_summary import canonical_sha
from public_native_load import timed_scan, verify_report

HERE = Path(__file__).resolve().parent
CONTRACT = HERE / "public-native-load-contract-20261120.json"
SAMPLES = HERE / "public-native-load-samples-20261120.csv"
RESULT = HERE / "public-native-load-timing-20261120.json"


class NativeLoadTests(unittest.TestCase):
    def test_spawned_child_is_timed_and_both_streams_are_observed(self):
        previous = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp:
            cwd = Path(tmp).resolve()
            dest = cwd / "sample"
            fields = timed_scan(
                Path(sys.executable),
                ["-c", "import sys; print('report'); print('log',file=sys.stderr)"],
                cwd,
                dest,
                10,
            )
            self.assertGreater(fields["wall_s"], 0)
            self.assertGreater(fields["wait4_maxrss_bytes"], 0)
            self.assertEqual((dest / "stdout").read_bytes(), b"report\n")
            self.assertEqual((dest / "stderr").read_bytes(), b"log\n")
            with self.assertRaisesRegex(ValueError, "nonzero scanner exit"):
                timed_scan(
                    Path(sys.executable),
                    ["-c", "raise SystemExit(3)"],
                    cwd,
                    cwd / "failed",
                    10,
                )
            self.assertEqual(Path.cwd(), previous)

    def test_matching_file_count_cannot_hide_source_or_context_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "source.js"
            source.write_text("let x=1;")
            report = root / "report.json"
            context = {"typescript": "missing"}
            row = {
                "inventory_sha256": canonical_sha(
                    {"source.js": hashlib.sha256(source.read_bytes()).hexdigest()}
                ),
                "metrics": {"files": 1},
                "semantic_context": context,
            }
            report.write_text(
                json.dumps(
                    {
                        "files": [{"path": "source.js"}],
                        "parity": {"semantic_context": context},
                        "project": {"metrics": {"files": 1}, "complete": True},
                    }
                )
            )
            verify_report(report, root, row)
            with self.assertRaises(ValueError):
                verify_report(
                    report,
                    root,
                    {**row, "semantic_context": {"typescript": "available"}},
                )
            source.write_text("let y=1;")
            with self.assertRaises(ValueError):
                verify_report(report, root, row)

    def test_all_published_samples_reproduce_the_release_summary(self):
        summary, contract = read_json(RESULT), read_json(CONTRACT)
        self.assertEqual(
            summary["contract_sha256"],
            hashlib.sha256(CONTRACT.read_bytes()).hexdigest(),
        )
        self.assertEqual(summary["binary_sha256"], contract["release"]["binary_sha256"])
        self.assertEqual(
            summary["samples_csv_sha256"],
            hashlib.sha256(SAMPLES.read_bytes()).hexdigest(),
        )
        with SAMPLES.open(newline="") as f:
            rows = list(csv.DictReader(f))
        self.assertEqual((2, 20), (summary["warmups"], summary["rounds"]))
        self.assertEqual(set(summary["projects"]), set(contract["projects"]))
        self.assertEqual(set(row["project"] for row in rows), set(contract["projects"]))
        for name, metrics in summary["projects"].items():
            runs = [r for r in rows if r["project"] == name]
            with self.subTest(project=name):
                self.assertEqual(list(range(-2, 20)), [int(r["round"]) for r in runs])
                for field, stats in metrics.items():
                    values = sorted(float(r[field]) for r in runs[2:])
                    self.assertTrue(all(math.isfinite(v) and v >= 0 for v in values))
                    self.assertEqual(
                        {
                            "min": values[0],
                            "p50": statistics.median(values),
                            "p95": values[18],
                            "max": values[-1],
                        },
                        stats,
                    )
