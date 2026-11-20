import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import public_csharp_pilot as pilot
from parity import read_json


class PublicCSharpPilotTests(unittest.TestCase):
    def test_generated_stateless_sources_stay_out_of_whole_scope_totals(self):
        receipt = read_json(pilot.RECEIPT)
        rows = receipt["projects"]
        observed = rows["stateless"]
        self.assertEqual(len(observed["compile_files"]), 60)
        self.assertEqual(observed["sonarqube"]["indexed_files"], 56)
        self.assertEqual(len(observed["not_indexed_by_sonarqube"]), 4)
        self.assertEqual(observed["comparison"], "excluded")
        self.assertEqual(
            pilot.verify_totals(receipt, rows.values())["identical_files"], 101
        )
        observed["comparison"] = "same_source_files"
        observed["shared_parameters_primary_findings"] = dict.fromkeys(
            pilot.MATCH_KEYS, 0
        )
        with self.assertRaisesRegex(ValueError, "scope count differs"):
            pilot.verify_totals(receipt, rows.values())

    def test_raw_proof_requires_exact_hash_after_recorded_normalization(self):
        data = b"\xef\xbb\xbfclass C {}\r\n"
        entry = {"path": "src/C.cs", "sha256": pilot.hash_bytes(data)}
        records = [(entry, data)]
        evidence = {
            "git_input_sha256": entry["sha256"],
            "server_raw_sha256": pilot.hash_bytes(b"class C {}\n\n"),
            "raw_equivalence": "text_equal_after_bom_or_line_ending_normalization",
        }
        row = {
            "indexed_file_bytes": {"src/C.cs": evidence},
            "not_indexed_by_sonarqube": [],
            "sonarqube": {"indexed_files": 1},
            "native_files": 1,
            "comparison": "same_source_files",
            "raw_source_readback": {
                "bom_removed": 1,
                "cr_normalized": 1,
                "one_final_lf_added": 1,
                "one_final_lf_removed": 0,
                "verbatim": 0,
            },
        }
        pilot.verify_source_proof(row, records)
        evidence["server_raw_sha256"] = pilot.hash_bytes(b"class C {}\n")
        with self.assertRaisesRegex(ValueError, "source readback proof differs"):
            pilot.verify_source_proof(row, records)

    def test_build_and_scan_guard_rejects_below_five_gibibytes(self):
        with (
            tempfile.TemporaryDirectory() as temp,
            patch.object(pilot.shutil, "disk_usage") as disk,
        ):
            disk.return_value.free = 5 * 1024**3 - 1
            with self.assertRaisesRegex(RuntimeError, "below 5 GiB"):
                pilot.require_disk(Path(temp))
