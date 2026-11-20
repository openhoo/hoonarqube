"""Controls for timing claims tied to the earlier independent Go capture."""

import unittest

from parity import read_json
from pathlib import Path
from public_go_pipeline import compare, contract


class GoPipelineContractTests(unittest.TestCase):
    def test_every_pinned_reference_is_accepted(self):
        rows = read_json(Path(__file__).with_name("public-go-pipeline-contract.json"))
        for name, contract_ in rows.items():
            with self.subTest(name=name):
                compare(name, contract_, dict(contract_))

    def test_equally_wrong_results_cannot_qualify(self):
        expected = read_json(
            Path(__file__).with_name("public-go-pipeline-contract.json")
        )["chi"]
        for field, value in [
            ("inventory_sha256", "changed"),
            ("primaries_sha256", "wrong"),
            ("no_todo_gate", "pass"),
        ]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                bad = {**expected, field: value}
                compare("chi", bad, bad)

    def test_counts_do_not_hide_a_changed_column_or_duplicate(self):
        paths = {"main.go": "a"}
        baseline = [
            ("go:S1135", "main.go", 1, 0, 1, 4),
            ("go:S1135", "main.go", 1, 5, 1, 9),
        ]
        original = contract(paths, baseline)
        self.assertEqual(original, contract(paths, list(reversed(baseline))))
        for other in (
            [baseline[0], baseline[0]],
            [baseline[0], ("go:S1135", "main.go", 1, 5, 1, 8)],
        ):
            changed = contract(paths, other)
            self.assertEqual(original["primaries"], changed["primaries"])
            self.assertNotEqual(
                original["primaries_sha256"], changed["primaries_sha256"]
            )

    def test_unknown_file_is_not_silently_dropped(self):
        with self.assertRaises(ValueError):
            contract({"actual.go": "a"}, [("go:S1186", "missing.go", 1, 0, 1, 4)])
