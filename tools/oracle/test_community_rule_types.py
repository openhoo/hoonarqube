import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import community_rule_types as rules


class RuleTypeEvidence(unittest.TestCase):
    def test_two_page_profile_rejects_gaps_duplicates_stale_totals_and_wrong_bindings(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            catalog = root / "catalog"
            (catalog / "rules").mkdir(parents=True)
            (catalog / "snapshot.toml").write_text(
                'catalog_sha256 = "' + "a" * 64 + '"'
            )

            def save(name, data):
                (root / name).write_text(json.dumps(data))

            save(
                "env.json",
                {
                    "server": {"version": rules.VERSION, "status": "UP"},
                    "server_image": {"image": rules.IMAGE},
                },
            )
            save(
                "profiles.json",
                {
                    "profiles": [
                        {
                            "key": "js-id",
                            "name": "Sonar way",
                            "language": "js",
                            "isBuiltIn": True,
                            "isDefault": True,
                            "activeRuleCount": 2,
                        }
                    ]
                },
            )
            save(
                "catalog/rules/javascript.json",
                {
                    "language": "js",
                    "rules": [
                        {"external_key": "js:active", "rule_type": "SECURITY_HOTSPOT"},
                        {"external_key": "js:inactive", "rule_type": "BUG"},
                    ],
                },
            )
            for page, key in enumerate(("js:active", "js:reference-only"), 1):
                for prefix in ("active", "effective"):
                    data = {
                        "p": page,
                        "ps": 1,
                        "total": 2,
                        "paging": {"pageIndex": page, "pageSize": 1, "total": 2},
                        "rules": [{"key": key, "type": "VULNERABILITY", "lang": "js"}],
                    }
                    if prefix == "effective":
                        data["actives"] = {key: [{"qProfile": "js-id"}]}
                    save(f"{prefix}-js-page-{page}.json", data)
            with patch.dict(rules.LANGS, {"javascript": "js"}, clear=True):

                def run():
                    rules.audit(root, root, root / "env.json", catalog, root / "out")

                run()
                table = (root / "out" / rules.TABLE).read_text()
                self.assertIn("js:reference-only\tVULNERABILITY", table)
                self.assertIn("js:inactive\tNOT_ACTIVE", table)
                for name, change in [
                    (
                        "active-js-page-2.json",
                        lambda d: d["rules"][0].update(key="js:active"),
                    ),
                    (
                        "effective-js-page-2.json",
                        lambda d: d["actives"]["js:reference-only"][0].update(
                            qProfile="other"
                        ),
                    ),
                    (
                        "effective-js-page-1.json",
                        lambda d: d["rules"][0].update(type="BUG"),
                    ),
                    ("active-js-page-2.json", lambda d: d["paging"].update(total=3)),
                ]:
                    path = root / name
                    raw = path.read_bytes()
                    data = json.loads(raw)
                    change(data)
                    save(name, data)
                    with self.assertRaises(ValueError):
                        run()
                    path.write_bytes(raw)
                (root / "active-js-page-2.json").unlink()
                with self.assertRaises(FileNotFoundError):
                    run()
