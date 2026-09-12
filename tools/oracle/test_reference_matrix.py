import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from reference_matrix import build_reference_rows
from reference_provenance import manifest_digest, package_metadata, validate_manifest


class ReferenceMatrixTests(unittest.TestCase):
    @staticmethod
    def _manifest_with_commit(commit):
        manifest = {
            "schema_version": 1,
            "project": "oracle-py",
            "kind": "sq",
            "repository": {"commit": commit},
            "inputs": {
                "input_sha256": "input",
                "source_root": "src",
                "expected": "expected",
                "catalog": "catalog",
            },
        }
        manifest["manifest_sha256"] = manifest_digest(manifest)
        return manifest

    def test_validate_manifest_accepts_lowercase_hex_commit_without_expected_commit(
        self,
    ):
        manifest = self._manifest_with_commit("a" * 40)
        validated = validate_manifest(
            manifest,
            project="oracle-py",
            kind="sq",
        )
        self.assertEqual(validated["repository"]["commit"], "a" * 40)

    def test_validate_manifest_rejects_nonhex_commit_without_expected_commit(self):
        manifest = self._manifest_with_commit("g" * 40)
        with self.assertRaisesRegex(ValueError, "exact repository commit"):
            validate_manifest(
                manifest,
                project="oracle-py",
                kind="sq",
            )

    def test_validate_manifest_rejects_wrong_length_commit_without_expected_commit(
        self,
    ):
        for commit in ("a" * 39, "a" * 41):
            with self.subTest(length=len(commit)):
                manifest = self._manifest_with_commit(commit)
                with self.assertRaisesRegex(ValueError, "exact repository commit"):
                    validate_manifest(
                        manifest,
                        project="oracle-py",
                        kind="sq",
                    )

    def test_validate_manifest_rejects_explicit_commit_mismatch(self):
        manifest = self._manifest_with_commit("a" * 40)
        with self.assertRaisesRegex(ValueError, "commit mismatch"):
            validate_manifest(
                manifest,
                project="oracle-py",
                kind="sq",
                commit="b" * 40,
            )

    def test_reference_rows_keep_multisets_and_deferred_native_statuses(self):
        expected = [
            {"key": "python:S1", "bad": "s1_bad.py", "good": "s1_good.py"},
            {"key": "python:S2", "bad": "s2_bad.py", "good": "s2_good.py"},
            {
                "key": "python:S3",
                "bad": "s3_bad.py",
                "good": "s3_good.py",
                "upstream_unverified": "upstream contract",
            },
        ]
        sonar = {
            "schema_version": 2,
            "project": "oracle-py",
            "issues": [
                {
                    "rule": "python:S1",
                    "file": "s1_bad.py",
                    "message": "same",
                    "range": {
                        "start": {"line": 1, "column": 1},
                        "end": {"line": 1, "column": 2},
                    },
                },
                {
                    "rule": "python:S1",
                    "file": "s1_bad.py",
                    "message": "same",
                    "range": {
                        "start": {"line": 1, "column": 1},
                        "end": {"line": 1, "column": 2},
                    },
                },
                {
                    "rule": "python:S2",
                    "file": "s2_good.py",
                    "message": "bad good",
                    "range": None,
                },
                {
                    "rule": "python:S9",
                    "file": "unknown.py",
                    "message": "new",
                    "range": None,
                },
            ],
        }
        rows, findings = build_reference_rows(
            expected,
            sonar,
            catalog_keys=["python:S1", "python:S2", "python:S3"],
            available_files=[
                "s1_bad.py",
                "s1_good.py",
                "s2_bad.py",
                "s2_good.py",
                "s3_bad.py",
                "s3_good.py",
            ],
        )
        by_key = {row["key"]: row for row in rows}
        self.assertEqual(by_key["python:S1"]["reference_status"], "REFERENCE_PRESENT")
        self.assertEqual(by_key["python:S1"]["native_status"], "DEFERRED")
        self.assertEqual(by_key["python:S1"]["sonar_bad"][0]["count"], 2)
        self.assertEqual(by_key["python:S2"]["reference_status"], "GOOD_FIRE")
        self.assertEqual(by_key["python:S3"]["reference_status"], "UPSTREAM_UNVERIFIED")
        self.assertEqual(by_key["python:S9"]["reference_status"], "NEW_UPSTREAM_RULE")
        self.assertEqual(findings[-1]["count"], 1)

    def test_package_metadata_includes_nupkg_hash_nuspec_and_signature(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "Example.1.2.3.nupkg"
            package.write_bytes(b"package")
            (root / "Example.1.2.3.nupkg.sha512").write_text("hash\n")
            (root / "Example.nuspec").write_text("<package />\n")
            (root / ".signature.p7s").write_bytes(b"signature")
            metadata = package_metadata(package, root=root)
            names = {item["path"] for item in metadata["sidecars"]}
            self.assertEqual(
                names,
                {"Example.1.2.3.nupkg.sha512", "Example.nuspec", ".signature.p7s"},
            )

    def test_manifest_digest_ignores_only_self_digest(self):
        manifest = {"schema_version": 1, "project": "oracle-py"}
        digest = manifest_digest({**manifest, "manifest_sha256": "stale"})
        self.assertEqual(digest, manifest_digest(manifest))


if __name__ == "__main__":
    unittest.main()
