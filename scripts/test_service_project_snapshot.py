import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

import service_project_snapshot as subject

OTHER = b"EXCLUSIVE_BETA_REPORT_BODY_DO_NOT_COPY"


class ProjectSnapshotTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(directory)
        self.live = self.root / "live.sqlite3"
        self.archive = self.root / "archive.sqlite3"
        self.restored = self.root / "restored.sqlite3"
        self.owner = self.enterContext(
            closing(sqlite3.connect(self.live, isolation_level=None))
        )
        subject.initialize(self.owner, version=2)
        self.owner.execute("PRAGMA journal_mode = WAL")
        self.owner.execute("PRAGMA wal_autocheckpoint = 0")
        self.owner.execute("PRAGMA foreign_keys = ON")
        self.owner.executescript(
            """
            INSERT INTO projects (project, created_at) VALUES ('alpha', 'now'), ('beta', 'now');
            INSERT INTO analyses (id, project, branch, commit_sha, analyzed_at,
                analyzed_epoch, report_schema_version, complete, metrics_json, report_json,
                content_hash, exact_floats)
            VALUES (3,'alpha','main','orig','now',1,1,1,'{}','alpha-content','digest',1),
                   (7,'beta','main','orig','now',1,1,1,'{}','EXCLUSIVE_BETA_REPORT_BODY_DO_NOT_COPY','digest',1),
                   (9,'alpha','main','later','now',2,1,1,'{}','alpha-content','digest',0);
            INSERT INTO findings (analysis_id, identity, occurrence, kind, path, rule_key,
                message, range_json, ambiguous)
            VALUES (3,'a',0,'finding','alpha','rule','message','null',0),
                   (7,'b',0,'finding','beta','rule','message','null',0);
            INSERT INTO reviews (id, project, branch, analysis_id, identity, kind,
                state, version, updated_by, updated_at, reason)
            VALUES (1,'alpha','main',3,'a','finding','resolved',2,'reviewer','now','done'),
                   (2,'beta','main',7,'b','finding','resolved',1,'beta-reviewer','now','done');
            INSERT INTO review_history (review_id, analysis_id, identity, kind,
                previous_state, new_state, actor, reason, created_at, version)
            VALUES (1,3,'a','finding',NULL,'accepted','reviewer','reason','before',1),
                   (1,3,'a','finding','accepted','resolved','reviewer','done','now',2),
                   (2,7,'b','finding',NULL,'resolved','beta-reviewer','done','now',1);
            UPDATE analyses SET deleted_at = 'now' WHERE id = 9;
            INSERT INTO deletion_audit (project, resource_type, analysis_id, action,
                actor, reason, created_at)
            VALUES ('alpha','analysis',9,'delete','admin','reason','now'),
                   ('beta','project',NULL,'delete','beta-admin','reason','now');
            """
        )

    def assert_absent(self, path):
        self.assertFalse(path.exists())
        self.assertEqual(list(self.root.glob(".hoonarqube-project-*")), [])

    def test_wal_export_keeps_one_snapshot_during_concurrent_commit(self):
        self.assertGreater(Path(f"{self.live}-wal").stat().st_size, 0)
        original = subject.verify_selected_project

        def after_selected(db, project, restoring):
            original(db, project, restoring)
            # This transaction commits while the exporting connection holds
            # its source read snapshot, before it copies any table.
            with closing(sqlite3.connect(self.live)) as writer, writer:
                writer.execute(
                    "UPDATE analyses SET report_json = 'changed' WHERE id = 3"
                )
                writer.execute(
                    "UPDATE review_history SET reason = 'changed' WHERE review_id = 1"
                )

        with patch.object(subject, "verify_selected_project", after_selected):
            backup = subject.snapshot(self.live, self.archive, "alpha")
        self.assertEqual(
            backup["rows"],
            dict(
                projects=1,
                analyses=2,
                findings=1,
                reviews=1,
                review_history=2,
                deletion_audit=1,
            ),
        )
        self.assertEqual(backup["sha256"], subject.checksum(self.archive))
        self.assertEqual(stat.S_IMODE(self.archive.stat().st_mode), 0o600)
        self.assertNotIn(OTHER, self.archive.read_bytes())
        result = subject.snapshot(
            self.archive, self.restored, "alpha", backup["sha256"]
        )
        self.assertEqual(result["rows"], backup["rows"])
        self.assertEqual(subject.checksum(self.archive), backup["sha256"])
        subject.require_standalone(self.archive)
        with closing(sqlite3.connect(self.restored)) as restored:
            self.assertEqual(
                restored.execute(
                    "SELECT id, report_json, exact_floats, deleted_at FROM analyses ORDER BY id"
                ).fetchall(),
                [(3, "alpha-content", 1, None), (9, "alpha-content", 0, "now")],
            )
            self.assertEqual(
                restored.execute(
                    "SELECT version, actor, reason FROM review_history ORDER BY version"
                ).fetchall(),
                [(1, "reviewer", "reason"), (2, "reviewer", "done")],
            )
            self.assertEqual(
                restored.execute(
                    "SELECT project, analysis_id, actor FROM deletion_audit"
                ).fetchall(),
                [("alpha", 9, "admin")],
            )
        self.assertEqual(
            self.owner.execute(
                "SELECT report_json FROM analyses WHERE id = 3"
            ).fetchone(),
            ("changed",),
        )

    def test_wrong_project_and_extra_tenant_are_refused(self):
        with self.assertRaisesRegex(subject.SnapshotError, "not in the source"):
            subject.snapshot(self.live, self.archive, "ALPHA")
        self.assert_absent(self.archive)
        backup = subject.snapshot(self.live, self.archive, "alpha")
        with self.assertRaisesRegex(subject.SnapshotError, "not in the source"):
            subject.snapshot(self.archive, self.restored, "beta", backup["sha256"])
        self.assert_absent(self.restored)
        with closing(sqlite3.connect(self.archive)) as db, db:
            db.execute(
                "INSERT INTO projects(project, created_at) VALUES ('beta','now')"
            )
        with self.assertRaisesRegex(subject.SnapshotError, "more than"):
            subject.snapshot(
                self.archive, self.restored, "alpha", subject.checksum(self.archive)
            )
        self.assert_absent(self.restored)

    def test_checksum_and_sqlite_damage_are_refused(self):
        backup = subject.snapshot(self.live, self.archive, "alpha")
        with self.archive.open("r+b") as stream:
            stream.write(b"x" * 16)
        with self.assertRaisesRegex(subject.SnapshotError, "SHA-256"):
            subject.snapshot(self.archive, self.restored, "alpha", backup["sha256"])
        self.assert_absent(self.restored)
        with self.assertRaises(sqlite3.DatabaseError):
            subject.snapshot(
                self.archive, self.restored, "alpha", subject.checksum(self.archive)
            )
        self.assert_absent(self.restored)

    def test_existing_file_sidecar_and_racing_file_are_preserved(self):
        backup = subject.snapshot(self.live, self.archive, "alpha")
        self.restored.write_bytes(b"original")
        with self.assertRaisesRegex(subject.SnapshotError, "already exists"):
            subject.snapshot(self.archive, self.restored, "alpha", backup["sha256"])
        self.assertEqual(self.restored.read_bytes(), b"original")
        self.restored.unlink()

        for suffix in subject.SIDECARS:
            sidecar = Path(str(self.restored) + suffix)
            sidecar.write_bytes(b"sidecar")
            with self.assertRaisesRegex(subject.SnapshotError, "already exists"):
                subject.snapshot(self.archive, self.restored, "alpha", backup["sha256"])
            self.assert_absent(self.restored)
            self.assertEqual(sidecar.read_bytes(), b"sidecar")
            sidecar.unlink()

        link = subject.os.link

        def another_operator_wins(stage, target):
            target.write_bytes(b"racing operator")
            return link(stage, target)

        with patch.object(subject.os, "link", another_operator_wins):
            with self.assertRaises(FileExistsError):
                subject.snapshot(self.archive, self.restored, "alpha", backup["sha256"])
        self.assertEqual(self.restored.read_bytes(), b"racing operator")
        self.assertEqual(list(self.root.glob(".hoonarqube-project-*")), [])

    def test_cross_project_audit_reference_aborts_after_copy(self):
        self.owner.execute(
            "UPDATE deletion_audit SET analysis_id=7 WHERE project='alpha'"
        )
        with self.assertRaisesRegex(subject.SnapshotError, "unrelated analysis"):
            subject.snapshot(self.live, self.archive, "alpha")
        self.assert_absent(self.archive)
        self.assertEqual(
            self.owner.execute(
                "SELECT analysis_id FROM deletion_audit WHERE project='alpha'"
            ).fetchone(),
            (7,),
        )

    def test_disk_full_during_projection_leaves_no_destination(self):
        self.owner.execute(
            "UPDATE analyses SET report_json = ? WHERE id = 9", ("z" * 300_000,)
        )
        backup = subject.snapshot(self.live, self.archive, "alpha")
        original = subject.initialize

        def tiny_target(db, version):
            db.execute("PRAGMA main.page_size = 4096")
            original(db, version)
            pages = db.execute("PRAGMA main.page_count").fetchone()[0]
            self.assertLess(pages, 25)
            db.execute("PRAGMA main.max_page_count = 25")

        with patch.object(subject, "initialize", tiny_target):
            with self.assertRaisesRegex(sqlite3.OperationalError, "full"):
                subject.snapshot(self.archive, self.restored, "alpha", backup["sha256"])
        self.assert_absent(self.restored)
        self.assertEqual(subject.checksum(self.archive), backup["sha256"])


if __name__ == "__main__":
    unittest.main()
