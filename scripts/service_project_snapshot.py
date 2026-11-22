#!/usr/bin/env python3
"""Export or restore one Hoonarqube project using the service's SQLite schema."""

import argparse
import hashlib
import json
import os
import re
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path

SCHEMA = Path(__file__).resolve().parents[1] / "crates/hoonarqube-service/src/store"
TABLES = (
    "projects",
    "analyses",
    "findings",
    "reviews",
    "review_history",
    "deletion_audit",
)
SIDECARS = ("-wal", "-shm", "-journal")

COPY = (
    """INSERT INTO projects SELECT p.* FROM source.projects p
       WHERE p.project COLLATE BINARY = ?""",
    """INSERT INTO analyses SELECT a.* FROM source.analyses a
       WHERE a.project COLLATE BINARY = ?""",
    """INSERT INTO findings SELECT f.* FROM source.analyses a
       CROSS JOIN source.findings f ON f.analysis_id = a.id
       WHERE a.project COLLATE BINARY = ?""",
    """INSERT INTO reviews SELECT r.* FROM source.reviews r
       WHERE r.project COLLATE BINARY = ?""",
    """INSERT INTO review_history SELECT h.* FROM source.reviews r
       CROSS JOIN source.review_history h ON h.review_id = r.id
       WHERE r.project COLLATE BINARY = ?""",
    """INSERT INTO deletion_audit SELECT d.* FROM source.deletion_audit d
       WHERE d.project COLLATE BINARY = ?""",
)


class SnapshotError(Exception):
    pass


def checksum(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require_unused(path):
    if path.name.endswith(SIDECARS):
        raise SnapshotError("destination name is reserved for a SQLite sidecar")
    for name in (path, *(Path(str(path) + suffix) for suffix in SIDECARS)):
        if os.path.lexists(name):
            raise SnapshotError(f"destination or SQLite sidecar already exists: {name}")


def require_standalone(path):
    if any(os.path.lexists(str(path) + suffix) for suffix in SIDECARS):
        raise SnapshotError(
            "snapshot must be a closed standalone file without SQLite sidecars"
        )


POLICY_TABLE = "project_gate_policies"
POLICY_COPY = "INSERT INTO project_gate_policies SELECT * FROM source.project_gate_policies WHERE project COLLATE BINARY = ?"


def initialize(db, version=3):
    if version not in (2, 3):
        raise SnapshotError(
            "expected a Hoonarqube service database at schema version 2 or 3"
        )
    for filename in (
        "schema_v1.sql",
        "migrate_v2.sql",
        *(("migrate_v3.sql",) if version == 3 else ()),
        "indexes_v1.sql",
        "indexes_v2.sql",
    ):
        db.executescript((SCHEMA / filename).read_text(encoding="utf-8"))
    if version == 3:
        db.execute("PRAGMA main.user_version = 3")
    else:
        db.execute("PRAGMA main.user_version = 2")


def verify_source(db, tables):
    objects = db.execute(
        """SELECT type, name FROM source.sqlite_schema
           WHERE type IN ('table', 'view', 'trigger') AND substr(name, 1, 7) <> 'sqlite_'"""
    )
    if set(objects) != {("table", name) for name in tables}:
        raise SnapshotError("source does not have the expected service tables")

    # The copy statements use the service table column order. Reject schema
    # changes before copying rather than silently remapping columns by position.
    for table in tables:
        columns = db.execute(
            "SELECT * FROM pragma_table_xinfo(?, 'source') ORDER BY cid", (table,)
        ).fetchall()
        expected = db.execute(
            "SELECT * FROM pragma_table_xinfo(?, 'main') ORDER BY cid", (table,)
        ).fetchall()
        if columns != expected:
            raise SnapshotError(f"unexpected service table structure: {table}")


def verify_selected_project(db, project, restoring):
    if not db.execute(
        "SELECT 1 FROM source.projects WHERE project COLLATE BINARY = ?", (project,)
    ).fetchone():
        raise SnapshotError("requested project is not in the source")
    if (
        restoring
        and db.execute(
            "SELECT 1 FROM source.projects WHERE project COLLATE BINARY <> ? LIMIT 1",
            (project,),
        ).fetchone()
    ):
        raise SnapshotError("snapshot contains more than the requested project")


def verify_projection(db, restoring, counts):
    if db.execute("PRAGMA main.foreign_key_check").fetchone():
        raise SnapshotError("project records reference missing or unrelated rows")
    if db.execute(
        """SELECT 1 FROM deletion_audit d LEFT JOIN analyses a ON a.id = d.analysis_id
           WHERE d.analysis_id IS NOT NULL AND a.id IS NULL LIMIT 1"""
    ).fetchone():
        raise SnapshotError(
            "project deletion audit references a missing or unrelated analysis"
        )
    if (
        POLICY_TABLE in counts
        and db.execute(
            """SELECT 1 FROM analyses a LEFT JOIN project_gate_policies p
        ON p.project=a.project AND p.version=a.gate_policy_version
        WHERE (a.gate_policy_version IS NULL) <> (a.assigned_gate_json IS NULL)
        OR (a.gate_policy_version IS NOT NULL AND p.version IS NULL) LIMIT 1"""
        ).fetchone()
    ):
        raise SnapshotError("analysis references a missing gate policy")
    if db.execute("PRAGMA main.integrity_check").fetchall() != [("ok",)]:
        raise SnapshotError("staged database failed its integrity check")
    if restoring:
        # Refuse archives with rows outside the projection, even if their
        # checksums were supplied. This catches detached records as well.
        total = dict(
            db.execute(
                """SELECT 'projects', count(*) FROM source.projects
               UNION ALL SELECT 'analyses', count(*) FROM source.analyses
               UNION ALL SELECT 'findings', count(*) FROM source.findings
               UNION ALL SELECT 'reviews', count(*) FROM source.reviews
               UNION ALL SELECT 'review_history', count(*) FROM source.review_history
               UNION ALL SELECT 'deletion_audit', count(*) FROM source.deletion_audit"""
            )
        )
        if POLICY_TABLE in counts:
            total[POLICY_TABLE] = db.execute(
                "SELECT count(*) FROM source.project_gate_policies"
            ).fetchone()[0]
        if total != counts:
            raise SnapshotError(
                "snapshot contains records outside the requested project"
            )


def project_copy(source, stage, project, restoring):
    # An unmodified archive has no active journal; the live source may have
    # committed rows in WAL, so open the live source without immutable mode.
    uri = source.as_uri() + ("?mode=ro&immutable=1" if restoring else "?mode=ro")
    with closing(sqlite3.connect(stage, uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA trusted_schema = OFF")
        # Defer constraints until the complete projection can be diagnosed.
        db.execute("PRAGMA foreign_keys = ON")
        db.execute("PRAGMA main.journal_mode = DELETE")
        db.execute("ATTACH DATABASE ? AS source", (uri,))
        version = db.execute("PRAGMA source.user_version").fetchone()[0]
        initialize(db, version)
        tables = TABLES + ((POLICY_TABLE,) if version == 3 else ())
        statements = COPY + ((POLICY_COPY,) if version == 3 else ())
        db.execute("BEGIN")
        db.execute("PRAGMA defer_foreign_keys = ON")
        verify_source(db, tables)
        verify_selected_project(db, project, restoring)
        counts = {
            table: db.execute(statement, (project,)).rowcount
            for table, statement in zip(tables, statements, strict=True)
        }
        verify_projection(db, restoring, counts)
        db.execute("COMMIT")
        return counts


def snapshot(source, target, project, expected_sha256=None):
    if (
        not project
        or len(project.encode()) > 256
        or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in project)
    ):
        raise SnapshotError("invalid project identifier")
    source = source.resolve(strict=True)
    if not source.is_file():
        raise SnapshotError("source must be a regular file")
    target = target.parent.resolve(strict=True) / target.name
    require_unused(target)
    restoring = expected_sha256 is not None
    if restoring:
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
            raise SnapshotError(
                "expected SHA-256 must be 64 lowercase hexadecimal digits"
            )
        require_standalone(source)
        if checksum(source) != expected_sha256:
            raise SnapshotError("snapshot SHA-256 does not match the trusted receipt")

    # The private sibling directory keeps the incomplete DB and any rollback
    # journal invisible at the requested destination, on the same filesystem.
    with tempfile.TemporaryDirectory(
        prefix=".hoonarqube-project-", dir=target.parent
    ) as tmp:
        stage = Path(tmp) / "project.sqlite3"
        counts = project_copy(source, stage, project, restoring)
        if restoring:
            require_standalone(source)
            if checksum(source) != expected_sha256:
                raise SnapshotError("snapshot changed during restore")
        stage.chmod(0o600)
        digest = checksum(stage)
        size = stage.stat().st_size
        with stage.open("rb") as stream:
            os.fsync(stream.fileno())
        require_unused(target)
        # Linking an existing file is atomic and fails if the target exists,
        # including a target created concurrently after the last check.
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.link(stage, target)
            os.fsync(directory)
        finally:
            os.close(directory)
    return {
        "project": project,
        "destination": str(target),
        "bytes": size,
        "sha256": digest,
        "rows": counts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="operation", required=True)
    for mode in ("export", "restore"):
        command = modes.add_parser(mode)
        command.add_argument("--project", required=True)
        command.add_argument("source", type=Path)
        command.add_argument("destination", type=Path)
        if mode == "restore":
            command.add_argument(
                "--sha256", required=True, help="SHA-256 from the backup receipt"
            )
    args = parser.parse_args()
    try:
        result = snapshot(
            args.source, args.destination, args.project, getattr(args, "sha256", None)
        )
    except (SnapshotError, OSError, sqlite3.Error, ValueError) as error:
        print(f"project snapshot: {error}", file=sys.stderr)
        return 1
    print(json.dumps({"operation": args.operation, **result}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
