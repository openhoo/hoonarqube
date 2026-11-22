use rusqlite::{Connection, TransactionBehavior};

use super::StoreError;

const SCHEMA_VERSION: i64 = 3;
const CREATE_V1: &str = include_str!("schema_v1.sql");
const MIGRATE_V2: &str = include_str!("migrate_v2.sql");
const ENSURE_V1_INDEXES: &str = include_str!("indexes_v1.sql");
const ENSURE_V2_INDEXES: &str = include_str!("indexes_v2.sql");

pub(super) fn initialize(connection: &mut Connection) -> Result<(), StoreError> {
    connection.pragma_update(None, "foreign_keys", true)?;
    // Take the writer lock before inspecting the version; a second process
    // opening the same new file must observe the first initializer's commit.
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let version: i64 = tx.pragma_query_value(None, "user_version", |row| row.get(0))?;
    match version {
        0 => {
            let occupied: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE substr(name, 1, 7) <> 'sqlite_')",
                [],
                |row| row.get(0),
            )?;
            if occupied {
                return Err(StoreError::Invalid(
                    "refusing to initialize a nonempty unversioned database".into(),
                ));
            }
            tx.execute_batch(CREATE_V1)?;
        }
        1..=SCHEMA_VERSION => {
            // Legacy v1 databases have no application_id. Verify that their
            // service tables exist before changing the persistent journal mode.
            let complete: bool = tx.query_row(
                "SELECT count(*) = 6 FROM sqlite_schema WHERE type = 'table' AND name IN
                    ('projects','analyses','findings','reviews','review_history','deletion_audit')",
                [],
                |row| row.get(0),
            )?;
            if !complete {
                return Err(StoreError::Invalid(format!(
                    "expected service tables are missing from schema version {version}"
                )));
            }
        }
        other => {
            return Err(StoreError::Invalid(format!(
                "unsupported database schema version {other}; this binary supports {SCHEMA_VERSION}"
            )));
        }
    }
    if version < 2 {
        tx.execute_batch(MIGRATE_V2)?;
    }
    if version < SCHEMA_VERSION {
        tx.execute_batch(include_str!("migrate_v3.sql"))?;
        tx.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    let has_policy_schema: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='project_gate_policies')
         AND (SELECT count(*) FROM pragma_table_info('project_gate_policies')
              WHERE name IN ('project','version','config_json','updated_by','updated_at')) = 5
         AND (SELECT count(*) FROM pragma_table_info('analyses')
              WHERE name IN ('gate_policy_version','assigned_gate_json')) = 2",
        [], |row| row.get(0),
    )?;
    if !has_policy_schema {
        return Err(StoreError::Invalid(
            "missing project gate policy schema".into(),
        ));
    }
    // Releases through 0.11.1 re-created missing service indexes on open.
    // IF NOT EXISTS keeps an intact schema unchanged on ordinary restarts.
    tx.execute_batch(ENSURE_V1_INDEXES)?;
    tx.execute_batch(ENSURE_V2_INDEXES)?;
    tx.commit()?;
    connection.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn version(connection: &Connection) -> i64 {
        connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap()
    }

    fn tables(connection: &Connection) -> Vec<String> {
        connection
            .prepare("SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn schema_initializes_once_and_preserves_existing_rows() {
        let mut db = Connection::open_in_memory().unwrap();
        initialize(&mut db).unwrap();
        assert_eq!(version(&db), SCHEMA_VERSION);
        db.execute(
            "INSERT INTO projects(project, created_at) VALUES ('existing', 'yesterday')",
            [],
        )
        .unwrap();
        let schema_cookie: i64 = db
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .unwrap();
        initialize(&mut db).unwrap();
        let reopened_cookie: i64 = db
            .pragma_query_value(None, "schema_version", |row| row.get(0))
            .unwrap();
        assert_eq!(schema_cookie, reopened_cookie);
        assert_eq!(
            db.query_row("SELECT project FROM projects", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "existing"
        );
    }

    #[test]
    fn v2_migration_preserves_unassigned_analyses_and_reports() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch(CREATE_V1).unwrap();
        db.execute_batch(MIGRATE_V2).unwrap();
        db.pragma_update(None, "user_version", 2).unwrap();
        db.execute_batch(
            "INSERT INTO projects(project, created_at) VALUES('legacy','before');
             INSERT INTO analyses(project,branch,commit_sha,analyzed_at,analyzed_epoch,
                 report_schema_version,complete,metrics_json,gate_json,report_json,content_hash,exact_floats)
             VALUES('legacy','main','base','before',1,1,1,'{}','{}','original bytes','original hash',1);"
        ).unwrap();
        initialize(&mut db).unwrap();
        assert_eq!(version(&db), 3);
        let untouched: bool = db.query_row(
            "SELECT report_json='original bytes' AND content_hash='original hash' AND gate_json='{}'
             AND exact_floats=1 AND gate_policy_version IS NULL AND assigned_gate_json IS NULL
             FROM analyses WHERE project='legacy'", [], |row| row.get(0),
        ).unwrap();
        assert!(untouched);
        db.execute_batch("DROP TABLE project_gate_policies")
            .unwrap();
        assert!(matches!(initialize(&mut db), Err(StoreError::Invalid(_))));
    }

    #[test]
    fn schema_reopens_v1_with_missing_service_indexes() {
        fn named_indexes(db: &Connection) -> Vec<(String, String)> {
            db.prepare("SELECT name, sql FROM sqlite_schema WHERE type = 'index' AND sql IS NOT NULL ORDER BY name")
                .unwrap()
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }

        let mut db = Connection::open_in_memory().unwrap();
        initialize(&mut db).unwrap();
        let expected = named_indexes(&db);
        db.execute_batch("DROP INDEX findings_analysis; DROP INDEX review_history_review;")
            .unwrap();
        assert_eq!(named_indexes(&db).len() + 2, expected.len());

        initialize(&mut db).unwrap();
        assert_eq!(version(&db), SCHEMA_VERSION);
        assert_eq!(named_indexes(&db), expected);
    }

    #[test]
    fn schema_refuses_foreign_partial_and_future_databases_without_changes() {
        for unsupported in [0, 1, SCHEMA_VERSION, SCHEMA_VERSION + 1] {
            let mut db = Connection::open_in_memory().unwrap();
            db.execute_batch("CREATE TABLE existing_data (value TEXT); INSERT INTO existing_data VALUES ('keep');").unwrap();
            db.pragma_update(None, "user_version", unsupported).unwrap();

            assert!(matches!(initialize(&mut db), Err(StoreError::Invalid(_))));
            assert_eq!(version(&db), unsupported);
            assert_eq!(tables(&db), ["existing_data"]);
            assert_eq!(
                db.query_row("SELECT value FROM existing_data", [], |row| row
                    .get::<_, String>(0))
                    .unwrap(),
                "keep"
            );
        }
    }

    #[test]
    fn schema_creation_failure_rolls_back_all_tables_and_version() {
        let mut db = Connection::open_in_memory().unwrap();
        db.execute_batch("PRAGMA page_size = 512; PRAGMA max_page_count = 4;")
            .unwrap();
        assert!(matches!(initialize(&mut db), Err(StoreError::Sql(_))));
        assert_eq!(version(&db), 0);
        assert!(tables(&db).is_empty());

        db.pragma_update(None, "max_page_count", 10000).unwrap();
        initialize(&mut db).unwrap();
        assert_eq!(version(&db), SCHEMA_VERSION);
    }
}
