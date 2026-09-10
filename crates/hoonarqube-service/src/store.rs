use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    BackupEnvelope, DeletionRecord, FindingKind, FindingRecordInput, IngestData, ReviewRequest,
    ReviewState, ValidatedRestore,
};

#[derive(Debug)]
pub(crate) enum StoreError {
    Sql(rusqlite::Error),
    Conflict(String),
    NotFound,
    Invalid(String),
}
impl Display for StoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sql(error) => write!(formatter, "database error: {error}"),
            Self::Conflict(message) => write!(formatter, "database conflict: {message}"),
            Self::NotFound => formatter.write_str("record not found"),
            Self::Invalid(message) => write!(formatter, "invalid database state: {message}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sql(error) => Some(error),
            Self::Conflict(_) | Self::NotFound | Self::Invalid(_) => None,
        }
    }
}

impl From<rusqlite::Error> for StoreError {
    fn from(error: rusqlite::Error) -> Self {
        Self::Sql(error)
    }
}
fn to_sqlite_u64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value)
        .map_err(|_| StoreError::Invalid("version exceeds SQLite integer range".to_string()))
}

fn from_sqlite_u64(value: i64, column: usize) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            column,
            rusqlite::types::Type::Integer,
            Box::new(error),
        )
    })
}
type ExistingAnalysis = (
    i64,
    String,
    Option<String>,
    u32,
    bool,
    String,
    Option<String>,
    Option<String>,
);
type RawFinding = (String, u32, String, String, String, String, String, bool);
type StoredHistory = (
    i64,
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    u64,
);

struct ReviewWrite<'a> {
    project: &'a str,
    branch: &'a str,
    request: &'a ReviewRequest,
    actor: &'a str,
    now: &'a str,
    existing: Option<&'a ReviewRecord>,
    version_sql: i64,
    expected_version_sql: i64,
}

#[derive(Clone)]
pub(crate) struct Store {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AnalysisSummary {
    pub id: i64,
    pub project: String,
    pub branch: String,
    pub commit: String,
    pub analyzed_at: String,
    pub report_schema_version: u32,
    pub complete: bool,
    pub metrics: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplication: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AnalysisDetail {
    #[serde(flatten)]
    pub summary: AnalysisSummary,
    pub report: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assessment: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FindingRecord {
    pub identity: String,
    pub occurrence: u32,
    pub kind: FindingKind,
    pub path: String,
    pub rule_key: String,
    pub message: String,
    pub range: Value,
    pub status: String,
    pub ambiguous: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub review: Option<ReviewRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReviewRecord {
    pub id: i64,
    pub project: String,
    pub branch: String,
    pub analysis_id: i64,
    pub identity: String,
    pub kind: FindingKind,
    pub state: ReviewState,
    pub version: u64,
    pub updated_by: String,
    pub updated_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HistoryRecord {
    pub id: i64,
    pub review_id: i64,
    pub analysis_id: i64,
    pub identity: String,
    pub kind: FindingKind,
    pub previous_state: Option<ReviewState>,
    pub new_state: ReviewState,
    pub actor: String,
    pub reason: String,
    pub created_at: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProjectSummary {
    pub project: String,
    pub branches: Vec<String>,
    pub analysis_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_analysis: Option<AnalysisSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IngestResult {
    pub analysis: AnalysisSummary,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ReviewMutation {
    pub review: ReviewRecord,
    pub history: HistoryRecord,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RetentionResult {
    pub deleted: u64,
    pub before: String,
    pub branch: Option<String>,
}
pub(crate) struct RetentionInput<'a> {
    pub(crate) project: &'a str,
    pub(crate) before: &'a str,
    pub(crate) before_epoch: i64,
    pub(crate) branch: Option<&'a str>,
    pub(crate) actor: &'a str,
    pub(crate) reason: &'a str,
    pub(crate) now: &'a str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RestoreResult {
    pub project: String,
    pub analyses: u64,
    pub findings: u64,
    pub reviews: u64,
    pub history: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BackupAnalysis {
    pub id: i64,
    pub branch: String,
    pub commit: String,
    pub analyzed_at: String,
    pub analyzed_epoch: i64,
    pub report_schema_version: u32,
    pub complete: bool,
    pub metrics: Value,
    #[serde(default)]
    pub duplication: Option<Value>,
    #[serde(default)]
    pub gate: Option<Value>,
    pub report: Value,
    #[serde(default)]
    pub assessment: Option<Value>,
    pub content_hash: String,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BackupFinding {
    pub analysis_id: i64,
    pub identity: String,
    pub occurrence: u32,
    pub kind: FindingKind,
    pub path: String,
    pub rule_key: String,
    pub message: String,
    pub range: Value,
    pub ambiguous: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BackupReview {
    pub id: i64,
    pub project: String,
    pub branch: String,
    pub analysis_id: i64,
    pub identity: String,
    pub kind: FindingKind,
    pub state: ReviewState,
    pub version: u64,
    pub updated_by: String,
    pub updated_at: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BackupHistory {
    pub id: i64,
    pub review_id: i64,
    pub analysis_id: i64,
    pub identity: String,
    pub kind: FindingKind,
    pub previous_state: Option<ReviewState>,
    pub new_state: ReviewState,
    pub actor: String,
    pub reason: String,
    pub created_at: String,
    pub version: u64,
}

impl Store {
    pub(crate) fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let connection = Connection::open(path).map_err(StoreError::Sql)?;
        let store = Self {
            connection: Arc::new(Mutex::new(connection)),
        };
        store.initialize()?;
        Ok(store)
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>, StoreError> {
        self.connection
            .lock()
            .map_err(|_| StoreError::Invalid("database lock poisoned".to_string()))
    }

    fn initialize(&self) -> Result<(), StoreError> {
        let connection = self.lock()?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS projects (
                 project TEXT PRIMARY KEY NOT NULL,
                 created_at TEXT NOT NULL,
                 deleted_at TEXT,
                 deleted_by TEXT,
                 deletion_reason TEXT
             );
             CREATE TABLE IF NOT EXISTS analyses (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 project TEXT NOT NULL REFERENCES projects(project),
                 branch TEXT NOT NULL,
                 commit_sha TEXT NOT NULL,
                 analyzed_at TEXT NOT NULL,
                 analyzed_epoch INTEGER NOT NULL,
                 report_schema_version INTEGER NOT NULL,
                 complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
                 metrics_json TEXT NOT NULL,
                 duplication_json TEXT,
                 gate_json TEXT,
                 report_json TEXT NOT NULL,
                 assessment_json TEXT,
                 content_hash TEXT NOT NULL,
                 deleted_at TEXT,
                 deleted_by TEXT,
                 deletion_reason TEXT,
                 UNIQUE(project, branch, commit_sha)
             );
             CREATE INDEX IF NOT EXISTS analyses_project_branch_time
                 ON analyses(project, branch, analyzed_epoch DESC, id DESC);
             CREATE TABLE IF NOT EXISTS findings (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 analysis_id INTEGER NOT NULL REFERENCES analyses(id),
                 identity TEXT NOT NULL,
                 occurrence INTEGER NOT NULL CHECK (occurrence >= 0),
                 kind TEXT NOT NULL,
                 path TEXT NOT NULL,
                 rule_key TEXT NOT NULL,
                 message TEXT NOT NULL,
                 range_json TEXT NOT NULL,
                 ambiguous INTEGER NOT NULL CHECK (ambiguous IN (0, 1)),
                 UNIQUE(analysis_id, identity, kind, occurrence)
             );
             CREATE INDEX IF NOT EXISTS findings_analysis ON findings(analysis_id);
             CREATE TABLE IF NOT EXISTS reviews (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 project TEXT NOT NULL REFERENCES projects(project),
                 branch TEXT NOT NULL,
                 analysis_id INTEGER NOT NULL REFERENCES analyses(id),
                 identity TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 state TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK (version > 0),
                 updated_by TEXT NOT NULL,
                 updated_at TEXT NOT NULL,
                 reason TEXT NOT NULL,
                 UNIQUE(project, branch, identity, kind)
             );
             CREATE INDEX IF NOT EXISTS reviews_project_branch
                 ON reviews(project, branch, updated_at DESC, id DESC);
             CREATE TABLE IF NOT EXISTS review_history (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 review_id INTEGER NOT NULL REFERENCES reviews(id),
                 analysis_id INTEGER NOT NULL REFERENCES analyses(id),
                 identity TEXT NOT NULL,
                 kind TEXT NOT NULL,
                 previous_state TEXT,
                 new_state TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 reason TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 version INTEGER NOT NULL CHECK (version > 0),
                 UNIQUE(review_id, version)
             );
             CREATE INDEX IF NOT EXISTS review_history_review
                 ON review_history(review_id, version ASC);
             CREATE TABLE IF NOT EXISTS deletion_audit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 project TEXT NOT NULL,
                 resource_type TEXT NOT NULL,
                 analysis_id INTEGER,
                 action TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 reason TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );
             PRAGMA user_version = 1;",
        )?;
        Ok(())
    }

    pub(crate) fn list_projects(&self) -> Result<Vec<ProjectSummary>, StoreError> {
        let connection = self.lock()?;
        let mut statement = connection.prepare(
            "SELECT project FROM projects WHERE deleted_at IS NULL ORDER BY project ASC",
        )?;
        let projects: Vec<String> = statement
            .query_map([], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        drop(statement);

        projects
            .into_iter()
            .map(|project| Self::project_summary_with_connection(&connection, &project))
            .collect()
    }

    fn project_summary_with_connection(
        connection: &Connection,
        project: &str,
    ) -> Result<ProjectSummary, StoreError> {
        let mut branches_statement = connection.prepare(
            "SELECT DISTINCT branch FROM analyses
             WHERE project = ?1 AND deleted_at IS NULL ORDER BY branch ASC",
        )?;
        let branches: Vec<String> = branches_statement
            .query_map([project], |row| row.get(0))?
            .collect::<Result<_, _>>()?;
        let analysis_count: u64 = connection.query_row(
            "SELECT COUNT(*) FROM analyses WHERE project = ?1 AND deleted_at IS NULL",
            [project],
            |row| from_sqlite_u64(row.get(0)?, 0),
        )?;

        let latest = connection
            .query_row(
                "SELECT id, project, branch, commit_sha, analyzed_at, report_schema_version,
                        complete, metrics_json, duplication_json, gate_json
                 FROM analyses
                 WHERE project = ?1 AND deleted_at IS NULL
                 ORDER BY analyzed_epoch DESC, id DESC LIMIT 1",
                [project],
                summary_from_row,
            )
            .optional()?;
        Ok(ProjectSummary {
            project: project.to_string(),
            branches,
            analysis_count,
            latest_analysis: latest,
        })
    }

    pub(crate) fn list_branches(&self, project: &str) -> Result<Vec<BranchSummary>, StoreError> {
        let connection = self.lock()?;
        ensure_active_project(&connection, project)?;
        let mut statement = connection.prepare(
            "SELECT branch,
                    COUNT(*) FILTER (WHERE deleted_at IS NULL),
                    (SELECT a2.id FROM analyses a2
                     WHERE a2.project = ?1 AND a2.branch = a.branch
                       AND a2.deleted_at IS NULL
                     ORDER BY a2.analyzed_epoch DESC, a2.id DESC LIMIT 1),
                    (SELECT a2.commit_sha FROM analyses a2
                     WHERE a2.project = ?1 AND a2.branch = a.branch
                       AND a2.deleted_at IS NULL
                     ORDER BY a2.analyzed_epoch DESC, a2.id DESC LIMIT 1),
                    (SELECT a2.analyzed_at FROM analyses a2
                     WHERE a2.project = ?1 AND a2.branch = a.branch
                       AND a2.deleted_at IS NULL
                     ORDER BY a2.analyzed_epoch DESC, a2.id DESC LIMIT 1)
             FROM analyses a
             WHERE a.project = ?1 AND a.deleted_at IS NULL
             GROUP BY a.branch ORDER BY a.branch ASC",
        )?;
        let rows = statement
            .query_map([project], |row| {
                Ok(BranchSummary {
                    name: row.get(0)?,
                    analysis_count: from_sqlite_u64(row.get(1)?, 1)?,

                    latest_analysis_id: row.get(2)?,
                    latest_commit: row.get(3)?,
                    latest_analyzed_at: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub(crate) fn list_analyses(
        &self,
        project: &str,
        branch: Option<&str>,
    ) -> Result<Vec<AnalysisSummary>, StoreError> {
        let connection = self.lock()?;
        ensure_active_project(&connection, project)?;
        let mut statement = connection.prepare(
            "SELECT id, project, branch, commit_sha, analyzed_at, report_schema_version,
                    complete, metrics_json, duplication_json, gate_json
             FROM analyses
             WHERE project = ?1 AND deleted_at IS NULL
               AND (?2 IS NULL OR branch = ?2)
             ORDER BY analyzed_epoch DESC, id DESC",
        )?;
        let rows = statement
            .query_map(rusqlite::params![project, branch], summary_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub(crate) fn get_analysis(
        &self,
        project: &str,
        id: i64,
    ) -> Result<AnalysisDetail, StoreError> {
        let connection = self.lock()?;
        ensure_active_project(&connection, project)?;
        connection
            .query_row(
                "SELECT id, project, branch, commit_sha, analyzed_at, report_schema_version,
                        complete, metrics_json, duplication_json, gate_json,
                        report_json, assessment_json
                 FROM analyses
                 WHERE id = ?1 AND project = ?2 AND deleted_at IS NULL",
                params![id, project],
                detail_from_row,
            )
            .optional()?
            .ok_or(StoreError::NotFound)
    }

    pub(crate) fn findings(
        &self,
        project: &str,
        analysis_id: i64,
    ) -> Result<Vec<FindingRecord>, StoreError> {
        let connection = self.lock()?;
        ensure_active_project(&connection, project)?;
        let branch: String = connection
            .query_row(
                "SELECT branch FROM analyses
                 WHERE id = ?1 AND project = ?2 AND deleted_at IS NULL",
                params![analysis_id, project],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let mut statement = connection.prepare(
            "SELECT identity, occurrence, kind, path, rule_key, message, range_json, ambiguous
             FROM findings WHERE analysis_id = ?1 ORDER BY path, rule_key, identity, occurrence",
        )?;
        let raw_findings: Vec<RawFinding> = statement
            .query_map([analysis_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get::<_, i64>(7)? != 0,
                ))
            })?
            .collect::<Result<_, _>>()?;
        drop(statement);
        let mut findings = Vec::with_capacity(raw_findings.len());
        for (identity, occurrence, kind_text, path, rule_key, message, range_text, ambiguous) in
            raw_findings
        {
            let kind = FindingKind::parse(&kind_text)
                .ok_or_else(|| StoreError::Invalid("invalid persisted finding kind".to_string()))?;
            let range = parse_json(&range_text)?;

            let review = if ambiguous {
                None
            } else {
                Self::review_for_key(&connection, project, &branch, analysis_id, &identity, kind)?
            };
            findings.push(FindingRecord {
                identity,
                occurrence,
                kind,
                path,
                rule_key,
                message,
                range,
                status: "open".to_string(),
                ambiguous,
                review,
            });
        }
        Ok(findings)
    }

    pub(crate) fn list_reviews(
        &self,
        project: &str,
        branch: Option<&str>,
        analysis_id: Option<i64>,
    ) -> Result<Vec<ReviewRecord>, StoreError> {
        let connection = self.lock()?;
        ensure_active_project(&connection, project)?;
        let mut statement = connection.prepare(
            "SELECT id, project, branch, analysis_id, identity, kind, state, version,
                    updated_by, updated_at, reason
             FROM reviews
             WHERE project = ?1 AND (?2 IS NULL OR branch = ?2)
               AND (?3 IS NULL OR analysis_id = ?3)
             ORDER BY branch, updated_at DESC, id DESC",
        )?;
        let rows = statement
            .query_map(
                rusqlite::params![project, branch, analysis_id],
                review_from_row,
            )?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub(crate) fn review_history(
        &self,
        project: &str,
        review_id: i64,
    ) -> Result<Vec<HistoryRecord>, StoreError> {
        let connection = self.lock()?;
        ensure_active_project(&connection, project)?;
        let exists: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM reviews WHERE id = ?1 AND project = ?2)",
            params![review_id, project],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(StoreError::NotFound);
        }
        let mut statement = connection.prepare(
            "SELECT id, review_id, analysis_id, identity, kind, previous_state, new_state,
                    actor, reason, created_at, version
             FROM review_history WHERE review_id = ?1 ORDER BY version ASC",
        )?;
        let rows = statement
            .query_map([review_id], history_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(rows)
    }

    pub(crate) fn insert_analysis(&self, input: &IngestData) -> Result<IngestResult, StoreError> {
        let mut connection = self.lock()?;
        let existing = Self::existing_analysis(&connection, input)?;
        if let Some((id, content_hash, deleted_at, _, _, _, _, _)) = existing {
            if deleted_at.is_some() {
                return Err(StoreError::Conflict(
                    "the commit has been explicitly deleted and cannot be replaced".to_string(),
                ));
            }
            if content_hash == input.content_hash {
                let summary = connection.query_row(
                    "SELECT id, project, branch, commit_sha, analyzed_at, report_schema_version,
                            complete, metrics_json, duplication_json, gate_json
                     FROM analyses WHERE id = ?1",
                    [id],
                    summary_from_row,
                )?;
                return Ok(IngestResult {
                    analysis: summary,
                    idempotent: true,
                });
            }
            return Err(StoreError::Conflict(
                "a different report already exists for this project, branch, and commit"
                    .to_string(),
            ));
        }
        let project_deleted: Option<String> = connection
            .query_row(
                "SELECT deleted_at FROM projects WHERE project = ?1",
                [&input.project],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        if project_deleted.is_some() {
            return Err(StoreError::Conflict(
                "the project has been explicitly deleted".to_string(),
            ));
        }

        let transaction = connection.transaction()?;
        let analysis_id = Self::insert_analysis_rows(&transaction, input)?;
        transaction.commit()?;
        let summary = connection.query_row(
            "SELECT id, project, branch, commit_sha, analyzed_at, report_schema_version,
                    complete, metrics_json, duplication_json, gate_json
             FROM analyses WHERE id = ?1",
            [analysis_id],
            summary_from_row,
        )?;
        Ok(IngestResult {
            analysis: summary,
            idempotent: false,
        })
    }

    pub(crate) fn apply_review(
        &self,
        project: &str,
        request: &ReviewRequest,
        actor: &str,
        now: &str,
    ) -> Result<ReviewMutation, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        ensure_active_project(&transaction, project)?;
        let branch = Self::review_target_branch(&transaction, project, request)?;
        let existing = Self::existing_review(&transaction, project, &branch, request)?;
        if let Some(current) = existing.as_ref()
            && request.expected_version != current.version
        {
            return Err(StoreError::Conflict(format!(
                "review version conflict: expected {}, current {}",
                request.expected_version, current.version
            )));
        }
        if existing.is_none() && request.expected_version != 0 {
            return Err(StoreError::Conflict(
                "new reviews must use expected_version 0".to_string(),
            ));
        }
        let previous_state = existing.as_ref().map(|review| review.state);
        if !crate::valid_review_transition(request.kind, previous_state, request.state) {
            return Err(StoreError::Conflict(
                "review state transition is not allowed".to_string(),
            ));
        }
        let version = if let Some(review) = existing.as_ref() {
            review
                .version
                .checked_add(1)
                .ok_or_else(|| StoreError::Invalid("review version overflow".to_string()))?
        } else {
            1
        };
        let version_sql = to_sqlite_u64(version)?;
        let expected_version_sql = to_sqlite_u64(request.expected_version)?;
        let review_id = Self::upsert_review(
            &transaction,
            &ReviewWrite {
                project,
                branch: &branch,
                request,
                actor,
                now,
                existing: existing.as_ref(),
                version_sql,
                expected_version_sql,
            },
        )?;
        Self::insert_review_history(
            &transaction,
            review_id,
            request,
            previous_state,
            actor,
            now,
            version_sql,
        )?;
        let mutation =
            Self::review_mutation_from_transaction(&transaction, review_id, version_sql)?;
        transaction.commit()?;
        Ok(mutation)
    }

    pub(crate) fn apply_retention(
        &self,
        input: &RetentionInput<'_>,
    ) -> Result<RetentionResult, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        ensure_active_project(&transaction, input.project)?;
        let mut statement = transaction.prepare(
            "SELECT id FROM analyses
             WHERE project = ?1 AND analyzed_epoch < ?2 AND deleted_at IS NULL
               AND (?3 IS NULL OR branch = ?3)
             ORDER BY analyzed_epoch ASC, id ASC",
        )?;
        let ids: Vec<i64> = statement
            .query_map(
                params![input.project, input.before_epoch, input.branch],
                |row| row.get(0),
            )?
            .collect::<Result<_, _>>()?;
        drop(statement);
        for id in &ids {
            transaction.execute(
                "UPDATE analyses SET deleted_at = ?1, deleted_by = ?2, deletion_reason = ?3
                 WHERE id = ?4",
                params![input.now, input.actor, input.reason, id],
            )?;
            transaction.execute(
                "INSERT INTO deletion_audit(
                    project, resource_type, analysis_id, action, actor, reason, created_at
                 ) VALUES (?1, 'analysis', ?2, 'retention', ?3, ?4, ?5)",
                params![input.project, id, input.actor, input.reason, input.now],
            )?;
        }
        transaction.commit()?;
        Ok(RetentionResult {
            deleted: ids.len() as u64,
            before: input.before.to_string(),
            branch: input.branch.map(str::to_string),
        })
    }

    fn existing_analysis(
        connection: &Connection,
        input: &IngestData,
    ) -> Result<Option<ExistingAnalysis>, StoreError> {
        connection
            .query_row(
                "SELECT id, content_hash, deleted_at,
                    report_schema_version, complete, metrics_json, duplication_json, gate_json
             FROM analyses WHERE project = ?1 AND branch = ?2 AND commit_sha = ?3",
                params![input.project, input.branch, input.commit],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, u32>(3)?,
                        row.get::<_, i64>(4)? != 0,
                        row.get::<_, String>(5)?,
                        row.get::<_, Option<String>>(6)?,
                        row.get::<_, Option<String>>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(StoreError::Sql)
    }

    fn insert_analysis_rows(
        transaction: &rusqlite::Transaction<'_>,
        input: &IngestData,
    ) -> Result<i64, StoreError> {
        transaction.execute(
            "INSERT OR IGNORE INTO projects(project, created_at) VALUES (?1, ?2)",
            params![input.project, input.received_at],
        )?;
        transaction.execute(
            "INSERT INTO analyses(
            project, branch, commit_sha, analyzed_at, analyzed_epoch,
            report_schema_version, complete,
            metrics_json, duplication_json, gate_json, report_json, assessment_json,
            content_hash
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                input.project,
                input.branch,
                input.commit,
                input.analyzed_at,
                input.analyzed_epoch,
                input.report_schema_version,
                i64::from(input.complete),
                input.metrics_json,
                input.duplication_json,
                input.gate_json,
                input.report_json,
                input.assessment_json,
                input.content_hash,
            ],
        )?;
        let analysis_id = transaction.last_insert_rowid();
        for finding in &input.findings {
            transaction.execute(
                "INSERT INTO findings(
                analysis_id, identity, occurrence, kind, path, rule_key, message,
                range_json, ambiguous
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    analysis_id,
                    finding.identity,
                    finding.occurrence,
                    finding.kind.as_str(),
                    finding.path,
                    finding.rule_key,
                    finding.message,
                    finding.range_json,
                    i64::from(finding.ambiguous),
                ],
            )?;
        }
        Ok(analysis_id)
    }

    fn review_target_branch(
        transaction: &rusqlite::Transaction<'_>,
        project: &str,
        request: &ReviewRequest,
    ) -> Result<String, StoreError> {
        let (branch, deleted): (String, Option<String>) = transaction
            .query_row(
                "SELECT branch, deleted_at FROM analyses WHERE id = ?1 AND project = ?2",
                params![request.analysis_id, project],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        if deleted.is_some() {
            return Err(StoreError::NotFound);
        }
        let finding: Option<(String, bool)> = transaction
            .query_row(
                "SELECT kind, ambiguous FROM findings
             WHERE analysis_id = ?1 AND identity = ?2",
                params![request.analysis_id, request.identity],
                |row| Ok((row.get(0)?, row.get::<_, i64>(1)? != 0)),
            )
            .optional()?;
        let Some((persisted_kind, ambiguous)) = finding else {
            return Err(StoreError::NotFound);
        };
        if ambiguous {
            return Err(StoreError::Conflict(
                "ambiguous findings cannot inherit or receive a review".to_string(),
            ));
        }
        let persisted_kind = FindingKind::parse(&persisted_kind)
            .ok_or_else(|| StoreError::Invalid("invalid persisted finding kind".to_string()))?;
        if persisted_kind != request.kind {
            return Err(StoreError::Conflict(
                "review kind does not match the finding".to_string(),
            ));
        }
        Ok(branch)
    }

    fn existing_review(
        transaction: &rusqlite::Transaction<'_>,
        project: &str,
        branch: &str,
        request: &ReviewRequest,
    ) -> Result<Option<ReviewRecord>, StoreError> {
        transaction
            .query_row(
                "SELECT id, project, branch, analysis_id, identity, kind, state, version,
                    updated_by, updated_at, reason
             FROM reviews
             WHERE project = ?1 AND branch = ?2 AND identity = ?3 AND kind = ?4",
                params![project, branch, request.identity, request.kind.as_str()],
                review_from_row,
            )
            .optional()
            .map_err(StoreError::Sql)
    }

    fn upsert_review(
        transaction: &rusqlite::Transaction<'_>,
        write: &ReviewWrite<'_>,
    ) -> Result<i64, StoreError> {
        if let Some(current) = write.existing {
            let changed = transaction.execute(
                "UPDATE reviews SET analysis_id = ?1, state = ?2, version = ?3,
                    updated_by = ?4, updated_at = ?5, reason = ?6
             WHERE id = ?7 AND version = ?8",
                params![
                    write.request.analysis_id,
                    write.request.state.as_str(),
                    write.version_sql,
                    write.actor,
                    write.now,
                    write.request.reason,
                    current.id,
                    write.expected_version_sql,
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::Conflict(
                    "review changed concurrently".to_string(),
                ));
            }
            Ok(current.id)
        } else {
            transaction.execute(
                "INSERT INTO reviews(
                project, branch, analysis_id, identity, kind, state, version,
                updated_by, updated_at, reason
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    write.project,
                    write.branch,
                    write.request.analysis_id,
                    write.request.identity,
                    write.request.kind.as_str(),
                    write.request.state.as_str(),
                    write.version_sql,
                    write.actor,
                    write.now,
                    write.request.reason,
                ],
            )?;
            Ok(transaction.last_insert_rowid())
        }
    }

    fn insert_review_history(
        transaction: &rusqlite::Transaction<'_>,
        review_id: i64,
        request: &ReviewRequest,
        previous_state: Option<ReviewState>,
        actor: &str,
        now: &str,
        version_sql: i64,
    ) -> Result<(), StoreError> {
        transaction.execute(
            "INSERT INTO review_history(
            review_id, analysis_id, identity, kind, previous_state, new_state,
            actor, reason, created_at, version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                review_id,
                request.analysis_id,
                request.identity,
                request.kind.as_str(),
                previous_state.map(ReviewState::as_str),
                request.state.as_str(),
                actor,
                request.reason,
                now,
                version_sql,
            ],
        )?;
        Ok(())
    }

    fn review_mutation_from_transaction(
        transaction: &rusqlite::Transaction<'_>,
        review_id: i64,
        version_sql: i64,
    ) -> Result<ReviewMutation, StoreError> {
        let review = transaction.query_row(
            "SELECT id, project, branch, analysis_id, identity, kind, state, version,
                updated_by, updated_at, reason
         FROM reviews WHERE id = ?1",
            [review_id],
            review_from_row,
        )?;
        let history = transaction.query_row(
            "SELECT id, review_id, analysis_id, identity, kind, previous_state, new_state,
                actor, reason, created_at, version
         FROM review_history WHERE review_id = ?1 AND version = ?2",
            params![review_id, version_sql],
            history_from_row,
        )?;
        Ok(ReviewMutation { review, history })
    }

    pub(crate) fn delete_analysis(
        &self,
        project: &str,
        analysis_id: i64,
        actor: &str,
        reason: &str,
        now: &str,
    ) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE analyses SET deleted_at = ?1, deleted_by = ?2, deletion_reason = ?3
             WHERE id = ?4 AND project = ?5 AND deleted_at IS NULL",
            params![now, actor, reason, analysis_id, project],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        transaction.execute(
            "INSERT INTO deletion_audit(
                project, resource_type, analysis_id, action, actor, reason, created_at
             ) VALUES (?1, 'analysis', ?2, 'delete', ?3, ?4, ?5)",
            params![project, analysis_id, actor, reason, now],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn delete_project(
        &self,
        project: &str,
        actor: &str,
        reason: &str,
        now: &str,
    ) -> Result<(), StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE projects SET deleted_at = ?1, deleted_by = ?2, deletion_reason = ?3
             WHERE project = ?4 AND deleted_at IS NULL",
            params![now, actor, reason, project],
        )?;
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        transaction.execute(
            "INSERT INTO deletion_audit(
                project, resource_type, action, actor, reason, created_at
             ) VALUES (?1, 'project', 'delete', ?2, ?3, ?4)",
            params![project, actor, reason, now],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn export_project(
        &self,
        project: &str,
        now: &str,
    ) -> Result<BackupEnvelope, StoreError> {
        let connection = self.lock()?;
        let project_deleted_at: Option<String> = connection
            .query_row(
                "SELECT deleted_at FROM projects WHERE project = ?1",
                [project],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let mut analyses_statement = connection.prepare(
            "SELECT id, branch, commit_sha, analyzed_at, analyzed_epoch, report_schema_version, complete,
                    metrics_json, duplication_json, gate_json, report_json, assessment_json,
                    content_hash, deleted_at
             FROM analyses WHERE project = ?1 ORDER BY id ASC",
        )?;
        let analyses = analyses_statement
            .query_map([project], backup_analysis_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        let mut findings_statement = connection.prepare(
            "SELECT f.analysis_id, f.identity, f.occurrence, f.kind, f.path, f.rule_key, f.message,
                    f.range_json, f.ambiguous
             FROM findings f JOIN analyses a ON a.id = f.analysis_id
             WHERE a.project = ?1 ORDER BY f.analysis_id, f.id",
        )?;
        let findings = findings_statement
            .query_map([project], backup_finding_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        let mut reviews_statement = connection.prepare(
            "SELECT id, project, branch, analysis_id, identity, kind, state, version,
                    updated_by, updated_at, reason
             FROM reviews WHERE project = ?1 ORDER BY id ASC",
        )?;
        let reviews = reviews_statement
            .query_map([project], backup_review_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        let mut history_statement = connection.prepare(
            "SELECT h.id, h.review_id, h.analysis_id, h.identity, h.kind, h.previous_state,
                    h.new_state, h.actor, h.reason, h.created_at, h.version
             FROM review_history h JOIN reviews r ON r.id = h.review_id
             WHERE r.project = ?1 ORDER BY h.id ASC",
        )?;
        let history = history_statement
            .query_map([project], backup_history_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        let mut deletion_statement = connection.prepare(
            "SELECT id, resource_type, analysis_id, action, actor, reason, created_at
             FROM deletion_audit WHERE project = ?1 ORDER BY id ASC",
        )?;
        let deletions = deletion_statement
            .query_map([project], deletion_from_row)?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BackupEnvelope {
            schema_version: 1,
            kind: "hoonarqube_service_backup".to_string(),
            project: project.to_string(),
            exported_at: now.to_string(),
            project_deleted_at,
            analyses,
            findings,
            reviews,
            history,
            deletions,
        })
    }

    pub(crate) fn restore(&self, restore: &ValidatedRestore) -> Result<RestoreResult, StoreError> {
        let mut connection = self.lock()?;
        let transaction = connection.transaction()?;
        restore_project(&transaction, &restore.backup)?;
        let (analysis_ids, analyses_count) = restore_analyses(&transaction, &restore.backup)?;
        let findings_count = restore_findings(&transaction, &restore.backup, &analysis_ids)?;
        let (review_ids, reviews_count) =
            restore_reviews(&transaction, &restore.backup, &analysis_ids)?;
        let history_count =
            restore_history(&transaction, &restore.backup, &analysis_ids, &review_ids)?;
        restore_deletions(&transaction, &restore.backup, &analysis_ids)?;
        transaction.commit()?;
        Ok(RestoreResult {
            project: restore.backup.project.clone(),
            analyses: analyses_count,
            findings: findings_count,
            reviews: reviews_count,
            history: history_count,
        })
    }

    fn review_for_key(
        connection: &Connection,
        project: &str,
        branch: &str,
        current_analysis_id: i64,
        identity: &str,
        kind: FindingKind,
    ) -> Result<Option<ReviewRecord>, StoreError> {
        let review = connection
            .query_row(
                "SELECT id, project, branch, analysis_id, identity, kind, state, version,
                        updated_by, updated_at, reason
                 FROM reviews WHERE project = ?1 AND branch = ?2
                   AND identity = ?3 AND kind = ?4",
                params![project, branch, identity, kind.as_str()],
                review_from_row,
            )
            .optional()
            .map_err(StoreError::Sql)?;
        let Some(review) = review else {
            return Ok(None);
        };
        if review.analysis_id == current_analysis_id
            || analysis_context_compatible(connection, current_analysis_id, review.analysis_id)?
        {
            Ok(Some(review))
        } else {
            Ok(None)
        }
    }
}
fn restore_project(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
) -> Result<(), StoreError> {
    let existing_project: Option<Option<String>> = transaction
        .query_row(
            "SELECT deleted_at FROM projects WHERE project = ?1",
            [&backup.project],
            |row| row.get(0),
        )
        .optional()?;
    match existing_project {
        Some(existing_deleted) => {
            if existing_deleted != backup.project_deleted_at {
                return Err(StoreError::Conflict(
                    "restore cannot change explicit project deletion state".to_string(),
                ));
            }
        }
        None => {
            transaction.execute(
                "INSERT INTO projects(project, created_at, deleted_at)
                 VALUES (?1, ?2, ?3)",
                params![
                    backup.project,
                    backup.exported_at,
                    backup.project_deleted_at,
                ],
            )?;
        }
    }
    Ok(())
}

fn restore_analyses(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
) -> Result<(HashMap<i64, i64>, u64), StoreError> {
    let mut analysis_ids = HashMap::new();
    let mut analyses_count = 0_u64;
    for analysis in &backup.analyses {
        let (target_id, inserted) = restore_analysis(transaction, backup, analysis)?;
        if inserted {
            analyses_count += 1;
        }
        analysis_ids.insert(analysis.id, target_id);
    }
    Ok((analysis_ids, analyses_count))
}

fn restore_analysis(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
    analysis: &BackupAnalysis,
) -> Result<(i64, bool), StoreError> {
    let existing = transaction
        .query_row(
            "SELECT id, content_hash, deleted_at FROM analyses
             WHERE project = ?1 AND branch = ?2 AND commit_sha = ?3",
            params![backup.project, analysis.branch, analysis.commit],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            },
        )
        .optional()?;
    if let Some((id, hash, deleted_at)) = existing {
        if hash != analysis.content_hash {
            return Err(StoreError::Conflict(
                "backup conflicts with an immutable commit report".to_string(),
            ));
        }
        if deleted_at != analysis.deleted_at {
            return Err(StoreError::Conflict(
                "restore cannot change explicit analysis deletion state".to_string(),
            ));
        }
        return Ok((id, false));
    }
    transaction.execute(
        "INSERT INTO analyses(
            project, branch, commit_sha, analyzed_at, analyzed_epoch,
            report_schema_version, complete,
            metrics_json, duplication_json, gate_json, report_json, assessment_json,
            content_hash, deleted_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            backup.project,
            analysis.branch,
            analysis.commit,
            analysis.analyzed_at,
            analysis.analyzed_epoch,
            analysis.report_schema_version,
            i64::from(analysis.complete),
            serde_json::to_string(&analysis.metrics)
                .map_err(|error| StoreError::Invalid(error.to_string()))?,
            analysis
                .duplication
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|error| StoreError::Invalid(error.to_string()))?,
            analysis
                .gate
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|error| StoreError::Invalid(error.to_string()))?,
            serde_json::to_string(&analysis.report)
                .map_err(|error| StoreError::Invalid(error.to_string()))?,
            analysis
                .assessment
                .as_ref()
                .map(serde_json::to_string)
                .transpose()
                .map_err(|error| StoreError::Invalid(error.to_string()))?,
            analysis.content_hash,
            analysis.deleted_at,
        ],
    )?;
    Ok((transaction.last_insert_rowid(), true))
}

fn restore_findings(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
    analysis_ids: &HashMap<i64, i64>,
) -> Result<u64, StoreError> {
    let mut findings_count = 0_u64;
    for finding in &backup.findings {
        if restore_finding(transaction, finding, analysis_ids)? {
            findings_count += 1;
        }
    }
    Ok(findings_count)
}

fn restore_finding(
    transaction: &rusqlite::Transaction<'_>,
    finding: &BackupFinding,
    analysis_ids: &HashMap<i64, i64>,
) -> Result<bool, StoreError> {
    let target_analysis_id = analysis_ids.get(&finding.analysis_id).ok_or_else(|| {
        StoreError::Invalid("backup finding references an unknown analysis".to_string())
    })?;
    let range_json = serde_json::to_string(&finding.range)
        .map_err(|error| StoreError::Invalid(error.to_string()))?;
    let occurrence = i64::from(finding.occurrence);
    let existing: Option<(String, String, String, String, i64)> = transaction
        .query_row(
            "SELECT path, rule_key, message, range_json, ambiguous
             FROM findings
             WHERE analysis_id = ?1 AND identity = ?2 AND kind = ?3 AND occurrence = ?4",
            params![
                target_analysis_id,
                finding.identity,
                finding.kind.as_str(),
                occurrence,
            ],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )
        .optional()?;
    if let Some((path, rule_key, message, stored_range, ambiguous)) = existing {
        if path != finding.path
            || rule_key != finding.rule_key
            || message != finding.message
            || stored_range != range_json
            || ambiguous != i64::from(finding.ambiguous)
        {
            return Err(StoreError::Conflict(
                "backup conflicts with immutable finding".to_string(),
            ));
        }
        return Ok(false);
    }
    transaction.execute(
        "INSERT INTO findings(
            analysis_id, identity, occurrence, kind, path, rule_key, message,
            range_json, ambiguous
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            target_analysis_id,
            finding.identity,
            occurrence,
            finding.kind.as_str(),
            finding.path,
            finding.rule_key,
            finding.message,
            range_json,
            i64::from(finding.ambiguous),
        ],
    )?;
    Ok(true)
}

fn restore_reviews(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
    analysis_ids: &HashMap<i64, i64>,
) -> Result<(HashMap<i64, i64>, u64), StoreError> {
    let mut review_ids = HashMap::new();
    let mut reviews_count = 0_u64;
    for review in &backup.reviews {
        let (target_review_id, inserted) =
            restore_review(transaction, backup, review, analysis_ids)?;
        if inserted {
            reviews_count += 1;
        }
        review_ids.insert(review.id, target_review_id);
    }
    Ok((review_ids, reviews_count))
}

fn restore_review(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
    review: &BackupReview,
    analysis_ids: &HashMap<i64, i64>,
) -> Result<(i64, bool), StoreError> {
    let existing = transaction
        .query_row(
            "SELECT id, analysis_id, state, version, updated_by, updated_at, reason
             FROM reviews WHERE project = ?1 AND branch = ?2
               AND identity = ?3 AND kind = ?4",
            params![
                backup.project,
                review.branch,
                review.identity,
                review.kind.as_str(),
            ],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    from_sqlite_u64(row.get::<_, i64>(3)?, 3)?,
                    row.get::<_, String>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                ))
            },
        )
        .optional()?;
    let target_analysis_id = *analysis_ids.get(&review.analysis_id).ok_or_else(|| {
        StoreError::Invalid("backup review references unknown analysis".to_string())
    })?;
    if let Some((id, existing_analysis, state, version, user, updated, reason)) = existing {
        if existing_analysis != target_analysis_id
            || state != review.state.as_str()
            || version != review.version
            || user != review.updated_by
            || updated != review.updated_at
            || reason != review.reason
        {
            return Err(StoreError::Conflict(
                "backup conflicts with immutable review state".to_string(),
            ));
        }
        return Ok((id, false));
    }
    transaction.execute(
        "INSERT INTO reviews(
            project, branch, analysis_id, identity, kind, state, version,
            updated_by, updated_at, reason
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            backup.project,
            review.branch,
            target_analysis_id,
            review.identity,
            review.kind.as_str(),
            review.state.as_str(),
            to_sqlite_u64(review.version)?,
            review.updated_by,
            review.updated_at,
            review.reason,
        ],
    )?;
    Ok((transaction.last_insert_rowid(), true))
}

fn restore_history(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
    analysis_ids: &HashMap<i64, i64>,
    review_ids: &HashMap<i64, i64>,
) -> Result<u64, StoreError> {
    let mut history_count = 0_u64;
    for history in &backup.history {
        let review_id = *review_ids.get(&history.review_id).ok_or_else(|| {
            StoreError::Invalid("backup history references unknown review".to_string())
        })?;
        let target_analysis_id = *analysis_ids.get(&history.analysis_id).ok_or_else(|| {
            StoreError::Invalid("backup history references unknown analysis".to_string())
        })?;
        if restore_history_entry(transaction, history, review_id, target_analysis_id)? {
            history_count += 1;
        }
    }
    Ok(history_count)
}

fn restore_history_entry(
    transaction: &rusqlite::Transaction<'_>,
    history: &BackupHistory,
    review_id: i64,
    target_analysis_id: i64,
) -> Result<bool, StoreError> {
    let existing: Option<StoredHistory> = transaction
        .query_row(
            "SELECT analysis_id, identity, kind, previous_state, new_state,
                    actor, reason, created_at, version
             FROM review_history WHERE review_id = ?1 AND version = ?2",
            params![review_id, to_sqlite_u64(history.version)?],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                    from_sqlite_u64(row.get::<_, i64>(8)?, 8)?,
                ))
            },
        )
        .optional()?;
    if let Some((
        existing_analysis_id,
        existing_identity,
        existing_kind,
        existing_previous_state,
        existing_new_state,
        existing_actor,
        existing_reason,
        existing_created_at,
        existing_version,
    )) = existing
    {
        if existing_analysis_id != target_analysis_id
            || existing_identity != history.identity
            || existing_kind != history.kind.as_str()
            || existing_previous_state
                != history
                    .previous_state
                    .map(|state| state.as_str().to_string())
            || existing_new_state != history.new_state.as_str()
            || existing_actor != history.actor
            || existing_reason != history.reason
            || existing_created_at != history.created_at
            || existing_version != history.version
        {
            return Err(StoreError::Conflict(
                "backup conflicts with immutable review history".to_string(),
            ));
        }
        return Ok(false);
    }
    transaction.execute(
        "INSERT INTO review_history(
            review_id, analysis_id, identity, kind, previous_state, new_state,
            actor, reason, created_at, version
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            review_id,
            target_analysis_id,
            history.identity,
            history.kind.as_str(),
            history.previous_state.map(ReviewState::as_str),
            history.new_state.as_str(),
            history.actor,
            history.reason,
            history.created_at,
            to_sqlite_u64(history.version)?,
        ],
    )?;
    Ok(true)
}

fn restore_deletions(
    transaction: &rusqlite::Transaction<'_>,
    backup: &BackupEnvelope,
    analysis_ids: &HashMap<i64, i64>,
) -> Result<(), StoreError> {
    for deletion in &backup.deletions {
        let analysis_id = deletion
            .analysis_id
            .and_then(|id| analysis_ids.get(&id).copied());
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT id FROM deletion_audit
                 WHERE project = ?1 AND resource_type = ?2
                   AND IFNULL(analysis_id, 0) = IFNULL(?3, 0)
                   AND action = ?4 AND actor = ?5 AND reason = ?6 AND created_at = ?7",
                params![
                    backup.project,
                    deletion.resource_type,
                    analysis_id,
                    deletion.action,
                    deletion.actor,
                    deletion.reason,
                    deletion.created_at,
                ],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_none() {
            transaction.execute(
                "INSERT INTO deletion_audit(
                    project, resource_type, analysis_id, action, actor, reason, created_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![
                    backup.project,
                    deletion.resource_type,
                    analysis_id,
                    deletion.action,
                    deletion.actor,
                    deletion.reason,
                    deletion.created_at,
                ],
            )?;
        }
    }
    Ok(())
}

fn analysis_context_compatible(
    connection: &Connection,
    current_analysis_id: i64,
    reviewed_analysis_id: i64,
) -> Result<bool, StoreError> {
    let current: Option<String> = connection
        .query_row(
            "SELECT assessment_json FROM analyses
             WHERE id = ?1 AND deleted_at IS NULL",
            [current_analysis_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let reviewed: Option<String> = connection
        .query_row(
            "SELECT assessment_json FROM analyses
             WHERE id = ?1 AND deleted_at IS NULL",
            [reviewed_analysis_id],
            |row| row.get(0),
        )
        .optional()?
        .flatten();
    let (Some(current), Some(reviewed)) = (current, reviewed) else {
        return Ok(false);
    };
    let current: Value =
        serde_json::from_str(&current).map_err(|error| StoreError::Invalid(error.to_string()))?;
    let reviewed: Value =
        serde_json::from_str(&reviewed).map_err(|error| StoreError::Invalid(error.to_string()))?;
    let current = current.get("context").and_then(Value::as_object);
    let reviewed = reviewed.get("context").and_then(Value::as_object);
    let (Some(current), Some(reviewed)) = (current, reviewed) else {
        return Ok(false);
    };
    for field in [
        "analyzer_version",
        "catalog_digest",
        "options_digest",
        "scope_digest",
    ] {
        if current.get(field) != reviewed.get(field) {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BranchSummary {
    pub name: String,
    pub analysis_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_analysis_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_commit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_analyzed_at: Option<String>,
}

fn ensure_active_project(connection: &Connection, project: &str) -> Result<(), StoreError> {
    let deleted: Option<String> = connection
        .query_row(
            "SELECT deleted_at FROM projects WHERE project = ?1",
            [project],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    if deleted.is_some() {
        return Err(StoreError::NotFound);
    }
    Ok(())
}

fn parse_json(text: &str) -> Result<Value, StoreError> {
    serde_json::from_str(text).map_err(|error| StoreError::Invalid(error.to_string()))
}

fn summary_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AnalysisSummary> {
    Ok(AnalysisSummary {
        id: row.get(0)?,
        project: row.get(1)?,
        branch: row.get(2)?,
        commit: row.get(3)?,
        analyzed_at: row.get(4)?,
        report_schema_version: row.get(5)?,
        complete: row.get::<_, i64>(6)? != 0,
        metrics: serde_json::from_str(&row.get::<_, String>(7)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        duplication: row
            .get::<_, Option<String>>(8)?
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        gate: row
            .get::<_, Option<String>>(9)?
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
    })
}

fn detail_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AnalysisDetail> {
    Ok(AnalysisDetail {
        summary: summary_from_row(row)?,
        report: serde_json::from_str(&row.get::<_, String>(10)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        assessment: row
            .get::<_, Option<String>>(11)?
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
    })
}

fn parse_kind_state<T>(text: String, parse: fn(&str) -> Option<T>) -> rusqlite::Result<T> {
    parse(&text)
        .ok_or_else(|| rusqlite::Error::InvalidColumnType(0, text, rusqlite::types::Type::Text))
}

fn review_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ReviewRecord> {
    let kind_text: String = row.get(5)?;
    let state_text: String = row.get(6)?;
    Ok(ReviewRecord {
        id: row.get(0)?,
        project: row.get(1)?,
        branch: row.get(2)?,
        analysis_id: row.get(3)?,
        identity: row.get(4)?,
        kind: parse_kind_state(kind_text, FindingKind::parse)?,
        state: parse_kind_state(state_text, ReviewState::parse)?,
        version: from_sqlite_u64(row.get::<_, i64>(7)?, 7)?,
        updated_by: row.get(8)?,
        updated_at: row.get(9)?,
        reason: row.get(10)?,
    })
}

fn history_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<HistoryRecord> {
    let kind_text: String = row.get(4)?;
    let previous_text: Option<String> = row.get(5)?;
    let new_text: String = row.get(6)?;
    Ok(HistoryRecord {
        id: row.get(0)?,
        review_id: row.get(1)?,
        analysis_id: row.get(2)?,
        identity: row.get(3)?,
        kind: parse_kind_state(kind_text, FindingKind::parse)?,
        previous_state: previous_text
            .map(|text| parse_kind_state(text, ReviewState::parse))
            .transpose()?,
        new_state: parse_kind_state(new_text, ReviewState::parse)?,
        actor: row.get(7)?,
        reason: row.get(8)?,
        created_at: row.get(9)?,
        version: from_sqlite_u64(row.get::<_, i64>(10)?, 10)?,
    })
}

fn backup_analysis_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BackupAnalysis> {
    Ok(BackupAnalysis {
        id: row.get(0)?,
        branch: row.get(1)?,
        commit: row.get(2)?,
        analyzed_at: row.get(3)?,
        analyzed_epoch: row.get(4)?,
        report_schema_version: row.get(5)?,
        complete: row.get::<_, i64>(6)? != 0,
        metrics: serde_json::from_str(&row.get::<_, String>(7)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        duplication: row
            .get::<_, Option<String>>(8)?
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    8,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        gate: row
            .get::<_, Option<String>>(9)?
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        report: serde_json::from_str(&row.get::<_, String>(10)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        assessment: row
            .get::<_, Option<String>>(11)?
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Text,
                    Box::new(error),
                )
            })?,
        content_hash: row.get(12)?,
        deleted_at: row.get(13)?,
    })
}

fn backup_finding_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BackupFinding> {
    let kind_text: String = row.get(3)?;
    Ok(BackupFinding {
        analysis_id: row.get(0)?,
        identity: row.get(1)?,
        occurrence: row.get(2)?,
        kind: parse_kind_state(kind_text, FindingKind::parse)?,
        path: row.get(4)?,
        rule_key: row.get(5)?,
        message: row.get(6)?,
        range: serde_json::from_str(&row.get::<_, String>(7)?).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                7,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        ambiguous: row.get::<_, i64>(8)? != 0,
    })
}

fn backup_review_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BackupReview> {
    let review = review_from_row(row)?;
    Ok(BackupReview {
        id: review.id,
        project: review.project,
        branch: review.branch,
        analysis_id: review.analysis_id,
        identity: review.identity,
        kind: review.kind,
        state: review.state,
        version: review.version,
        updated_by: review.updated_by,
        updated_at: review.updated_at,
        reason: review.reason,
    })
}

fn backup_history_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<BackupHistory> {
    let history = history_from_row(row)?;
    Ok(BackupHistory {
        id: history.id,
        review_id: history.review_id,
        analysis_id: history.analysis_id,
        identity: history.identity,
        kind: history.kind,
        previous_state: history.previous_state,
        new_state: history.new_state,
        actor: history.actor,
        reason: history.reason,
        created_at: history.created_at,
        version: history.version,
    })
}

fn deletion_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeletionRecord> {
    Ok(DeletionRecord {
        id: row.get(0)?,
        resource_type: row.get(1)?,
        analysis_id: row.get(2)?,
        action: row.get(3)?,
        actor: row.get(4)?,
        reason: row.get(5)?,
        created_at: row.get(6)?,
    })
}

impl From<FindingRecordInput> for BackupFinding {
    fn from(finding: FindingRecordInput) -> Self {
        Self {
            analysis_id: 0,
            identity: finding.identity,
            occurrence: finding.occurrence,
            kind: finding.kind,
            path: finding.path,
            rule_key: finding.rule_key,
            message: finding.message,
            range: finding.range,
            ambiguous: finding.ambiguous,
        }
    }
}
