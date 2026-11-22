use rusqlite::{OptionalExtension, params};
use serde::Serialize;

use super::{
    AnalysisSummary, Store, StoreError, ensure_active_project, optional_u64, summary_from_row,
};

#[derive(Debug, Serialize)]
pub(crate) struct AnalysisHistoryEntry {
    id: i64,
    project: String,
    branch: String,
    commit: String,
    analyzed_at: String,
    report_schema_version: u32,
    complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    gate_policy_version: Option<u64>,
}

pub(crate) struct AnalysisPage {
    pub analyses: Vec<AnalysisHistoryEntry>,
    pub next_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AnalysisOverview {
    #[serde(flatten)]
    summary: AnalysisSummary,
    warnings: Vec<String>,
}

impl Store {
    pub(crate) fn analysis_page(
        &self,
        project: &str,
        branch: Option<&str>,
        after_id: Option<i64>,
        limit: u16,
    ) -> Result<AnalysisPage, StoreError> {
        // Resolve the cursor and read the rows in one snapshot, including when
        // another service process is writing to this database.
        let mut connection = self.lock()?;
        let tx = connection.transaction()?;
        ensure_active_project(&tx, project)?;
        let after_epoch = after_id
            .map(|id| {
                // A retained tombstone still marks the position of a cursor.
                tx.query_row(
                    "SELECT analyzed_epoch FROM analyses
                     WHERE id = ?1 AND project = ?2 AND (?3 IS NULL OR branch = ?3)",
                    params![id, project, branch],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .ok_or(StoreError::InvalidCursor)
            })
            .transpose()?;

        let sql = page_sql(branch.is_some(), after_id.is_some());
        let page = {
            let mut statement = tx.prepare(&sql)?;
            let mut rows = statement.query(params![
                project,
                branch,
                after_epoch,
                after_id,
                i64::from(limit) + 1
            ])?;
            let mut analyses: Vec<AnalysisHistoryEntry> = Vec::new();
            let mut next_id = None;
            while let Some(row) = rows.next()? {
                if analyses.len() == usize::from(limit) {
                    next_id = analyses.last().map(|analysis| analysis.id);
                    break;
                }
                analyses.push(AnalysisHistoryEntry {
                    id: row.get(0)?,
                    project: row.get(1)?,
                    branch: row.get(2)?,
                    commit: row.get(3)?,
                    analyzed_at: row.get(4)?,
                    report_schema_version: row.get(5)?,
                    complete: row.get(6)?,
                    gate_policy_version: optional_u64(row, 7)?,
                });
            }
            AnalysisPage { analyses, next_id }
        };
        tx.commit()?;
        Ok(page)
    }

    pub(crate) fn analysis_overview(
        &self,
        project: &str,
        id: i64,
    ) -> Result<AnalysisOverview, StoreError> {
        let connection = self.lock()?;
        let (summary, warnings) = connection
            .query_row(
                "SELECT a.id, a.project, a.branch, a.commit_sha, a.analyzed_at, a.report_schema_version,
                        a.complete, a.metrics_json, a.duplication_json, COALESCE(a.assigned_gate_json, a.gate_json),
                        a.gate_policy_version,
                        CASE WHEN a.complete = 0 THEN json_extract(a.report_json, '$.project.warnings') END
                 FROM analyses a JOIN projects p ON p.project = a.project
                 WHERE a.id = ?1 AND a.project = ?2 AND a.deleted_at IS NULL AND p.deleted_at IS NULL",
                params![id, project],
                |row| Ok((summary_from_row(row)?, row.get::<_, Option<String>>(11)?)),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let warnings = warnings
            .map(|json| serde_json::from_str(&json))
            .transpose()
            .map_err(|error| StoreError::Invalid(error.to_string()))?
            .unwrap_or_default();
        Ok(AnalysisOverview { summary, warnings })
    }
}

fn page_sql(scoped: bool, after_cursor: bool) -> String {
    // Distinct predicates let SQLite seek against the matching history index.
    let branch = if scoped { " AND branch = ?2" } else { "" };
    let after = if after_cursor {
        " AND (analyzed_epoch, id) < (?3, ?4)"
    } else {
        ""
    };
    format!(
        "SELECT id, project, branch, commit_sha, analyzed_at, report_schema_version,
                complete, gate_policy_version
         FROM analyses WHERE project = ?1 AND deleted_at IS NULL{branch}{after}
         ORDER BY analyzed_epoch DESC, id DESC LIMIT ?5"
    )
}
