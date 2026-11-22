use rusqlite::{Connection, OptionalExtension, params};
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
        let cursor = after_id
            .map(|id| {
                // A retained tombstone still marks the position of a cursor.
                tx.query_row(
                    "SELECT analyzed_epoch FROM analyses
                     WHERE id = ?1 AND project = ?2 AND (?3 IS NULL OR branch = ?3)",
                    params![id, project, branch],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .map(|epoch| (epoch, id))
                .ok_or(StoreError::InvalidCursor)
            })
            .transpose()?;

        let capacity = usize::from(limit) + 1;
        let mut analyses = Vec::with_capacity(capacity);
        if let Some((epoch, id)) = cursor {
            // SQLite can scan earlier pages of tied timestamps with a tuple
            // bound. Seek by ID within this timestamp, then by timestamp.
            append_history(
                &tx,
                project,
                branch,
                HistoryRange::Tied { epoch, id },
                capacity,
                &mut analyses,
            )?;
            let remaining = capacity - analyses.len();
            if remaining > 0 {
                append_history(
                    &tx,
                    project,
                    branch,
                    HistoryRange::Older { epoch },
                    remaining,
                    &mut analyses,
                )?;
            }
        } else {
            append_history(
                &tx,
                project,
                branch,
                HistoryRange::All,
                capacity,
                &mut analyses,
            )?;
        }
        let next_id = if analyses.len() == capacity {
            analyses.pop();
            analyses.last().map(|analysis| analysis.id)
        } else {
            None
        };
        tx.commit()?;
        Ok(AnalysisPage { analyses, next_id })
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

#[derive(Clone, Copy)]
enum HistoryRange {
    All,
    Tied { epoch: i64, id: i64 },
    Older { epoch: i64 },
}

fn page_sql(scoped: bool, range: HistoryRange) -> String {
    // Distinct predicates let SQLite seek against the matching history index.
    let branch = if scoped { " AND branch = ?2" } else { "" };
    let bound = match range {
        HistoryRange::All => "",
        HistoryRange::Tied { .. } => " AND analyzed_epoch = ?3 AND id < ?4",
        HistoryRange::Older { .. } => " AND analyzed_epoch < ?3",
    };
    format!(
        "SELECT id, project, branch, commit_sha, analyzed_at, report_schema_version,
                complete, gate_policy_version
         FROM analyses WHERE project = ?1 AND deleted_at IS NULL{branch}{bound}
         ORDER BY analyzed_epoch DESC, id DESC LIMIT ?5"
    )
}

fn append_history(
    connection: &Connection,
    project: &str,
    branch: Option<&str>,
    range: HistoryRange,
    limit: usize,
    analyses: &mut Vec<AnalysisHistoryEntry>,
) -> rusqlite::Result<()> {
    let (epoch, id) = match range {
        HistoryRange::All => (None, None),
        HistoryRange::Tied { epoch, id } => (Some(epoch), Some(id)),
        HistoryRange::Older { epoch } => (Some(epoch), None),
    };
    let mut statement = connection.prepare_cached(&page_sql(branch.is_some(), range))?;
    let limit = i64::try_from(limit).expect("history page limit fits in i64");
    let mut rows = statement.query(params![project, branch, epoch, id, limit])?;
    while let Some(row) = rows.next()? {
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::StatementStatus;

    #[test]
    fn history_seeks_stay_bounded_when_timestamps_tie() {
        const LIMIT: u16 = 25;
        let store = Store::open(":memory:").unwrap();
        {
            let connection = store.lock().unwrap();
            connection
                .execute_batch(
                    "INSERT INTO projects(project, created_at) VALUES ('demo', 'created');
                     WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n + 1 FROM seq WHERE n < 100100)
                     INSERT INTO analyses(id, project, branch, commit_sha, analyzed_at, analyzed_epoch,
                         report_schema_version, complete, metrics_json, report_json, content_hash)
                     SELECT n, 'demo', CASE WHEN n % 2 = 1 THEN 'main' ELSE 'other' END, CAST(n AS TEXT),
                         'analyzed', CASE WHEN n <= 100000 THEN 2 WHEN n <= 100060 THEN 1 ELSE 0 END,
                         1, 1, '{}', '{}', 'hash'
                     FROM seq;
                     ANALYZE;",
                )
                .unwrap();
        }

        for (branch, at_boundary) in [(None, 26), (Some("main"), 51)] {
            let in_scope = |id: &i64| branch.is_none() || id % 2 == 1;
            let read = |cursor| {
                let page = store
                    .analysis_page("demo", branch, Some(cursor), LIMIT)
                    .unwrap();
                // Inspect the statements executed by the store. VM instructions
                // reveal a scan even when the returned rows are correct.
                let connection = store.lock().unwrap();
                let steps: i32 = [
                    HistoryRange::Tied { epoch: 0, id: 0 },
                    HistoryRange::Older { epoch: 0 },
                ]
                .into_iter()
                .map(|range| {
                    connection
                        .prepare_cached(&page_sql(branch.is_some(), range))
                        .unwrap()
                        .reset_status(StatementStatus::VmStep)
                })
                .sum();
                assert!(
                    (1..2_000).contains(&steps),
                    "{branch:?} cursor {cursor} used {steps} SQLite VM steps for {LIMIT} rows"
                );
                (
                    page.analyses
                        .into_iter()
                        .map(|entry| entry.id)
                        .collect::<Vec<_>>(),
                    page.next_id,
                )
            };
            for cursor in [99_999, 49_999, 101] {
                let expected: Vec<_> = (1..cursor)
                    .rev()
                    .filter(in_scope)
                    .take(usize::from(LIMIT))
                    .collect();
                let next = expected.last().copied();
                assert_eq!(read(cursor), (expected, next));
            }

            let tied: Vec<_> = (1..at_boundary).rev().filter(in_scope).collect();
            assert_eq!(read(at_boundary), (tied, Some(1)));

            // Older analyses have larger IDs. Their epoch must take precedence,
            // including when lookahead crosses from tied to older timestamps.
            let mut cursor = Some(15);
            let expected: Vec<_> = (1..15)
                .rev()
                .chain((100_001..=100_060).rev())
                .chain((100_061..=100_100).rev())
                .filter(in_scope)
                .collect();
            for remaining in expected.chunks(usize::from(LIMIT)) {
                let (ids, next) = read(cursor.unwrap());
                assert_eq!(ids, remaining);
                cursor = next;
            }
            assert!(cursor.is_none());
        }
    }
}
