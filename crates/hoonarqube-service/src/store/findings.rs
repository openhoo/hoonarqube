use std::collections::{BTreeSet, HashMap};

use hoonarqube_ir::assessment::AnalysisContext;
use rusqlite::{Connection, OptionalExtension, Params, params};

use super::{FindingKind, FindingRecord, Store, StoreError, parse_json, review_from_row};

const FIRST_FINDINGS: &str =
    "SELECT id, identity, occurrence, kind, path, rule_key, message, range_json, ambiguous
     FROM findings WHERE analysis_id = ?1
     ORDER BY path, rule_key, identity, occurrence, id LIMIT ?2";
const NEXT_FINDINGS: &str =
    "SELECT id, identity, occurrence, kind, path, rule_key, message, range_json, ambiguous
     FROM findings WHERE analysis_id = ?1 AND (path, rule_key, identity, occurrence, id) >
        (?3, ?4, ?5, ?6, ?7)
     ORDER BY path, rule_key, identity, occurrence, id LIMIT ?2";

pub(crate) struct FindingPage {
    pub findings: Vec<FindingRecord>,
    pub next_id: Option<i64>,
}

#[derive(Clone, Copy)]
struct FindingWindow {
    after_id: Option<i64>,
    limit: u16,
}

struct FindingPosition {
    path: String,
    rule_key: String,
    identity: String,
    occurrence: u32,
}

impl Store {
    pub(crate) fn findings(
        &self,
        project: &str,
        analysis_id: i64,
    ) -> Result<Vec<FindingRecord>, StoreError> {
        Ok(self.finding_window(project, analysis_id, None)?.findings)
    }

    pub(crate) fn findings_page(
        &self,
        project: &str,
        analysis_id: i64,
        after_id: Option<i64>,
        limit: u16,
    ) -> Result<FindingPage, StoreError> {
        self.finding_window(
            project,
            analysis_id,
            Some(FindingWindow { after_id, limit }),
        )
    }

    fn finding_window(
        &self,
        project: &str,
        analysis_id: i64,
        window: Option<FindingWindow>,
    ) -> Result<FindingPage, StoreError> {
        // Keep this page, its review versions and compatible contexts in one snapshot.
        let mut connection = self.lock()?;
        let tx = connection.transaction()?;
        let branch: String = tx
            .query_row(
                "SELECT a.branch FROM analyses a JOIN projects p ON p.project = a.project
                 WHERE a.id = ?1 AND p.project = ?2 AND a.deleted_at IS NULL AND p.deleted_at IS NULL",
                params![analysis_id, project],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::NotFound)?;
        let mut page = select_findings(&tx, analysis_id, window)?;
        if page.findings.iter().any(|f| !f.ambiguous) {
            attach_reviews(&tx, project, &branch, &mut page.findings)?;
        }
        filter_inherited_reviews(&tx, &mut page.findings, analysis_id)?;
        tx.commit()?;
        Ok(page)
    }
}

fn select_findings(
    db: &Connection,
    analysis_id: i64,
    window: Option<FindingWindow>,
) -> Result<FindingPage, StoreError> {
    // Fetch one extra row only to detect another page. Review reads exclude it.
    let row_limit = window.map_or(-1, |window| i64::from(window.limit) + 1);
    if let Some(after_id) = window.and_then(|window| window.after_id) {
        let position = finding_position(db, analysis_id, after_id)?;
        read_findings(
            db,
            NEXT_FINDINGS,
            params![
                analysis_id,
                row_limit,
                position.path,
                position.rule_key,
                position.identity,
                position.occurrence,
                after_id
            ],
            window.map(|window| window.limit),
        )
    } else {
        read_findings(
            db,
            FIRST_FINDINGS,
            params![analysis_id, row_limit],
            window.map(|window| window.limit),
        )
    }
}

fn finding_position(
    db: &Connection,
    analysis_id: i64,
    after_id: i64,
) -> Result<FindingPosition, StoreError> {
    db.query_row(
        "SELECT path, rule_key, identity, occurrence FROM findings WHERE id = ?1 AND analysis_id = ?2",
        params![after_id, analysis_id],
        |row| Ok(FindingPosition {
            path: row.get(0)?,
            rule_key: row.get(1)?,
            identity: row.get(2)?,
            occurrence: row.get(3)?,
        }),
    )
    .optional()?
    .ok_or(StoreError::InvalidFindingCursor)
}

fn read_findings(
    db: &Connection,
    sql: &str,
    bindings: impl Params,
    limit: Option<u16>,
) -> Result<FindingPage, StoreError> {
    let mut statement = db.prepare(sql)?;
    let mut rows = statement.query(bindings)?;
    let mut findings = Vec::new();
    let mut last_id = None;
    while let Some(row) = rows.next()? {
        if let Some(limit) = limit {
            if findings.len() == usize::from(limit) {
                return Ok(FindingPage {
                    findings,
                    next_id: last_id,
                });
            }
            last_id = Some(row.get(0)?);
        }
        let kind_text: String = row.get(3)?;
        findings.push(FindingRecord {
            identity: row.get(1)?,
            occurrence: row.get(2)?,
            kind: FindingKind::parse(&kind_text)
                .ok_or_else(|| StoreError::Invalid("invalid persisted finding kind".into()))?,
            path: row.get(4)?,
            rule_key: row.get(5)?,
            message: row.get(6)?,
            range: parse_json(&row.get::<_, String>(7)?)?,
            status: "open".into(),
            ambiguous: row.get::<_, i64>(8)? != 0,
            review: None,
        });
    }
    Ok(FindingPage {
        findings,
        next_id: None,
    })
}

// Keep review payloads out of the findings sort. On some projects nearly all
// findings are ambiguous and cannot receive a review.
fn attach_reviews(
    db: &Connection,
    project: &str,
    branch: &str,
    findings: &mut [FindingRecord],
) -> Result<(), StoreError> {
    // Ingest and restore mark repeated identities ambiguous; only unique claims
    // can receive or inherit a review. Match kind separately even for equal identities.
    let indices: HashMap<_, _> = findings
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.ambiguous)
        .map(|(i, f)| ((f.identity.as_str(), f.kind.as_str()), i))
        .collect();
    let identities: Vec<_> = indices.keys().map(|(identity, _)| *identity).collect();
    let identities =
        serde_json::to_string(&identities).map_err(|e| StoreError::Invalid(e.to_string()))?;
    let mut statement = db.prepare(
        "SELECT id, project, branch, analysis_id, identity, kind, state, version,
                updated_by, updated_at, reason FROM reviews
         WHERE project = ?2 AND branch = ?3 AND identity IN (SELECT value FROM json_each(?1))",
    )?;
    let mut matched = Vec::new();
    for row in statement.query_map(params![identities, project, branch], review_from_row)? {
        let review = row?;
        if let Some(&i) = indices.get(&(review.identity.as_str(), review.kind.as_str())) {
            matched.push((i, review));
        }
    }
    for (i, review) in matched {
        findings[i].review = Some(review);
    }
    Ok(())
}

fn filter_inherited_reviews(
    db: &Connection,
    findings: &mut [FindingRecord],
    current: i64,
) -> Result<(), StoreError> {
    let mut ids: BTreeSet<_> = findings
        .iter()
        .filter_map(|f| {
            f.review
                .as_ref()
                .map(|r| r.analysis_id)
                .filter(|id| *id != current)
        })
        .collect();
    if ids.is_empty() {
        return Ok(());
    }
    ids.insert(current);
    let ids = serde_json::to_string(&ids).map_err(|e| StoreError::Invalid(e.to_string()))?;
    // Retention can soft-delete the analysis on which a review was recorded.
    // Its context still determines whether the live analysis can inherit the review.
    let mut statement = db.prepare(
        "SELECT id, assessment_json -> '$.context' FROM analyses
         WHERE id IN (SELECT value FROM json_each(?1))",
    )?;
    let mut rows = statement.query([ids])?;
    let mut contexts = HashMap::new();
    while let Some(row) = rows.next()? {
        let raw: Option<String> = row.get(1)?;
        if let Some(context) = raw
            .and_then(|s| serde_json::from_str::<AnalysisContext>(&s).ok())
            .filter(|c| c.validate().is_ok())
        {
            contexts.insert(row.get::<_, i64>(0)?, context);
        }
    }
    for finding in findings {
        if let Some(review) = &finding.review
            && review.analysis_id != current
            && !contexts
                .get(&current)
                .zip(contexts.get(&review.analysis_id))
                .is_some_and(|(a, b)| a.compatible_with(b))
        {
            finding.review = None;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_sql_seeks_index_without_sorting() {
        fn plan(db: &Connection, sql: &str, arguments: impl Params) -> Vec<String> {
            db.prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(arguments, |row| row.get(3))
                .unwrap()
                .collect::<Result<_, _>>()
                .unwrap()
        }
        let mut db = Connection::open_in_memory().unwrap();
        super::super::schema::initialize(&mut db).unwrap();
        let first = plan(&db, FIRST_FINDINGS, params![1, 3]);
        let next = plan(
            &db,
            NEXT_FINDINGS,
            params![1, 3, "a.py", "S1", "identity", 0, 67],
        );
        for query in [&first, &next] {
            assert!(
                query.iter().any(
                    |step| step.contains("SEARCH findings USING INDEX findings_analysis_order")
                ),
                "{query:?}"
            );
            assert!(
                !query
                    .iter()
                    .any(|step| step.contains("TEMP B-TREE") || step.contains("SCAN findings")),
                "{query:?}"
            );
        }
        assert!(
            next.iter()
                .any(|step| step.contains("(path,rule_key,identity,occurrence)>(?,?,?,?)")),
            "{next:?}"
        );
    }
}
