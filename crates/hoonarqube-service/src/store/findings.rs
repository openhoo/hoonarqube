use std::collections::{BTreeSet, HashMap};

use hoonarqube_ir::assessment::AnalysisContext;
use rusqlite::{Connection, OptionalExtension, params};

use super::{FindingKind, FindingRecord, Store, StoreError, parse_json, review_from_row};

impl Store {
    pub(crate) fn findings(
        &self,
        project: &str,
        analysis_id: i64,
    ) -> Result<Vec<FindingRecord>, StoreError> {
        // Keep the analysis, review versions and compatible contexts in one SQLite snapshot.
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
        let mut findings = findings_with_reviews(&tx, project, &branch, analysis_id)?;
        filter_inherited_reviews(&tx, &mut findings, analysis_id)?;
        tx.commit()?;
        Ok(findings)
    }
}

fn findings_with_reviews(
    db: &Connection,
    project: &str,
    branch: &str,
    analysis_id: i64,
) -> Result<Vec<FindingRecord>, StoreError> {
    let mut statement = db.prepare(
        "SELECT identity, occurrence, kind, path, rule_key, message, range_json, ambiguous
         FROM findings WHERE analysis_id = ?1 ORDER BY path, rule_key, identity, occurrence",
    )?;
    let mut rows = statement.query([analysis_id])?;
    let mut findings = Vec::new();
    while let Some(row) = rows.next()? {
        let kind_text: String = row.get(2)?;
        findings.push(FindingRecord {
            identity: row.get(0)?,
            occurrence: row.get(1)?,
            kind: FindingKind::parse(&kind_text)
                .ok_or_else(|| StoreError::Invalid("invalid persisted finding kind".into()))?,
            path: row.get(3)?,
            rule_key: row.get(4)?,
            message: row.get(5)?,
            range: parse_json(&row.get::<_, String>(6)?)?,
            status: "open".into(),
            ambiguous: row.get::<_, i64>(7)? != 0,
            review: None,
        });
    }
    if findings.iter().any(|f| !f.ambiguous) {
        attach_reviews(db, project, branch, &mut findings)?;
    }
    Ok(findings)
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
