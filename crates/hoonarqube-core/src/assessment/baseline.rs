//! Conservative matching against a pinned reference assessment report.
//!
//! The first supported mode is an explicitly supplied, pinned report.  This
//! module does not inspect Git history, resolve merge bases, or read files.  A
//! caller that cannot provide a trustworthy reference must pass `None` and the
//! result remains indeterminate rather than becoming a clean zero.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use hoonarqube_ir::assessment::{
    ASSESSMENT_SCHEMA_VERSION, AnalysisContext, AssessmentError, AssessmentReport,
    AssessmentStatus, FindingIdentity, FindingMatch, FindingStatus, NewCodeLines, NewCodeReport,
    SourceSnapshot,
};

/// Schema version emitted by the pinned-reference baseline result.
pub const BASELINE_SCHEMA_VERSION: u32 = ASSESSMENT_SCHEMA_VERSION;
const MAX_NEW_CODE_LINES: u64 = 4_000_000;
const MAX_NEW_CODE_WORK: u64 = 64_000_000;

/// The only baseline mode implemented by this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineMode {
    /// Compare against the exact report supplied by the caller.
    PinnedReferenceReport,
}

/// Compares current source snapshots against an optional pinned reference
/// report.  Context/schema/source validation failures are represented in the
/// machine-readable status and diagnostics; they never produce a clean result.
#[must_use]
pub fn compare_to_reference(
    current_context: &AnalysisContext,
    current_sources: &[SourceSnapshot],
    reference: Option<&AssessmentReport>,
) -> NewCodeReport {
    let current_order = match ordered_sources(current_sources) {
        Ok(order) => order,
        Err(error) => {
            return unavailable_result(
                current_sources,
                AssessmentStatus::Invalid,
                None,
                format!("current assessment is invalid: {error}"),
            );
        }
    };

    let Some(reference) = reference else {
        return indeterminate_current(
            &current_order,
            AssessmentStatus::Missing,
            None,
            "pinned reference report is absent; new-code status is indeterminate",
        );
    };

    if let Err(error) = reference.validate() {
        return indeterminate_current(
            &current_order,
            AssessmentStatus::Invalid,
            Some(reference.context.clone()),
            format!("pinned reference report is invalid: {error}"),
        );
    }
    if !current_context.compatible_with(&reference.context) {
        return indeterminate_current(
            &current_order,
            AssessmentStatus::Incomplete,
            Some(reference.context.clone()),
            "pinned reference context is incompatible with the current analyzer, profile, scope, or source revision",
        );
    }

    let reference_order = match ordered_sources(&reference.sources) {
        Ok(order) => order,
        Err(error) => {
            return indeterminate_current(
                &current_order,
                AssessmentStatus::Invalid,
                Some(reference.context.clone()),
                format!("pinned reference sources are invalid: {error}"),
            );
        }
    };
    match classify(&current_order, &reference_order, reference.context.clone()) {
        Ok(result) => result,
        Err(error) => indeterminate_current(
            &current_order,
            AssessmentStatus::Incomplete,
            Some(reference.context.clone()),
            error,
        ),
    }
}

/// Compares two complete assessment reports.  This is convenient for callers
/// that already retained the current report and keeps all validation at this
/// boundary.
#[must_use]
pub fn compare_reports(
    current: &AssessmentReport,
    reference: Option<&AssessmentReport>,
) -> NewCodeReport {
    if let Err(error) = current.validate() {
        return unavailable_result(
            &current.sources,
            AssessmentStatus::Invalid,
            reference.map(|report| report.context.clone()),
            format!("current assessment is invalid: {error}"),
        );
    }
    compare_to_reference(&current.context, &current.sources, reference)
}

fn ordered_sources(sources: &[SourceSnapshot]) -> Result<Vec<&SourceSnapshot>, AssessmentError> {
    let mut order = sources.iter().collect::<Vec<_>>();
    for source in &order {
        source.validate()?;
    }
    order.sort_by(|left, right| left.path.cmp(&right.path));
    if order.windows(2).any(|pair| pair[0].path == pair[1].path) {
        let path = order
            .windows(2)
            .find(|pair| pair[0].path == pair[1].path)
            .map_or_else(PathBuf::new, |pair| pair[0].path.clone());
        return Err(AssessmentError::DuplicatePath(path));
    }
    Ok(order)
}

fn indeterminate_current(
    current: &[&SourceSnapshot],
    status: AssessmentStatus,
    reference_context: Option<AnalysisContext>,
    diagnostic: impl Into<String>,
) -> NewCodeReport {
    NewCodeReport {
        schema_version: BASELINE_SCHEMA_VERSION,
        status,
        reference_context,
        findings: current
            .iter()
            .flat_map(|source| {
                source.findings.iter().map(|finding| FindingMatch {
                    path: source.path.clone(),
                    issue_index: finding.issue_index,
                    identity: finding.identity.clone(),
                    status: FindingStatus::Uncertain,
                })
            })
            .collect(),
        resolved: Vec::new(),
        lines: Vec::new(),
        diagnostics: vec![diagnostic.into()],
    }
}

fn unavailable_result(
    _current_sources: &[SourceSnapshot],
    status: AssessmentStatus,
    reference_context: Option<AnalysisContext>,
    diagnostic: String,
) -> NewCodeReport {
    indeterminate_current(&[], status, reference_context, diagnostic)
}

fn classify(
    current: &[&SourceSnapshot],
    reference: &[&SourceSnapshot],
    reference_context: AnalysisContext,
) -> Result<NewCodeReport, String> {
    let reference_by_identity = reference_identity_index(reference);
    let mut new_lines = BTreeMap::<PathBuf, BTreeSet<u32>>::new();
    let mut total_new_lines = 0_u64;
    let mut new_line_work = 0_u64;
    let pairing = assign_counterparts(current, reference)?;
    let line_mapping_uncertain = add_changed_source_lines(
        current,
        reference,
        &pairing,
        &mut new_lines,
        &mut total_new_lines,
        &mut new_line_work,
    )?;
    let mut uncertain = line_mapping_uncertain;
    let (current_identities, current_identity_counts) = current_identity_data(current);
    let findings = {
        let mut classification = FindingClassification {
            reference_by_identity: &reference_by_identity,
            current_identity_counts: &current_identity_counts,
            new_lines: &mut new_lines,
            total_new_lines: &mut total_new_lines,
            new_line_work: &mut new_line_work,
            uncertain: &mut uncertain,
        };
        classify_current_findings(current, reference, &pairing, &mut classification)?
    };
    let resolved = collect_resolved(
        current,
        reference,
        &pairing,
        &current_identities,
        line_mapping_uncertain,
    );
    let lines = new_lines
        .into_iter()
        .map(|(path, lines)| NewCodeLines {
            path,
            lines: lines.into_iter().collect(),
        })
        .collect::<Vec<_>>();
    let diagnostics = classification_diagnostics(line_mapping_uncertain, uncertain);
    Ok(NewCodeReport {
        schema_version: BASELINE_SCHEMA_VERSION,
        status: if uncertain {
            AssessmentStatus::Incomplete
        } else {
            AssessmentStatus::Complete
        },
        reference_context: Some(reference_context),
        findings: sort_finding_matches(findings),
        resolved: sort_resolved(resolved)
            .into_iter()
            .map(|(_, finding)| finding)
            .collect(),
        lines,
        diagnostics,
    })
}

fn reference_identity_index<'a>(
    reference: &[&'a SourceSnapshot],
) -> BTreeMap<String, Vec<&'a FindingIdentity>> {
    let mut identities = BTreeMap::<String, Vec<&FindingIdentity>>::new();
    for source in reference {
        for finding in &source.findings {
            identities
                .entry(finding.identity.clone())
                .or_default()
                .push(finding);
        }
    }
    identities
}

fn current_identity_data(
    current: &[&SourceSnapshot],
) -> (BTreeSet<String>, BTreeMap<String, usize>) {
    let mut identities = BTreeSet::<String>::new();
    let mut counts = BTreeMap::<String, usize>::new();
    for source in current {
        for finding in &source.findings {
            identities.insert(finding.identity.clone());
            *counts.entry(finding.identity.clone()).or_default() += 1;
        }
    }
    (identities, counts)
}

struct FindingClassification<'map, 'finding> {
    reference_by_identity: &'map BTreeMap<String, Vec<&'finding FindingIdentity>>,
    current_identity_counts: &'map BTreeMap<String, usize>,
    new_lines: &'map mut BTreeMap<PathBuf, BTreeSet<u32>>,
    total_new_lines: &'map mut u64,
    new_line_work: &'map mut u64,
    uncertain: &'map mut bool,
}

fn classify_current_findings(
    current: &[&SourceSnapshot],
    reference: &[&SourceSnapshot],
    pairing: &CounterpartPairs,
    classification: &mut FindingClassification<'_, '_>,
) -> Result<Vec<FindingMatch>, String> {
    let mut findings = Vec::new();
    for (current_index, source) in current.iter().enumerate() {
        let source = *source;
        let reference_source =
            pairing.current_to_reference[current_index].map(|index| reference[index]);
        for finding in &source.findings {
            let status = classify_finding(finding, source, reference_source, classification)?;
            findings.push(FindingMatch {
                path: source.path.clone(),
                issue_index: finding.issue_index,
                identity: finding.identity.clone(),
                status,
            });
        }
    }
    Ok(findings)
}

fn classify_finding(
    finding: &FindingIdentity,
    source: &SourceSnapshot,
    reference_source: Option<&SourceSnapshot>,
    classification: &mut FindingClassification<'_, '_>,
) -> Result<FindingStatus, String> {
    let (local_candidates, local_candidate) =
        local_identity_candidates(reference_source, &finding.identity);
    let known_reference_identity = classification
        .reference_by_identity
        .contains_key(&finding.identity);
    if finding.ambiguous
        || classification
            .current_identity_counts
            .get(&finding.identity)
            != Some(&1)
    {
        *classification.uncertain = true;
        return Ok(FindingStatus::Uncertain);
    }
    if local_candidates == 0 {
        if known_reference_identity {
            *classification.uncertain = true;
            return Ok(FindingStatus::Uncertain);
        }
        add_new_lines(
            classification.new_lines,
            &source.path,
            finding,
            classification.total_new_lines,
            classification.new_line_work,
        )?;
        return Ok(FindingStatus::New);
    }
    if local_candidates == 1 && local_candidate.is_some_and(|candidate| !candidate.ambiguous) {
        Ok(FindingStatus::Existing)
    } else {
        *classification.uncertain = true;
        Ok(FindingStatus::Uncertain)
    }
}

fn local_identity_candidates<'a>(
    source: Option<&'a SourceSnapshot>,
    identity: &str,
) -> (usize, Option<&'a FindingIdentity>) {
    let Some(source) = source else {
        return (0, None);
    };
    let candidates = source
        .findings
        .iter()
        .filter(|candidate| candidate.identity == identity)
        .count();
    let candidate = source
        .findings
        .iter()
        .find(|candidate| candidate.identity == identity);
    (candidates, candidate)
}

fn collect_resolved(
    current: &[&SourceSnapshot],
    reference: &[&SourceSnapshot],
    pairing: &CounterpartPairs,
    current_identities: &BTreeSet<String>,
    line_mapping_uncertain: bool,
) -> Vec<(PathBuf, FindingIdentity)> {
    if line_mapping_uncertain {
        return Vec::new();
    }
    let mut resolved = Vec::<(PathBuf, FindingIdentity)>::new();
    for (reference_index, source) in reference.iter().enumerate() {
        let Some(current_index) = pairing.reference_to_current[reference_index] else {
            continue;
        };
        let current_source = current[current_index];
        collect_source_resolved(source, current_source, current_identities, &mut resolved);
    }
    resolved
}

fn collect_source_resolved(
    reference_source: &SourceSnapshot,
    current_source: &SourceSnapshot,
    current_identities: &BTreeSet<String>,
    resolved: &mut Vec<(PathBuf, FindingIdentity)>,
) {
    if current_source
        .findings
        .iter()
        .any(|finding| finding.ambiguous)
    {
        return;
    }
    for finding in &reference_source.findings {
        if !finding.ambiguous && !current_identities.contains(&finding.identity) {
            resolved.push((reference_source.path.clone(), finding.clone()));
        }
    }
}

fn sort_finding_matches(mut findings: Vec<FindingMatch>) -> Vec<FindingMatch> {
    findings.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.issue_index.cmp(&right.issue_index))
            .then_with(|| left.identity.cmp(&right.identity))
    });
    findings
}

fn sort_resolved(mut resolved: Vec<(PathBuf, FindingIdentity)>) -> Vec<(PathBuf, FindingIdentity)> {
    resolved.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.issue_index.cmp(&right.1.issue_index))
            .then_with(|| left.1.identity.cmp(&right.1.identity))
    });
    resolved
}

fn classification_diagnostics(line_mapping_uncertain: bool, uncertain: bool) -> Vec<String> {
    let mut diagnostics = Vec::new();
    if line_mapping_uncertain {
        diagnostics.push(
            "one or more changed source files had ambiguous baseline line mapping".to_string(),
        );
    }
    if uncertain && !line_mapping_uncertain {
        diagnostics.push(
            "one or more finding identities are duplicated or ambiguous; they remain uncertain"
                .to_string(),
        );
    } else if uncertain {
        diagnostics.push(
            "one or more finding identities or changed-line mappings are ambiguous; they remain uncertain"
                .to_string(),
        );
    }
    diagnostics
}

struct CounterpartPairs {
    current_to_reference: Vec<Option<usize>>,
    reference_to_current: Vec<Option<usize>>,
    ambiguous: bool,
}

fn assign_counterparts(
    current: &[&SourceSnapshot],
    reference: &[&SourceSnapshot],
) -> Result<CounterpartPairs, String> {
    const MAX_SOURCE_FILES: usize = 16_384;
    const MAX_PAIR_WORK: usize = 4_000_000;
    const MAX_LINE_WORK: usize = 64_000_000;
    validate_source_inventory(current, reference, MAX_SOURCE_FILES)?;

    let mut current_to_reference = vec![None; current.len()];
    let mut reference_to_current = vec![None; reference.len()];
    let mut used_current = vec![false; current.len()];
    let mut used_reference = vec![false; reference.len()];
    pair_exact_paths(
        current,
        reference,
        &mut current_to_reference,
        &mut reference_to_current,
        &mut used_current,
        &mut used_reference,
    );
    let current_groups = unpaired_digest_groups(current, &used_current);
    let reference_groups = unpaired_digest_groups(reference, &used_reference);
    let mut ambiguous = pair_unique_digests(
        current_groups,
        &reference_groups,
        &mut current_to_reference,
        &mut reference_to_current,
        &mut used_current,
        &mut used_reference,
    );

    let mut pair_work = 0_usize;
    let mut line_work = 0_usize;
    let mut candidates_by_current = vec![Vec::<(usize, usize)>::new(); current.len()];
    let mut candidates_by_reference = vec![Vec::<(usize, usize)>::new(); reference.len()];
    {
        let mut matching = CounterpartMatching {
            current,
            reference,
            used_reference: &used_reference,
            max_pair_work: MAX_PAIR_WORK,
            max_line_work: MAX_LINE_WORK,
            pair_work: &mut pair_work,
            line_work: &mut line_work,
        };
        collect_counterpart_candidates(
            &mut matching,
            &used_current,
            &mut candidates_by_current,
            &mut candidates_by_reference,
        )?;
    }
    ambiguous |= reserve_fuzzy_counterparts(
        current,
        &mut current_to_reference,
        &mut reference_to_current,
        &mut used_current,
        &mut used_reference,
        &candidates_by_current,
        &candidates_by_reference,
    );
    Ok(CounterpartPairs {
        current_to_reference,
        reference_to_current,
        ambiguous,
    })
}

fn validate_source_inventory(
    current: &[&SourceSnapshot],
    reference: &[&SourceSnapshot],
    max_source_files: usize,
) -> Result<(), String> {
    if current.len() > max_source_files || reference.len() > max_source_files {
        return Err("assessment source inventory exceeds the bounded baseline limit".to_string());
    }
    Ok(())
}

fn pair_exact_paths(
    current: &[&SourceSnapshot],
    reference: &[&SourceSnapshot],
    current_to_reference: &mut [Option<usize>],
    reference_to_current: &mut [Option<usize>],
    used_current: &mut [bool],
    used_reference: &mut [bool],
) {
    let mut reference_by_path = BTreeMap::<PathBuf, usize>::new();
    for (reference_index, source) in reference.iter().enumerate() {
        reference_by_path.insert(source.path.clone(), reference_index);
    }
    for (current_index, source) in current.iter().enumerate() {
        let Some(&reference_index) = reference_by_path.get(&source.path) else {
            continue;
        };
        current_to_reference[current_index] = Some(reference_index);
        reference_to_current[reference_index] = Some(current_index);
        used_current[current_index] = true;
        used_reference[reference_index] = true;
    }
}

fn unpaired_digest_groups(
    sources: &[&SourceSnapshot],
    used: &[bool],
) -> BTreeMap<String, Vec<usize>> {
    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for (index, source) in sources.iter().enumerate() {
        if !used[index] {
            groups
                .entry(source.content_digest.clone())
                .or_default()
                .push(index);
        }
    }
    groups
}

fn pair_unique_digests(
    current_groups: BTreeMap<String, Vec<usize>>,
    reference_groups: &BTreeMap<String, Vec<usize>>,
    current_to_reference: &mut [Option<usize>],
    reference_to_current: &mut [Option<usize>],
    used_current: &mut [bool],
    used_reference: &mut [bool],
) -> bool {
    let mut ambiguous = false;
    for (digest, current_group) in current_groups {
        let Some(reference_group) = reference_groups.get(&digest) else {
            continue;
        };
        if current_group.len() == 1 && reference_group.len() == 1 {
            let current_index = current_group[0];
            let reference_index = reference_group[0];
            current_to_reference[current_index] = Some(reference_index);
            reference_to_current[reference_index] = Some(current_index);
            used_current[current_index] = true;
            used_reference[reference_index] = true;
        } else {
            // Equal bytes in more than one unpaired source cannot prove a
            // rename. Leave all of them unpaired and make the result
            // incomplete rather than reusing a reference.
            ambiguous = true;
        }
    }
    ambiguous
}

struct CounterpartMatching<'sources, 'state> {
    current: &'sources [&'state SourceSnapshot],
    reference: &'sources [&'state SourceSnapshot],
    used_reference: &'sources [bool],
    max_pair_work: usize,
    max_line_work: usize,
    pair_work: &'state mut usize,
    line_work: &'state mut usize,
}

fn collect_counterpart_candidates(
    matching: &mut CounterpartMatching<'_, '_>,
    used_current: &[bool],
    candidates_by_current: &mut [Vec<(usize, usize)>],
    candidates_by_reference: &mut [Vec<(usize, usize)>],
) -> Result<(), String> {
    let current_len = matching.current.len();
    for current_index in 0..current_len {
        if used_current[current_index] {
            continue;
        }
        for (reference_index, reference_candidates) in
            candidates_by_reference.iter_mut().enumerate()
        {
            let Some(score) =
                counterpart_candidate_score(matching, current_index, reference_index)?
            else {
                continue;
            };
            candidates_by_current[current_index].push((reference_index, score));
            reference_candidates.push((current_index, score));
        }
    }
    Ok(())
}

fn counterpart_candidate_score(
    matching: &mut CounterpartMatching<'_, '_>,
    current_index: usize,
    reference_index: usize,
) -> Result<Option<usize>, String> {
    if matching.used_reference[reference_index]
        || matching.current[current_index].content_digest
            == matching.reference[reference_index].content_digest
    {
        return Ok(None);
    }
    *matching.pair_work = (*matching.pair_work).saturating_add(1);
    if *matching.pair_work > matching.max_pair_work {
        return Err("baseline counterpart candidate work exceeds the bounded limit".to_string());
    }
    let score = line_overlap_score(
        matching.current[current_index],
        matching.reference[reference_index],
        matching.line_work,
        matching.max_line_work,
    )?;
    Ok((score != 0).then_some(score))
}

fn reserve_fuzzy_counterparts(
    current: &[&SourceSnapshot],
    current_to_reference: &mut [Option<usize>],
    reference_to_current: &mut [Option<usize>],
    used_current: &mut [bool],
    used_reference: &mut [bool],
    candidates_by_current: &[Vec<(usize, usize)>],
    candidates_by_reference: &[Vec<(usize, usize)>],
) -> bool {
    let mut ambiguous = false;
    for current_index in 0..current.len() {
        if used_current[current_index] {
            continue;
        }
        let candidates = &candidates_by_current[current_index];
        let Some(best_score) = candidates.iter().map(|(_, score)| *score).max() else {
            continue;
        };
        let best = best_candidate_references(candidates, best_score);
        let reference_has_tie = best.iter().any(|reference_index| {
            reference_candidate_ties(candidates_by_reference, *reference_index)
        });
        if best.len() != 1 || reference_has_tie {
            ambiguous = true;
            continue;
        }
        let reference_index = best[0];
        if used_reference[reference_index] {
            ambiguous = true;
            continue;
        }
        current_to_reference[current_index] = Some(reference_index);
        reference_to_current[reference_index] = Some(current_index);
        used_current[current_index] = true;
        used_reference[reference_index] = true;
    }
    ambiguous
}

fn best_candidate_references(candidates: &[(usize, usize)], best_score: usize) -> Vec<usize> {
    candidates
        .iter()
        .filter(|(_, score)| *score == best_score)
        .map(|(reference_index, _)| *reference_index)
        .collect()
}

fn reference_candidate_ties(
    candidates_by_reference: &[Vec<(usize, usize)>],
    reference_index: usize,
) -> bool {
    let candidates = &candidates_by_reference[reference_index];
    let max_score = candidates
        .iter()
        .map(|(_, score)| *score)
        .max()
        .unwrap_or(0);
    candidates
        .iter()
        .filter(|(_, score)| *score == max_score)
        .count()
        > 1
}

fn line_overlap_score(
    left: &SourceSnapshot,
    right: &SourceSnapshot,
    line_work: &mut usize,
    max_line_work: usize,
) -> Result<usize, String> {
    lcs_length(
        &left.line_digests,
        &right.line_digests,
        line_work,
        max_line_work,
    )
}

fn matrix_cells(left_len: usize, right_len: usize) -> Result<usize, String> {
    const MAX_ALIGNMENT_CELLS: usize = 4_000_000;
    let cells = left_len
        .checked_add(1)
        .and_then(|left| {
            right_len
                .checked_add(1)
                .and_then(|right| left.checked_mul(right))
        })
        .ok_or_else(|| "baseline alignment matrix size overflows".to_string())?;
    if cells > MAX_ALIGNMENT_CELLS {
        return Err("baseline alignment matrix exceeds the bounded limit".to_string());
    }
    Ok(cells)
}

fn reserve_alignment_work(
    line_work: &mut usize,
    max_line_work: usize,
    cells: usize,
    passes: usize,
) -> Result<(), String> {
    let work = cells
        .checked_mul(passes)
        .ok_or_else(|| "baseline alignment work overflows".to_string())?;
    *line_work = line_work
        .checked_add(work)
        .ok_or_else(|| "baseline alignment work overflows".to_string())?;
    if *line_work > max_line_work {
        return Err("baseline line-mapping work exceeds the bounded limit".to_string());
    }
    Ok(())
}

fn lcs_length(
    left: &[String],
    right: &[String],
    line_work: &mut usize,
    max_line_work: usize,
) -> Result<usize, String> {
    let cells = matrix_cells(left.len(), right.len())?;
    reserve_alignment_work(line_work, max_line_work, cells, 1)?;
    let mut previous = vec![0_u32; right.len() + 1];
    let mut current = vec![0_u32; right.len() + 1];
    for left_line in left {
        current[0] = 0;
        for (index, right_line) in right.iter().enumerate() {
            current[index + 1] = if left_line == right_line {
                previous[index] + 1
            } else {
                previous[index + 1].max(current[index])
            };
        }
        std::mem::swap(&mut previous, &mut current);
    }
    Ok(previous[right.len()] as usize)
}

struct LineAlignment {
    new_line_indices: Vec<usize>,
    uncertain: bool,
}

fn align_lines(
    current: &[String],
    reference: &[String],
    line_work: &mut usize,
    max_line_work: usize,
) -> Result<LineAlignment, String> {
    let cells = matrix_cells(current.len(), reference.len())?;
    reserve_alignment_work(line_work, max_line_work, cells, 3)?;
    let columns = reference.len() + 1;
    let prefix = alignment_prefix(current, reference, cells, columns);
    let suffix = alignment_suffix(current, reference, cells, columns);
    let global = prefix[current.len() * columns + reference.len()];
    let mut new_line_indices = Vec::new();
    let mut uncertain = false;
    for current_index in 0..current.len() {
        let decision = aligned_line_decision(
            current,
            reference,
            &prefix,
            &suffix,
            columns,
            current_index,
            global,
        );
        if decision.new_line {
            new_line_indices.push(current_index);
        }
        uncertain |= decision.uncertain;
    }
    Ok(LineAlignment {
        new_line_indices,
        uncertain,
    })
}

fn alignment_prefix(
    current: &[String],
    reference: &[String],
    cells: usize,
    columns: usize,
) -> Vec<u32> {
    let mut prefix = vec![0_u32; cells];
    for (current_index, current_line) in current.iter().enumerate() {
        let row = current_index + 1;
        for (reference_index, reference_line) in reference.iter().enumerate() {
            let column = reference_index + 1;
            prefix[row * columns + column] = if current_line == reference_line {
                prefix[(row - 1) * columns + column - 1] + 1
            } else {
                prefix[(row - 1) * columns + column].max(prefix[row * columns + column - 1])
            };
        }
    }
    prefix
}

fn alignment_suffix(
    current: &[String],
    reference: &[String],
    cells: usize,
    columns: usize,
) -> Vec<u32> {
    let mut suffix = vec![0_u32; cells];
    for current_index in (0..current.len()).rev() {
        for reference_index in (0..reference.len()).rev() {
            let row = current_index;
            let column = reference_index;
            suffix[row * columns + column] = if current[current_index] == reference[reference_index]
            {
                suffix[(row + 1) * columns + column + 1] + 1
            } else {
                suffix[(row + 1) * columns + column].max(suffix[row * columns + column + 1])
            };
        }
    }
    suffix
}

#[derive(Debug, Clone, Copy)]
struct AlignmentDecision {
    new_line: bool,
    uncertain: bool,
}

fn aligned_line_decision(
    current: &[String],
    reference: &[String],
    prefix: &[u32],
    suffix: &[u32],
    columns: usize,
    current_index: usize,
    global: u32,
) -> AlignmentDecision {
    let mut include_best = 0_u32;
    let mut include_positions = 0_usize;
    for (reference_index, reference_line) in reference.iter().enumerate() {
        if current[current_index].as_str() != reference_line.as_str() {
            continue;
        }
        let score = prefix[current_index * columns + reference_index]
            + 1
            + suffix[(current_index + 1) * columns + reference_index + 1];
        if score > include_best {
            include_best = score;
            include_positions = 1;
        } else if score == include_best {
            include_positions += 1;
        }
    }
    let exclude_best = (0..=reference.len())
        .map(|reference_index| {
            prefix[current_index * columns + reference_index]
                + suffix[(current_index + 1) * columns + reference_index]
        })
        .max()
        .unwrap_or(0);
    if global == 0 || include_best < global {
        AlignmentDecision {
            new_line: true,
            uncertain: false,
        }
    } else if exclude_best < global {
        AlignmentDecision {
            new_line: false,
            uncertain: include_positions > 1,
        }
    } else {
        AlignmentDecision {
            new_line: true,
            uncertain: true,
        }
    }
}

fn add_changed_source_lines(
    current: &[&SourceSnapshot],
    reference: &[&SourceSnapshot],
    pairing: &CounterpartPairs,
    line_sets: &mut BTreeMap<PathBuf, BTreeSet<u32>>,
    total_new_lines: &mut u64,
    new_line_work: &mut u64,
) -> Result<bool, String> {
    let mut uncertain = pairing.ambiguous;
    let mut line_work = 0_usize;
    for (current_index, source) in current.iter().enumerate() {
        let mut add_line = |index: usize| -> Result<(), String> {
            *new_line_work = (*new_line_work)
                .checked_add(1)
                .ok_or_else(|| "new-code line mapping work overflows".to_string())?;
            if *new_line_work > MAX_NEW_CODE_WORK {
                return Err("new-code line mapping work exceeds the bounded limit".to_string());
            }
            let line = u32::try_from(index + 1)
                .map_err(|_| "source line number exceeds the u32 artifact range".to_string())?;
            let lines = line_sets.entry(source.path.clone()).or_default();
            if lines.insert(line) {
                *total_new_lines += 1;
                if *total_new_lines > MAX_NEW_CODE_LINES {
                    return Err("new-code line set exceeds the bounded line-set limit".to_string());
                }
            }
            Ok(())
        };
        let reference_source =
            pairing.current_to_reference[current_index].map(|index| reference[index]);
        if reference_source
            .is_some_and(|reference| reference.content_digest == source.content_digest)
        {
            continue;
        }
        let Some(reference_source) = reference_source else {
            for index in 0..source.line_digests.len() {
                add_line(index)?;
            }
            continue;
        };
        let alignment = align_lines(
            &source.line_digests,
            &reference_source.line_digests,
            &mut line_work,
            64_000_000,
        )?;
        uncertain |= alignment.uncertain;
        for index in alignment.new_line_indices {
            add_line(index)?;
        }
    }
    Ok(uncertain)
}

fn add_new_lines(
    line_sets: &mut BTreeMap<PathBuf, BTreeSet<u32>>,
    path: &Path,
    finding: &FindingIdentity,
    total_new_lines: &mut u64,
    new_line_work: &mut u64,
) -> Result<(), String> {
    if finding.start_line == 0 || finding.end_line == 0 {
        return Ok(());
    }
    let lines = line_sets.entry(path.to_path_buf()).or_default();
    for line in finding.start_line..=finding.end_line {
        *new_line_work = (*new_line_work)
            .checked_add(1)
            .ok_or_else(|| "new-code line mapping work overflows".to_string())?;
        if *new_line_work > MAX_NEW_CODE_WORK {
            return Err("new-code line mapping work exceeds the bounded limit".to_string());
        }
        if lines.contains(&line) {
            continue;
        }
        if *total_new_lines >= MAX_NEW_CODE_LINES {
            return Err("new-code line set exceeds the bounded line-set limit".to_string());
        }
        lines.insert(line);
        *total_new_lines += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hoonarqube_ir::assessment::SourceInput;
    use hoonarqube_ir::{FileMetrics, FileReport, Issue, Pos, Range};
    use std::path::PathBuf;

    fn context() -> AnalysisContext {
        AnalysisContext::new("analyzer", "catalog", "options", "scope", None::<String>)
    }

    fn assessment(path: &str, source: &str, issues: Vec<Issue>) -> AssessmentReport {
        let path = PathBuf::from(path);
        let input = SourceInput::new(&path, source.as_bytes());
        let line_count =
            u32::try_from(source.lines().count()).expect("fixture line count fits u32");
        let file = FileReport {
            path: path.clone(),
            language: "python".to_string(),
            issues,
            metrics: FileMetrics {
                lines: line_count,
                code_lines: line_count,
                comment_lines: 0,
            },
        };
        AssessmentReport::from_reports_and_source_inputs(context(), &[file], &[input])
            .expect("assessment")
    }

    fn finding(message: &str) -> Issue {
        Issue::new(
            "python:S1",
            message,
            Range {
                start: Pos { line: 1, column: 0 },
                end: Pos { line: 1, column: 3 },
            },
        )
    }

    fn report(path: &str, source: &str, message: &str) -> AssessmentReport {
        assessment(path, source, vec![finding(message)])
    }

    fn clean(path: &str, source: &str) -> AssessmentReport {
        assessment(path, source, Vec::new())
    }

    #[test]
    fn overlapping_new_finding_range_reuses_existing_line_budget() {
        let path = PathBuf::from("src/a.py");
        let finding = report("src/a.py", "bad\n", "message").sources[0].findings[0].clone();
        let mut line_sets = BTreeMap::new();
        let mut existing_lines = BTreeSet::new();
        existing_lines.insert(1);
        line_sets.insert(path.clone(), existing_lines);
        let mut total_new_lines = MAX_NEW_CODE_LINES;
        let mut new_line_work = 0;
        add_new_lines(
            &mut line_sets,
            &path,
            &finding,
            &mut total_new_lines,
            &mut new_line_work,
        )
        .expect("overlapping line was already counted");
        assert_eq!(total_new_lines, MAX_NEW_CODE_LINES);
        assert_eq!(line_sets[&path].len(), 1);
    }

    #[test]
    fn absent_reference_is_not_a_clean_result() {
        let current = report("src/a.py", "bad\n", "message");
        let result = compare_reports(&current, None);
        assert_eq!(result.status, AssessmentStatus::Missing);
        assert_eq!(result.findings[0].status, FindingStatus::Uncertain);
        assert!(result.lines.is_empty());
    }

    #[test]
    fn invalid_current_report_returns_a_valid_empty_result() {
        let current = AssessmentReport {
            schema_version: 99,
            context: context(),
            sources: Vec::new(),
            coverage: None,
            new_code: None,
            gate: None,
        };
        let result = compare_reports(&current, None);
        assert_eq!(result.status, AssessmentStatus::Invalid);
        assert!(result.validate().is_ok());
        assert!(result.findings.is_empty());
        assert!(result.lines.is_empty());
    }
    #[test]
    fn changed_clean_source_exposes_changed_lines_without_trailing_sentinel() {
        let reference = clean("src/a.py", "one\nstable\n");
        let current = clean("src/a.py", "one\nchanged\n");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Complete);
        assert_eq!(result.lines[0].path, PathBuf::from("src/a.py"));
        assert_eq!(result.lines[0].lines, vec![2]);
    }

    #[test]
    fn changed_source_resolves_a_removed_reference_finding() {
        let reference = report("src/a.py", "bad\n", "old message");
        let current = clean("src/a.py", "good\n");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Complete);
        assert_eq!(result.resolved.len(), 1);
    }

    #[test]
    fn changed_finding_is_new_and_marks_its_line() {
        let reference = report("src/a.py", "bad\n", "message");
        let current = report("src/a.py", "new\n", "message");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Complete);
        assert_eq!(result.findings[0].status, FindingStatus::New);
        assert_eq!(result.lines[0].lines, vec![1]);
    }

    #[test]
    fn copied_current_finding_is_not_reused_across_files() {
        let reference = report("src/a.py", "bad\n", "message");
        let first = report("src/a.py", "bad\n", "message");
        let second = report("src/b.py", "bad\n", "message");
        let current = AssessmentReport::new(
            context(),
            first.sources.into_iter().chain(second.sources).collect(),
        )
        .expect("current assessment");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Incomplete);
        assert_eq!(result.findings.len(), 2);
        assert!(
            result
                .findings
                .iter()
                .all(|finding| finding.status == FindingStatus::Uncertain)
        );
    }

    #[test]
    fn rival_fuzzy_renames_remain_uncertain() {
        let reference = clean("old.py", "common\nold\n");
        let current = AssessmentReport::new(
            context(),
            vec![
                SourceSnapshot::from_source("a.py", b"common\na\n", &[]).expect("source"),
                SourceSnapshot::from_source("b.py", b"common\nb\n", &[]).expect("source"),
            ],
        )
        .expect("current assessment");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Incomplete);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("ambiguous"))
        );
    }

    #[test]
    fn repeated_lines_in_an_unmatched_new_file_are_complete() {
        let reference = clean("old.py", "old\n");
        let current = AssessmentReport::new(
            context(),
            vec![SourceSnapshot::from_source("new.py", b"same\nsame\n", &[]).expect("source")],
        )
        .expect("current assessment");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Complete);
        assert_eq!(result.lines[0].lines, vec![1, 2]);
    }

    #[test]
    fn blank_physical_line_is_new_code() {
        let reference = clean("src.py", "first\nlast\n");
        let current = AssessmentReport::new(
            context(),
            vec![SourceSnapshot::from_source("src.py", b"first\n\nlast\n", &[]).expect("source")],
        )
        .expect("current assessment");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Complete);
        assert_eq!(result.lines[0].lines, vec![2]);
    }

    #[test]
    fn reordered_lines_are_not_collapsed_by_equal_digest_counts() {
        let reference = clean("src.py", "x=1\nsend()\nx=2\n");
        let current = AssessmentReport::new(
            context(),
            vec![
                SourceSnapshot::from_source("src.py", b"x=2\nsend()\nx=1\n", &[]).expect("source"),
            ],
        )
        .expect("current assessment");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Incomplete);
        assert_eq!(result.lines[0].lines, vec![1, 2, 3]);
    }

    #[test]
    fn message_change_and_path_rename_keep_existing_identity() {
        let reference = report("src/a.py", "bad\n", "old message");
        let current = report("renamed/a.py", "bad\n", "new message");
        let result = compare_reports(&current, Some(&reference));
        assert_eq!(result.status, AssessmentStatus::Complete);
        assert_eq!(result.findings[0].status, FindingStatus::Existing);
    }
}
