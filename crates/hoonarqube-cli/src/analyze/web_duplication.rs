//! Project-wide Web duplication scope. Directory and explicitly named files
//! pass through the same source selection, bounded read and facts collector.
use super::{
    AnalyzedSource, CollectedProjectInputs, FileClassification, Language,
    MAX_RETAINED_SOURCE_BYTES, Path, PathBuf, ProjectAnalysisOptions, ProjectFile,
    community_inputs, deduplicate_input_files, is_inventory_class, read_bounded_source,
};

fn web(path: &Path) -> bool {
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        ["html", "xhtml", "erb"]
            .iter()
            .any(|s| e.eq_ignore_ascii_case(s))
    })
}

pub(super) fn collect(
    mut files: Vec<PathBuf>,
    failures: Vec<(PathBuf, String)>,
    opts: &ProjectAnalysisOptions,
    out: &mut CollectedProjectInputs,
    warnings: &mut Vec<String>,
) {
    for (path, reason) in failures {
        super::record_collection_failure(out, path, reason, &opts.patterns, false);
    }
    files.extend(
        std::mem::take(&mut out.unsupported_inventory)
            .into_iter()
            .map(|(p, _)| p),
    );
    let mut measured = false;
    let mut remaining_tokens = opts.duplication.max_tokens;
    if opts.duplication.min_lines != 10 || opts.duplication.min_tokens != 100 {
        warnings
            .push("Community Web duplication requires its 10-line and 100-token thresholds".into());
    }

    for path in deduplicate_input_files(files) {
        let classification = super::classify_collected_path(&opts.patterns, &path);
        let mut row = ProjectFile {
            path: path.clone(),
            classification,
            report: None,
            facts: None,
            error: None,
            duplication_excluded: opts.patterns.duplication_excluded(&path),
        };
        if is_inventory_class(classification) {
            out.project_files.push(row);
            continue;
        }
        if !web(&path) {
            // This Community build has no Ruby analyzer. Other recognized
            // source families cannot be silently dropped from the denominator.
            if hoonarqube_core::language_for_path(&path) == Some(Language::Ruby) {
                continue;
            }
            row.error = Some(
                if hoonarqube_core::language_for_path(&path).is_some()
                    || community_inputs::classify(&path).is_some()
                {
                    "another source language is outside the Web duplication measurement"
                } else {
                    "explicit file has no verified Web classification"
                }
                .to_owned(),
            );
        } else if classification != FileClassification::Source || row.duplication_excluded {
            row.error = Some(
                "test and CPD-exclusion semantics are not qualified for Web duplication".into(),
            );
        } else {
            let result = (|| {
                let source = read_bounded_source(&path)
                    .map_err(|e| format!("cannot read Web source: {e}"))?;
                let cost = source.len().max(1);
                out.retained_bytes = out
                    .retained_bytes
                    .checked_add(cost)
                    .filter(|n| *n <= MAX_RETAINED_SOURCE_BYTES)
                    .ok_or("Web source budget exceeded")?;
                let facts =
                    hoonarqube_core::source_facts::community_web_facts(&source, remaining_tokens)?;
                remaining_tokens = remaining_tokens
                    .checked_sub(facts.tokens.len())
                    .ok_or("project Web token budget exceeded")?;
                row.report = Some(hoonarqube_ir::FileReport {
                    path: path.clone(),
                    language: "web".into(),
                    issues: Vec::new(),
                    metrics: facts.metrics.clone(),
                });
                row.facts = Some(facts);
                measured = true;
                if opts.features.assessment_requested() {
                    out.source_inventory.push(AnalyzedSource {
                        path,
                        source,
                        classification,
                    });
                }
                Ok::<_, String>(())
            })();
            row.error = result.err();
        }
        out.project_files.push(row);
    }
    if !measured {
        warnings.push("no qualified Web source contributed to the duplication measurement".into());
    }
}
