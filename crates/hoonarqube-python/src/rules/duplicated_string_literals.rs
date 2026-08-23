use crate::AnalyzerOptions;
use crate::support::collect_literal_strings;
use crate::support::excluded_by_pattern;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use std::collections::HashMap;

pub(crate) fn check_duplicated_string_literals(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let threshold = (options.duplicate_literal_threshold.max(2)) as usize;
    let mut occurrences = Vec::new();
    collect_literal_strings(parsed.syntax().body.as_slice(), &mut occurrences);

    let mut totals: HashMap<String, usize> = HashMap::new();
    for (text, _) in &occurrences {
        *totals.entry(text.clone()).or_insert(0) += 1;
    }
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut issues = Vec::new();
    for (text, range) in &occurrences {
        let total = totals[text.as_str()];
        let nth = seen.entry(text.clone()).or_insert(0);
        *nth += 1;
        let excluded = excluded_by_pattern(&options.duplicate_literal_exclusion_regex, text);
        if total >= threshold && *nth > 1 && !excluded {
            issues.push(issue_at(
                "python:S1192",
                &format!("This string literal appears {total} times; extract it into a constant."),
                *range,
                index,
                source,
            ));
        }
    }
    issues
}
