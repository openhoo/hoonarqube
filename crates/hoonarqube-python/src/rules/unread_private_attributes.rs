use crate::AnalyzerOptions;
use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::engine::scope::name_used_in_tokens;
use crate::support::is_dunder_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use std::collections::HashSet;

// --- python:S4487 — unread private attributes --------------------------------

pub(crate) fn check_unread_private_attributes(
    table: &SymbolTable,
    facts: &FileFacts,
    options: &AnalyzerOptions,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut reported: HashSet<String> = HashSet::new();
    for (attr, range) in &table.attr_writes {
        let single_underscore = attr.starts_with('_') && !attr.starts_with("__");
        let double_underscore = attr.starts_with("__") && !is_dunder_name(attr);
        if !(double_underscore
            || (single_underscore && options.enable_single_underscore_attribute_issues))
            || !reported.insert(attr.clone())
        {
            continue;
        }
        let read = facts
            .attr_reads
            .iter()
            .any(|(read_attr, _)| read_attr == attr)
            || name_used_in_tokens(facts, attr, &[*range])
            || facts
                .string_texts
                .iter()
                .any(|text| text.contains(attr.as_str()));
        if !read {
            issues.push(issue_at(
                "python:S4487",
                &format!("Private attribute '{attr}' is written but never read."),
                *range,
                index,
                source,
            ));
        }
    }
    issues
}
