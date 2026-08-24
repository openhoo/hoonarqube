use crate::support::dict_string_entry;
use crate::support::for_each_dict_literal;
use crate::support::has_boto3_binding;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6317_wildcard_action_scope(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // CE only evaluates policies in files with a resolvable boto3 binding;
    // stub-only files stay silent.
    if !has_boto3_binding(parsed.syntax().body.as_slice()) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_dict_literal(parsed.syntax().body.as_slice(), &mut |dict| {
        if dict_string_entry(dict, "Action").is_some_and(action_scope_wildcards) {
            issues.push(issue_at(
                "python:S6317",
                "Limit the scope of these IAM permissions.",
                dict.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S6317) ---
// --- python:S6317 — wildcard-scoped actions in policies ---------------------------

pub(crate) fn action_scope_wildcards(value: &Expr) -> bool {
    match value {
        Expr::List(list) => list.elts.iter().any(action_scope_wildcards),
        Expr::StringLiteral(_) => {
            string_literal_text(value).is_some_and(|action| action.ends_with(":*"))
        }
        _ => false,
    }
}
