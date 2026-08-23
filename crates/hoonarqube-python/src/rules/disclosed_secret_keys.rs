use crate::support::assignment_target_leaf_name;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_disclosed_secret_keys(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (targets, value): (Vec<&Expr>, Option<&Expr>) = match stmt {
            Stmt::Assign(assign) => (assign.targets.iter().collect(), Some(&assign.value)),
            Stmt::AnnAssign(assign) => (vec![&assign.target], assign.value.as_deref()),
            _ => (Vec::new(), None),
        };
        let secret_named = targets
            .iter()
            .filter_map(|target| assignment_target_leaf_name(target))
            .any(|name| name.to_lowercase().ends_with("secret_key"));
        if secret_named
            && let Some(value) = value
            && string_literal_text(value).is_some()
        {
            issues.push(issue_at(
                "python:S6779",
                "Do not disclose secret keys in source code.",
                value.range(),
                index,
                source,
            ));
        }
    });
    issues
}
