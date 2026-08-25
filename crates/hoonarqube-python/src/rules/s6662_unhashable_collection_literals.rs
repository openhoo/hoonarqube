use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6662_unhashable_collection_literals(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let unhashable =
        |expr: &Expr| literal_kind(expr).is_some_and(|kind| UNHASHABLE_KINDS.contains(&kind));
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::Set(set) => {
            for element in set.elts.iter().filter(|element| unhashable(element)) {
                issues.push(issue_at(
                    "python:S6662",
                    "This set member is not hashable.",
                    element.range(),
                    index,
                    source,
                ));
            }
        }
        Expr::Dict(dict) => {
            for item in &dict.items {
                if let Some(key) = item.key.as_ref()
                    && unhashable(key)
                {
                    issues.push(issue_at(
                        "python:S6662",
                        "This dictionary key is not hashable.",
                        key.range(),
                        index,
                        source,
                    ));
                }
            }
        }
        _ => {}
    });
    issues
}

// --- migrated from support/mod.rs (S6662) ---
// --- python:S6662 — unhashable set members and dict keys ---------------------------

const UNHASHABLE_KINDS: [&str; 3] = ["list", "set", "dict"];
