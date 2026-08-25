use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6662_unhashable_collection_literals(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let unhashable =
        |expr: &Expr| literal_kind(expr).is_some_and(|kind| UNHASHABLE_KINDS.contains(&kind));
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        match expr {
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
        }
    }
    issues
}

// --- python:S6662 — unhashable set members and dict keys ---------------------------

const UNHASHABLE_KINDS: [&str; 3] = ["list", "set", "dict"];
