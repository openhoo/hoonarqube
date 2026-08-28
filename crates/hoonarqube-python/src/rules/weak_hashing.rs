use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_weak_hashing(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(path) = dotted_name(&call.func) else {
            continue;
        };
        let weak_direct = matches!(path.as_str(), "hashlib.md5" | "hashlib.sha1");
        let weak_named_new = path == "hashlib.new"
            && call
                .arguments
                .args
                .first()
                .and_then(string_literal_text)
                .is_some_and(|name| matches!(name.to_lowercase().as_str(), "md5" | "sha1" | "sha"));
        if (weak_direct || weak_named_new) && !hash_call_is_exempt(call) {
            let range = if weak_direct {
                match call.func.as_ref() {
                    Expr::Attribute(attribute) => attribute.attr.range,
                    _ => call.func.range(),
                }
            } else {
                call.arguments
                    .args
                    .first()
                    .map_or_else(|| call.func.range(), Ranged::range)
            };
            issues.push(issue_at(
                "python:S4790",
                "Make sure that hashing data is safe here.",
                range,
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S4790 — weak hashing algorithms -----------------------------------

fn hash_call_is_exempt(call: &ruff_python_ast::ExprCall) -> bool {
    keyword_value(&call.arguments, "usedforsecurity").is_some_and(is_false_literal)
}
