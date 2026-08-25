use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::is_false_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_weak_hashing(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let Some(path) = dotted_name(&call.func) else {
            return;
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
            issues.push(issue_at(
                "python:S4790",
                "Remove this usage of a weak hashing algorithm.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S4790) ---
// --- python:S4790 — weak hashing algorithms -----------------------------------

fn hash_call_is_exempt(call: &ruff_python_ast::ExprCall) -> bool {
    keyword_value(&call.arguments, "usedforsecurity").is_some_and(is_false_literal)
}
