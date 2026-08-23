use crate::support::for_each_call;
use crate::support::has_keyword;
use crate::support::is_call_method;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5659 — JWT signed and verified -------------------------------------

pub(crate) fn check_s5659_jwt_signing(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let unsigned = is_call_method(call, "encode")
            && keyword_value(&call.arguments, "algorithm")
                .and_then(string_literal_text)
                .is_some_and(|algorithm| algorithm == "none");
        let unverified =
            is_call_method(call, "decode") && !has_keyword(&call.arguments, "algorithms");
        if unsigned || unverified {
            issues.push(issue_at(
                "python:S5659",
                "Sign this JWT with a strong algorithm and verify it on decode.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
