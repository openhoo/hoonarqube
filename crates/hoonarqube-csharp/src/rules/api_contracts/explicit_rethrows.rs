use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3445 — `throw ex;` restarts the stack trace at the catch.
pub(crate) fn check(source_root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(source_root, &["throw_statement"])
        .into_iter()
        .filter(|throw| !is_error_tainted(*throw))
        .filter(|throw| {
            first_named_child(*throw).is_some_and(|expression| expression.kind() == "identifier")
        })
        .map(|throw| {
            issue(
                language,
                "S3445",
                "Use a bare 'throw;' statement to rethrow.",
                range_of(throw),
            )
        })
        .collect()
}
