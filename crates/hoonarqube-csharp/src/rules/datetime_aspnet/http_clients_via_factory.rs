use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6962 — hand-rolled `HttpClient` instances rot sockets;
/// `IHttpClientFactory` pools them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| simple_name(creation_type_text(*creation, source)) == "HttpClient")
        .map(|creation| {
            issue(
                language,
                "S6962",
                "Create 'HttpClient' through 'IHttpClientFactory' instead.",
                range_of(creation, source),
            )
        })
        .collect()
}
