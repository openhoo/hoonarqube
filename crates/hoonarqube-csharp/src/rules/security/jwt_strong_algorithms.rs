use crate::CsLanguage;
use crate::cst::{ancestors_of, is_error_tainted, issue, node_text, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5659 — JWTs signed or accepted with 'none'/weak HMAC
/// algorithms can be forged by anyone.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const WEAK_JWT_ALGORITHMS: [&str; 4] = ["none", "HS256", "HS384", "HS512"];
    let jwt_context_tokens = ["Jwt", "TokenValidation", "SigningCredentials"];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let algorithm = literal_inner_text(literal, source);
        if !WEAK_JWT_ALGORITHMS.contains(&algorithm) {
            continue;
        }
        let call_context = ancestors_of(literal).find(|ancestor| {
            matches!(
                ancestor.kind(),
                "invocation_expression" | "object_creation_expression"
            )
        });
        let jwt_context = call_context.is_some_and(|call| {
            let text = node_text(call, source);
            jwt_context_tokens.iter().any(|token| text.contains(token))
        });
        if jwt_context {
            issues.push(issue(
                language,
                "S5659",
                "Sign and verify JWTs with a strong algorithm such as 'RS256'.",
                range_of(literal, source),
            ));
        }
    }
    issues
}
