use super::support::{call_argument_nodes, named_argument_value};
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::callee_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5659 — JWT.Net decoding must verify the token signature.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation)
            || callee_name(invocation, source) != Some("Decode")
            || !call_argument_nodes(invocation).into_iter().any(|argument| {
                named_argument_value(argument, source, "verify")
                    .is_some_and(|value| node_text(value, source) == "false")
            })
        {
            continue;
        }
        issues.push(issue(
            language,
            "S5659",
            "Use only strong cipher algorithms when verifying the signature of this JWT.",
            range_of(invocation, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5659_parses_named_verify_argument_without_spacing_assumptions() {
        let report = analyze_default(
            "class Auth { string Read(IJwtDecoder decoder, string token) => decoder.Decode(token, verify:false); }",
        );
        assert_eq!(with_key(&report, "csharpsquid:S5659").len(), 1);
    }

    #[test]
    fn s5659_other_false_named_arguments_do_not_disable_verification() {
        let report = analyze_default(
            "class Auth { string Read(IJwtDecoder decoder, string token) => decoder.Decode(token, verify:true, cache:false); }",
        );
        assert!(with_key(&report, "csharpsquid:S5659").is_empty());
    }
}
