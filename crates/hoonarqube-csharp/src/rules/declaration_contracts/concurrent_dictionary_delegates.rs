use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    callee_name, invocation_arguments, lambda_shape, references_identifier,
};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6612 — factory lambdas should use the key passed by
/// `ConcurrentDictionary` instead of capturing the call-site key.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            matches!(
                callee_name(*invocation, source),
                Some("GetOrAdd" | "AddOrUpdate")
            )
        })
    {
        let arguments = invocation_arguments(invocation);
        let Some(key_argument) = arguments.first().copied() else {
            continue;
        };
        let key_expression = argument_expression(key_argument);
        if key_expression.kind() != "identifier" {
            continue;
        }
        let captured_key = node_text(key_expression, source);
        for argument in arguments.into_iter().skip(1) {
            let expression = argument_expression(argument);
            let Some((lambda_parameter, body)) = lambda_shape(expression, source) else {
                continue;
            };
            if lambda_parameter != captured_key && references_identifier(body, captured_key, source)
            {
                issues.push(issue(
                    language,
                    "S6612",
                    format!(
                        "Use the lambda parameter instead of capturing the argument '{captured_key}'"
                    ),
                    range_of(expression, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6612_flags_captured_call_site_key() {
        let report = analyze_default(
            "int M(ConcurrentDictionary<int, int> map, int key) => map.GetOrAdd(key, _ => key + 1);",
        );
        let found = with_key(&report, "csharpsquid:S6612");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].message,
            "Use the lambda parameter instead of capturing the argument 'key'"
        );

        let clean = analyze_default(
            "int M(ConcurrentDictionary<int, int> map, int key) => map.GetOrAdd(key, current => current + 1);",
        );
        assert!(with_key(&clean, "csharpsquid:S6612").is_empty());
    }
}
