use super::support::logging_calls;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::invocation_arguments;
use crate::rules::literals::{argument_expression, is_string_literal};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2629 — interpolated or computed templates defeat structured
/// logging; only constant templates can be parsed by log backends.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    logging_calls(root, source)
        .into_iter()
        .filter_map(|call| {
            invocation_arguments(call)
                .first()
                .copied()
                .map(|first| (call, argument_expression(first)))
        })
        .filter(|(_, expression)| !is_string_literal(*expression))
        .map(|(_, expression)| {
            let message = if expression.kind() == "interpolated_string_expression" {
                "Don't use string interpolation in logging message templates."
            } else {
                "Don't use string concatenation in logging message templates."
            };
            issue(language, "S2629", message, range_of(expression, source))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2629_accepts_verbatim_and_raw_static_templates() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        logger.LogInformation(@\"Value {Value}\", value);\n        logger.LogInformation(\"\"\"Value {Value}\"\"\", value);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2629").is_empty());
    }
}
