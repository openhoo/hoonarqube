use super::support::parameter_default_value;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::expressions::{invocation_arguments, invocation_function};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3466 — calls into `base.` members that repeat an optional
/// parameter of the enclosing member purely to hand back its default.
/// Subset: textual `base.` receivers and identifier arguments matching a
/// defaulted parameter name of the enclosing callable.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            invocation_function(*call)
                .is_some_and(|function| node_text(function, source).trim().starts_with("base."))
        })
        .filter_map(|call| {
            let enclosing = enclosing_method(call)?;
            let defaulted: std::collections::HashSet<&str> = parameters_of(enclosing)
                .into_iter()
                .filter(|parameter| parameter_default_value(*parameter).is_some())
                .filter_map(|parameter| parameter.child_by_field_name("name"))
                .map(|name| node_text(name, source))
                .collect();
            (!defaulted.is_empty()).then_some((call, defaulted))
        })
        .filter(|(call, defaulted)| {
            invocation_arguments(*call).into_iter().any(|argument| {
                let expression = argument_expression(argument);
                expression.kind() == "identifier"
                    && defaulted.contains(node_text(expression, source))
            })
        })
        .map(|(call, _)| {
            issue(
                language,
                "S3466",
                "Omit this argument; the base declaration already makes it optional.",
                range_of(call),
            )
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3466_enclosing_callable_without_defaults_never_flags() {
        let report = analyze_default(
            "class Sub\n{\n    public void Go(int count)\n    {\n        base.Save(count);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3466").is_empty());
    }

    #[test]
    fn s3466_argument_not_among_the_defaults_stays_silent() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Save(int retries = 3) { }\n}\nclass Sub : Base\n{\n    public void Retry(int retries = 3)\n    {\n        int burst = 5;\n        base.Save(burst);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3466").is_empty());
    }

    #[test]
    fn s3466_argument_lookup_against_defaults_is_case_sensitive() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Save(int count = 3) { }\n}\nclass Sub : Base\n{\n    public void Retry(int Retries = 3)\n    {\n        base.Save(retries);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3466").is_empty());
    }

    #[test]
    fn s3466_non_base_receivers_are_ignored() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Save(int retries = 3) { }\n}\nclass Sub : Base\n{\n    public void Retry(int retries = 3)\n    {\n        this.Save(retries);\n        Save(retries);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3466").is_empty());
    }

    #[test]
    fn s3466_reports_each_forwarding_call_at_its_own_line() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Save(int retries = 3) { }\n}\nclass Sub : Base\n{\n    public void Retry(int retries = 3)\n    {\n        base.Save(retries);\n        base.Save(retries);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3466");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 9);
        assert_eq!(flagged[1].range.start.line, 10);
    }

    #[test]
    fn s3466_lambda_wrapped_call_still_pairs_with_method_defaults() {
        let report = analyze_default(
            "class Base\n{\n    public virtual void Save(int retries = 3) { }\n}\nclass Sub : Base\n{\n    public void Retry(int retries = 3)\n    {\n        System.Action defer = () => base.Save(retries);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3466");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);
    }
}
