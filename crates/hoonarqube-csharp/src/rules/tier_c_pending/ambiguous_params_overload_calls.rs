use super::support::local_method_table;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::tier_c::parameter_units;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3220 — calls resolving ambiguously to a `params` overload.
/// File-local overload approximation: a call reaching a `params` candidate
/// while a non-`params` overload has the same written arity.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let methods = local_method_table(root, source);
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            let Some(candidates) = callee_name(*call, source).and_then(|name| methods.get(name))
            else {
                return false;
            };
            let argument_count = invocation_arguments(*call).len();
            let has_params = candidates.iter().any(|method| {
                let units = parameter_units(*method, source);
                units.iter().any(|unit| unit.has_params) && argument_count > units.len()
            });
            let plain_candidate = candidates.iter().find(|method| {
                let parameters = parameters_of(**method);
                parameters.len() == argument_count
                    && !parameter_units(**method, source)
                        .iter()
                        .any(|unit| unit.has_params)
            });
            has_params && plain_candidate.is_some()
        })
        .map(|call| {
            let candidates = callee_name(call, source)
                .and_then(|name| methods.get(name))
                .expect("filtered calls retain candidates");
            let argument_count = invocation_arguments(call).len();
            let plain = candidates
                .iter()
                .find(|method| {
                    parameters_of(**method).len() == argument_count
                        && !parameter_units(**method, source)
                            .iter()
                            .any(|unit| unit.has_params)
                })
                .expect("filtered calls retain a plain candidate");
            issue(
                language,
                "S3220",
                format!(
                    "Review this call, which partially matches an overload without 'params'. The partial match is '{}'.",
                    method_signature(*plain, source)
                ),
                range_of(call, source),
            )
        })
        .collect()
}

fn method_signature(method: Node<'_>, source: &str) -> String {
    let return_type = method
        .child_by_field_name("returns")
        .or_else(|| method.child_by_field_name("type"))
        .map_or("void", |node| node_text(node, source));
    let owner = enclosing_type(method)
        .and_then(|node| node.child_by_field_name("name"))
        .map_or("", |node| node_text(node, source));
    let name = method
        .child_by_field_name("name")
        .map_or("", |node| node_text(node, source));
    let parameters = method
        .child_by_field_name("parameters")
        .map_or("()", |node| node_text(node, source));
    format!("{return_type} {owner}.{name}{parameters}")
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3220_explicit_array_binding_to_plain_overload_is_clean() {
        let report = analyze_default(
            "class Writer\n{\n    public void Write(string[] lines)\n    {\n    }\n    public void Write(params string[] lines)\n    {\n    }\n    public void Flush()\n    {\n        Write(new[] { \"a\" });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3220").is_empty());
    }

    #[test]
    fn s3220_missing_plain_array_overload_stays_clean() {
        let report = analyze_default(
            "class Writer\n{\n    public void Write(params string[] lines)\n    {\n    }\n    public void Flush()\n    {\n        Write(new[] { \"a\" });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3220").is_empty());
    }

    #[test]
    fn s3220_non_array_plain_overload_stays_clean() {
        let report = analyze_default(
            "class Writer\n{\n    public void Write(string text)\n    {\n    }\n    public void Write(params string[] lines)\n    {\n    }\n    public void Flush()\n    {\n        Write(new[] { \"a\" });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3220").is_empty());
    }

    #[test]
    fn s3220_object_typed_plain_overload_wins_without_params_expansion() {
        let report = analyze_default(
            "class Writer\n{\n    public void Write(object item)\n    {\n    }\n    public void Write(params string[] lines)\n    {\n    }\n    public void Flush()\n    {\n        Write(new[] { \"a\" });\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3220").is_empty());
    }

    #[test]
    fn s3220_non_array_arguments_stay_clean() {
        let report = analyze_default(
            "class Writer\n{\n    public void Write(string[] lines)\n    {\n    }\n    public void Write(params string[] lines)\n    {\n    }\n    public void Flush(string[] buffer)\n    {\n        Write(buffer);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3220").is_empty());
    }

    #[test]
    fn s3220_flags_each_ambiguous_call_distinctly() {
        let report = analyze_default(
            "class Writer\n{\n    public void Write(string head, params object[] lines)\n    {\n    }\n    public void Write(object first, object second, object third)\n    {\n    }\n    public void Flush()\n    {\n        Write(\"\", null, null);\n        Write(\"x\", 1, 2);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3220");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 11);
        assert_eq!(flagged[1].range.start.line, 12);
    }
}
