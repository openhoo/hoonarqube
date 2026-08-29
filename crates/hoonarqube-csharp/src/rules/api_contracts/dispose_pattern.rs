use super::support::dispose_methods;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, base_simple_names, collect_kinds, is_error_tainted, issue, node_text,
    parameters_of, range_of, simple_name,
};
use crate::rules::expressions::{
    callee_name, invocation_arguments, invocation_receiver, member_declarations_of_kind,
};
use crate::rules::literals::argument_expression;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::{body_of, name_anchor};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3881 — the full dispose pattern wires `Dispose`, a virtual
/// `Dispose(bool)`, and the finalizer together.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node)
            || !base_simple_names(type_node, source).contains(&"IDisposable")
        {
            continue;
        }
        let disposes = dispose_methods(type_node, source);
        let parameterless = disposes
            .iter()
            .copied()
            .find(|method| parameters_of(*method).is_empty());
        let missing_bool_overload = disposes
            .iter()
            .all(|method| !is_bool_dispose(*method, source));
        let parameterless_miswired = if let Some(dispose) = parameterless {
            let routes_through_bool =
                body_of(dispose).is_some_and(|body| calls_dispose_with_boolean(body, source, true));
            !routes_through_bool
        } else {
            false
        };
        let finalizer_miswired = member_declarations_of_kind(type_node, "destructor_declaration")
            .into_iter()
            .any(|destructor| {
                !body_of(destructor)
                    .is_some_and(|body| calls_dispose_with_boolean(body, source, false))
            });
        if missing_bool_overload || parameterless_miswired || finalizer_miswired {
            issues.push(issue(
                language,
                "S3881",
                "Fix this implementation of 'IDisposable' to conform to the dispose pattern.",
                range_of(name_anchor(type_node), source),
            ));
        }
    }
    issues
}

fn is_bool_dispose(method: Node<'_>, source: &str) -> bool {
    let parameters = parameters_of(method);
    parameters.len() == 1
        && parameters[0]
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                matches!(
                    simple_name(node_text(type_node, source)),
                    "bool" | "Boolean"
                )
            })
}

/// Whether the body directly invokes `Dispose(expected)` on the current
/// instance. Calls hidden in a local function or lambda do not wire the
/// enclosing dispose method.
fn calls_dispose_with_boolean(body: Node<'_>, source: &str, expected: bool) -> bool {
    collect_kinds(body, &["invocation_expression"])
        .into_iter()
        .any(|call| {
            if !belongs_to_body(call, body)
                || callee_name(call, source) != Some("Dispose")
                || invocation_receiver(call)
                    .is_some_and(|receiver| node_text(receiver, source) != "this")
            {
                return false;
            }
            let arguments = invocation_arguments(call);
            arguments.len() == 1
                && node_text(argument_expression(arguments[0]), source)
                    == if expected { "true" } else { "false" }
        })
}

fn belongs_to_body(node: Node<'_>, body: Node<'_>) -> bool {
    for ancestor in ancestors_of(node) {
        if ancestor.id() == body.id() {
            return true;
        }
        if matches!(
            ancestor.kind(),
            "local_function_statement" | "lambda_expression" | "anonymous_method_expression"
        ) {
            return false;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3881_bool_overload_without_parameterless_dispose_is_accepted() {
        let report = analyze_default(
            "class Weird : IDisposable\n{\n    protected virtual void Dispose(bool disposing) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3881").is_empty());
    }

    #[test]
    fn s3881_finalizer_skipping_dispose_flags_once() {
        let report = analyze_default(
            "class Bad : IDisposable\n{\n    public void Dispose() { Dispose(true); }\n    protected virtual void Dispose(bool disposing) { }\n    ~Bad() { done = true; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3881");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("IDisposable"));
    }

    #[test]
    fn s3881_requires_a_boolean_overload_and_exact_wiring_values() {
        let wrong_type = analyze_default(
            "class Bad : IDisposable\n{\n    public void Dispose() { Dispose(true); }\n    protected virtual void Dispose(int disposing) { }\n}\n",
        );
        assert_eq!(with_key(&wrong_type, "csharpsquid:S3881").len(), 1);

        let reversed = analyze_default(
            "class Bad : IDisposable\n{\n    public void Dispose() { Dispose(false); }\n    protected virtual void Dispose(bool disposing) { }\n    ~Bad() { Dispose(true); }\n}\n",
        );
        assert_eq!(with_key(&reversed, "csharpsquid:S3881").len(), 1);
    }

    #[test]
    fn s3881_ignores_dispose_calls_hidden_in_nested_callables() {
        let report = analyze_default(
            "class Bad : IDisposable\n{\n    public void Dispose()\n    {\n        void Later() { Dispose(true); }\n    }\n    protected virtual void Dispose(bool disposing) { }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3881").len(), 1);
    }
}
