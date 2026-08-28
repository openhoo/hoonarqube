use super::support::dispose_methods;
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, parameters_of, range_of,
};
use crate::rules::expressions::{callee_name, invocation_arguments, member_declarations_of_kind};
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
            .all(|method| parameters_of(*method).len() != 1);
        let parameterless_miswired = if let Some(dispose) = parameterless {
            let routes_through_bool =
                body_of(dispose).is_some_and(|body| calls_dispose_with_literal(body, source));
            !routes_through_bool
        } else {
            false
        };
        let finalizer_miswired = member_declarations_of_kind(type_node, "destructor_declaration")
            .into_iter()
            .any(|destructor| {
                !body_of(destructor).is_some_and(|body| calls_dispose_with_literal(body, source))
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

/// Whether the body invokes `Dispose` with a literal argument.
fn calls_dispose_with_literal(body: Node<'_>, source: &str) -> bool {
    collect_kinds(body, &["invocation_expression"])
        .into_iter()
        .any(|call| {
            callee_name(call, source) == Some("Dispose") && invocation_arguments(call).len() == 1
        })
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
}
