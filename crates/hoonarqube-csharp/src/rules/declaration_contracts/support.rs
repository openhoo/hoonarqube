use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::expressions::{
    first_named_child, member_declarations_of_kind, overloaded_operator,
};
use crate::rules::literals::{literal_inner_text, string_literals};
use crate::rules::structure::CALLABLE_BODY_OWNER_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Every attribute application in the file as `(simple name, argument list,
/// attribute node)`, assembly-level ones included.
pub(crate) fn attribute_applications<'t, 's>(
    root: Node<'t>,
    source: &'s str,
) -> Vec<(&'s str, Option<Node<'t>>, Node<'t>)> {
    collect_kinds(root, &["attribute"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter_map(|node| {
            let mut cursor = node.walk();
            let named: Vec<Node> = node
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect();
            let name = first_named_child(node).map(|name| simple_name(node_text(name, source)))?;
            Some((name, named.get(1).copied(), node))
        })
        .collect()
}

/// Attribute nodes applying any of `names` (exact match over both the short
/// and the `XAttribute` long form).
pub(crate) fn tracked_attribute_nodes<'t>(
    root: Node<'t>,
    source: &str,
    names: &[&str],
) -> Vec<Node<'t>> {
    attribute_applications(root, source)
        .into_iter()
        .filter(|(name, _, _)| names.contains(name))
        .map(|(_, _, node)| node)
        .collect()
}

/// One tracking issue per application of `names`, anchored on the attribute
/// node.
pub(crate) fn tracked_attribute_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    names: &[&str],
    rule: &str,
    message: &str,
) -> Vec<Issue> {
    tracked_attribute_nodes(root, source, names)
        .into_iter()
        .map(|node| issue(language, rule, message, range_of(node, source)))
        .collect()
}

/// The `operator_declaration` overloading `token`, if any.
pub(crate) fn operator_declaration_for<'t>(type_node: Node<'t>, token: &str) -> Option<Node<'t>> {
    member_declarations_of_kind(type_node, "operator_declaration")
        .into_iter()
        .find(|declaration| overloaded_operator(*declaration) == Some(token))
}

/// The nearest enclosing method declaration, if any.
pub(crate) fn enclosing_method(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| ancestor.kind() == "method_declaration")
}

/// Whether `node` belongs to `callable`, excluding nested callable and closure
/// bodies with independent execution contracts.
pub(crate) fn owned_by_callable(node: Node<'_>, callable: Node<'_>) -> bool {
    for ancestor in ancestors_of(node) {
        if ancestor.id() == callable.id() {
            return true;
        }
        if CALLABLE_BODY_OWNER_KINDS.contains(&ancestor.kind())
            || matches!(
                ancestor.kind(),
                "lambda_expression" | "anonymous_method_expression"
            )
        {
            return false;
        }
    }
    false
}

/// Whether an attribute argument carries a non-empty, non-null reason.
/// Constant expressions without an inline string remain accepted because
/// resolving their compile-time value requires semantic information.
pub(crate) fn nonempty_attribute_argument(argument: Node<'_>, source: &str) -> bool {
    let literals = string_literals(argument);
    if !literals.is_empty() {
        return literals
            .into_iter()
            .any(|literal| !literal_inner_text(literal, source).trim().is_empty());
    }
    collect_kinds(argument, &["null_literal"]).is_empty()
}

/// Whether the first positional attribute argument supplies an explanation.
pub(crate) fn has_attribute_explanation(arguments: Option<Node<'_>>, source: &str) -> bool {
    arguments
        .and_then(|arguments| {
            collect_kinds(arguments, &["attribute_argument"])
                .into_iter()
                .next()
        })
        .is_some_and(|argument| nonempty_attribute_argument(argument, source))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn qualified_attribute_names_are_normalized_for_contract_rules() {
        let report = analyze_default(
            "[System.Obsolete]\nclass Legacy\n{\n}\n\n[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]\nclass Generated\n{\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1123").len(), 1);
        assert_eq!(with_key(&report, "csharpsquid:S6513").len(), 1);
    }
}
