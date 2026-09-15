use super::support::collect_in_callable;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::expressions::{binary_operands, operator_of};
use crate::rules::structure::{CALLABLE_BODY_OWNER_KINDS, body_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1226 — parameters and caught exceptions keep their initial
/// value only until something reads them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for callable in collect_kinds(root, &CALLABLE_BODY_OWNER_KINDS) {
        check_callable(callable, source, language, &mut issues);
    }
    for catch_clause in collect_kinds(root, &["catch_clause"]) {
        if let Some((assignment, name)) = catch_offender(catch_clause, source) {
            push_issue(&mut issues, assignment, name, source, language);
        }
    }
    issues
}

fn check_callable(callable: Node<'_>, source: &str, language: CsLanguage, issues: &mut Vec<Issue>) {
    if is_error_tainted(callable) {
        return;
    }
    let Some(body) = body_of(callable) else {
        return;
    };
    for name_node in parameter_name_nodes(callable) {
        check_parameter(name_node, body, source, language, issues);
    }
}

/// Name nodes of every parameter, covering both the grammar's `parameter`
/// nodes and the flattened `params T name` spelling the parser emits
/// directly under `parameter_list` (`params`, `array_type`, `identifier`
/// siblings without a `parameter` wrapper).
fn parameter_name_nodes<'t>(callable: Node<'t>) -> Vec<Node<'t>> {
    let mut names: Vec<Node<'t>> = parameters_of(callable)
        .iter()
        .filter_map(|parameter| parameter.child_by_field_name("name"))
        .collect();
    let Some(list) = callable.child_by_field_name("parameters") else {
        return names;
    };
    let mut cursor = list.walk();
    let children: Vec<Node<'t>> = list.children(&mut cursor).collect();
    for (index, child) in children.iter().enumerate() {
        if child.kind() != "params" || child.is_named() {
            continue;
        }
        let is_flattened_params = children
            .get(index + 1)
            .is_some_and(|ty| ty.kind() == "array_type")
            && children
                .get(index + 2)
                .is_some_and(|name| name.kind() == "identifier");
        if is_flattened_params {
            names.push(children[index + 2]);
        }
    }
    names
}

fn check_parameter(
    name_node: Node<'_>,
    body: Node<'_>,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<Issue>,
) {
    if is_error_tainted(name_node)
        || name_node
            .parent()
            .filter(|parent| parent.kind() == "parameter")
            .is_some_and(|parameter| {
                modifiers_of(parameter, source)
                    .iter()
                    .any(|modifier| matches!(*modifier, "ref" | "out" | "in"))
            })
    {
        return;
    }
    let name = node_text(name_node, source);
    if let Some(assignment) = ignored_initial_value(body, name, source) {
        push_issue(issues, assignment, name, source, language);
    }
}

fn push_issue(
    issues: &mut Vec<Issue>,
    assignment: Node<'_>,
    name: &str,
    source: &str,
    language: CsLanguage,
) {
    let left = binary_operands(assignment).map_or(assignment, |(left, _)| left);
    issues.push(issue(
        language,
        "S1226",
        format!("Introduce a new variable instead of reusing the parameter '{name}'."),
        range_of(left, source),
    ));
}

/// The assignment overwriting `variable` before any read within `scope`.
fn ignored_initial_value<'t>(scope: Node<'t>, variable: &str, source: &str) -> Option<Node<'t>> {
    let mut references: Vec<Node> = collect_in_callable(scope, "identifier")
        .into_iter()
        .filter(|candidate| {
            !is_error_tainted(*candidate) && node_text(*candidate, source) == variable
        })
        .collect();
    references.sort_by_key(|node| node.byte_range().start);
    let first = *references.first()?;
    let assignment = first
        .parent()
        .filter(|parent| parent.kind() == "assignment_expression")?;
    if operator_of(assignment) != Some("=") {
        return None;
    }
    let (left, right) = binary_operands(assignment)?;
    if left.id() != first.id()
        || collect_kinds(right, &["identifier"])
            .iter()
            .any(|identifier| node_text(*identifier, source) == variable)
    {
        return None;
    }
    Some(assignment)
}

/// `(assignment, variable)` overwriting a caught exception unread.
fn catch_offender<'a>(catch_clause: Node<'a>, source: &'a str) -> Option<(Node<'a>, &'a str)> {
    if is_error_tainted(catch_clause) {
        return None;
    }
    let declaration = collect_kinds(catch_clause, &["catch_declaration"])
        .into_iter()
        .next()?;
    let block = collect_kinds(catch_clause, &["block"]).into_iter().next()?;
    let name_node = declaration.child_by_field_name("name")?;
    let name = node_text(name_node, source);
    Some((ignored_initial_value(block, name, source)?, name))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1226_ignores_assignments_deferred_into_closures() {
        let report = analyze_default(
            "class C\n{\n    public void Run(int value)\n    {\n        System.Action later = () => value = 0;\n        System.Console.WriteLine(value);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1226").is_empty());
    }

    #[test]
    fn s1226_ignores_nested_local_function_rebinding() {
        let report = analyze_default(
            "class C\n{\n    public void Run(int value)\n    {\n        void Reset() { value = 0; }\n        System.Console.WriteLine(value);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1226").is_empty());
    }

    #[test]
    fn s1226_flags_params_parameter_overwritten_before_read() {
        let report = analyze_default(
            "class C\n{\n    public object Build(string where, object key, params object[] args)\n    {\n        if (key != null)\n        {\n            args = new object[] { key };\n        }\n        return Create(args);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1226");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s1226_ignores_params_parameter_read_before_write() {
        let report = analyze_default(
            "class C\n{\n    public object Build(object key, params object[] args)\n    {\n        var count = args.Length;\n        args = new object[] { key };\n        return Create(args, count);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1226").is_empty());
    }
}
