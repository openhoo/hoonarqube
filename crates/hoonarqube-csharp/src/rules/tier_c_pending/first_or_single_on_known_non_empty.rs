use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, walk_all};
use crate::rules::dataflow::{WriteKind, callable_blocks, identifier_write};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S7130 — First/Single on collections proven non-empty.
/// Subset: same-callable proof in document order — the receiver identifier
/// was populated by `.Add`/`.AddRange`/`.Insert` or a non-empty collection
/// initializer and never reassigned or cleared before the call; other
/// receiver shapes and cross-method flow stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let trackable = trackable_local_names(body, source);
        let mut populated: std::collections::HashSet<String> = std::collections::HashSet::new();
        walk_all(body, &mut |node| {
            if belongs_to_body(node, body) {
                process_node(
                    node,
                    body,
                    source,
                    language,
                    &trackable,
                    &mut populated,
                    &mut issues,
                );
            }
        });
    }
    issues
}

fn process_node(
    node: Node<'_>,
    body: Node<'_>,
    source: &str,
    language: CsLanguage,
    trackable: &std::collections::HashSet<String>,
    populated: &mut std::collections::HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    match node.kind() {
        "invocation_expression" => {
            process_invocation(node, body, source, language, trackable, populated, issues);
        }
        "variable_declaration" => credit_initializers(node, body, source, trackable, populated),
        "identifier"
            if identifier_write(node) == Some(WriteKind::Store)
                && !credited_by_initializer(node) =>
        {
            populated.remove(node_text(node, source));
        }
        _ => {}
    }
}

fn process_invocation(
    call: Node<'_>,
    body: Node<'_>,
    source: &str,
    language: CsLanguage,
    trackable: &std::collections::HashSet<String>,
    populated: &mut std::collections::HashSet<String>,
    issues: &mut Vec<Issue>,
) {
    let Some(receiver) =
        invocation_receiver(call).filter(|receiver| receiver.kind() == "identifier")
    else {
        return;
    };
    let name = node_text(receiver, source);
    if !trackable.contains(name) {
        return;
    }
    match callee_name(call, source) {
        Some("Add" | "Insert") if is_definitely_executed(call, body) => {
            populated.insert(name.to_owned());
        }
        Some("AddRange")
            if is_definitely_executed(call, body) && add_range_is_definitely_non_empty(call) =>
        {
            populated.insert(name.to_owned());
        }
        Some("Clear") => {
            populated.remove(name);
        }
        Some("FirstOrDefault" | "SingleOrDefault") if populated.contains(name) => {
            issues.push(issue(
                language,
                "S7130",
                "Use 'First' or 'Single' here; this collection is known to be non-empty.",
                range_of(call, source),
            ));
        }
        _ => {}
    }
}

fn credit_initializers(
    declaration: Node<'_>,
    body: Node<'_>,
    source: &str,
    trackable: &std::collections::HashSet<String>,
    populated: &mut std::collections::HashSet<String>,
) {
    if !is_definitely_executed(declaration, body) {
        return;
    }
    for declarator in collect_kinds(declaration, &["variable_declarator"]) {
        if has_non_empty_initializer(declarator)
            && let Some(name) = declarator.child_by_field_name("name")
            && trackable.contains(node_text(name, source))
        {
            populated.insert(node_text(name, source).to_owned());
        }
    }
}

fn credited_by_initializer(identifier: Node<'_>) -> bool {
    identifier
        .parent()
        .filter(|parent| parent.kind() == "variable_declarator")
        .is_some_and(has_non_empty_initializer)
}

fn has_non_empty_initializer(declarator: Node<'_>) -> bool {
    collect_kinds(declarator, &["initializer_expression"])
        .into_iter()
        .next()
        .is_some_and(initializer_has_definite_element)
}

fn initializer_has_definite_element(initializer: Node<'_>) -> bool {
    initializer
        .children(&mut initializer.walk())
        .any(|child| child.is_named() && child.kind() != "assignment_expression")
}

fn add_range_is_definitely_non_empty(call: Node<'_>) -> bool {
    invocation_arguments(call)
        .first()
        .and_then(|argument| {
            collect_kinds(*argument, &["initializer_expression"])
                .into_iter()
                .next()
        })
        .is_some_and(initializer_has_definite_element)
}

/// Locals with one declaration in this callable. Ambiguous same-name locals
/// are skipped because a flat name set cannot model nested lexical shadowing.
fn trackable_local_names(body: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for declarator in collect_kinds(body, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| belongs_to_body(*declarator, body))
    {
        if let Some(name) = declarator.child_by_field_name("name") {
            *counts
                .entry(node_text(name, source).to_owned())
                .or_default() += 1;
        }
    }
    counts
        .into_iter()
        .filter_map(|(name, count)| (count == 1).then_some(name))
        .collect()
}

/// Excludes nested local functions, closures, and types from the enclosing
/// callable's state. Their bodies execute independently, if at all.
fn belongs_to_body(node: Node<'_>, body: Node<'_>) -> bool {
    const BOUNDARIES: [&str; 12] = [
        "lambda_expression",
        "anonymous_method_expression",
        "local_function_statement",
        "method_declaration",
        "constructor_declaration",
        "destructor_declaration",
        "operator_declaration",
        "accessor_declaration",
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "interface_declaration",
    ];
    let mut current = Some(node);
    while let Some(candidate) = current {
        if candidate.id() == body.id() {
            return true;
        }
        if candidate.id() != node.id() && BOUNDARIES.contains(&candidate.kind()) {
            return false;
        }
        current = candidate.parent();
    }
    false
}

/// Population inside a branch or loop is not proof that execution reaches
/// the later query with an element present.
fn is_definitely_executed(node: Node<'_>, body: Node<'_>) -> bool {
    const CONDITIONAL_ANCESTORS: [&str; 11] = [
        "if_statement",
        "switch_statement",
        "switch_expression",
        "for_statement",
        "foreach_statement",
        "while_statement",
        "do_statement",
        "try_statement",
        "catch_clause",
        "finally_clause",
        "conditional_expression",
    ];
    let mut current = node.parent();
    while let Some(ancestor) = current {
        if ancestor.id() == body.id() {
            return true;
        }
        if CONDITIONAL_ANCESTORS.contains(&ancestor.kind()) {
            return false;
        }
        current = ancestor.parent();
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s7130_single_or_default_is_flagged_too() {
        let report = analyze_default(
            "void Register()\n{\n    var ids = new List<int>();\n    ids.Add(1);\n    var only = ids.SingleOrDefault();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S7130");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s7130_clear_and_reassignment_displace_the_proof() {
        let report = analyze_default(
            "void Register()\n{\n    var ids = new List<int>();\n    ids.Add(1);\n    ids.Clear();\n    ids = new List<int>();\n    var first = ids.FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }

    #[test]
    fn s7130_non_empty_collection_initializers_populate() {
        let report = analyze_default(
            "void A()\n{\n    var ids = new List<int> { 1 };\n    var first = ids.FirstOrDefault();\n}\nvoid B()\n{\n    var ids = new List<int> { };\n    var first = ids.FirstOrDefault();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S7130");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s7130_add_range_and_insert_also_prove_non_emptiness() {
        let report = analyze_default(
            "void A()\n{\n    var ids = new List<int>();\n    ids.AddRange(new[] { 1 });\n    var first = ids.FirstOrDefault();\n}\nvoid B()\n{\n    var ids = new List<int>();\n    ids.Insert(0, 2);\n    var first = ids.FirstOrDefault();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S7130");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 11);
    }

    #[test]
    fn s7130_conditional_and_deferred_mutations_are_not_proof() {
        let report = analyze_default(
            "void A(bool add)\n{\n    var ids = new List<int>();\n    if (add) ids.Add(1);\n    var first = ids.FirstOrDefault();\n}\nvoid B()\n{\n    var ids = new List<int>();\n    Action fill = () => ids.Add(1);\n    var first = ids.FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }

    #[test]
    fn s7130_unknown_or_empty_add_range_is_not_proof() {
        let report = analyze_default(
            "void A(IEnumerable<int> values)\n{\n    var ids = new List<int>();\n    ids.AddRange(values);\n    var first = ids.FirstOrDefault();\n}\nvoid B()\n{\n    var ids = new List<int>();\n    ids.AddRange(new int[] { });\n    var first = ids.FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }

    #[test]
    fn s7130_nested_shadowing_does_not_leak_population() {
        let report = analyze_default(
            "void A()\n{\n    {\n        var ids = new List<int> { 1 };\n    }\n    {\n        var ids = new List<int>();\n        var first = ids.FirstOrDefault();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }

    #[test]
    fn s7130_other_receiver_shapes_and_unpopulated_locals_stay_clean() {
        let report = analyze_default(
            "void Run()\n{\n    var ids = GetIds();\n    var first = ids.FirstOrDefault();\n    var other = Load().FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }

    #[test]
    fn s7130_population_does_not_cross_callables() {
        let report = analyze_default(
            "void Fill()\n{\n    var ids = new List<int>();\n    ids.Add(1);\n}\nvoid Use()\n{\n    var ids = new List<int>();\n    var first = ids.FirstOrDefault();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S7130").is_empty());
    }
}
