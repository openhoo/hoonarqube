use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    binary_operands, callee_name, invocation_function, invocation_receiver, operator_of,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1155 — emptiness is what `Any()` expresses.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let zero = |operand: Node<'_>| {
            operand.kind() == "integer_literal" && node_text(operand, source) == "0"
        };
        let count = match operator {
            "==" | "<=" if is_count_expression(left, source) && zero(right) => Some(left),
            "==" | ">=" if zero(left) && is_count_expression(right, source) => Some(right),
            _ => None,
        };
        if let Some(count) = count {
            let anchor = invocation_function(count)
                .and_then(|function| function.child_by_field_name("name"))
                .unwrap_or(count);
            let collection_type = invocation_receiver(count)
                .filter(|receiver| receiver.kind() == "identifier")
                .and_then(|receiver| declared_type(root, node_text(receiver, source), source))
                .unwrap_or("IEnumerable");
            issues.push(issue(
                language,
                "S1155",
                format!("Use '.Any()' to test whether this '{collection_type}' is empty or not."),
                range_of(anchor, source),
            ));
        }
    }
    issues
}

fn declared_type<'a>(root: Node<'_>, name: &str, source: &'a str) -> Option<&'a str> {
    for declaration in collect_kinds(root, &["parameter", "variable_declaration"]) {
        let matches_name = if declaration.kind() == "parameter" {
            declaration
                .child_by_field_name("name")
                .is_some_and(|candidate| node_text(candidate, source) == name)
        } else {
            collect_kinds(declaration, &["variable_declarator"])
                .iter()
                .any(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .is_some_and(|candidate| node_text(candidate, source) == name)
                })
        };
        if matches_name && let Some(type_node) = declaration.child_by_field_name("type") {
            return node_text(type_node, source).rsplit('.').next();
        }
    }
    None
}

/// Whether the operand invokes the LINQ `Count()` method. The reference
/// only reports when `Count` resolves to an extension method on
/// `IEnumerable<T>`/`IQueryable`; a `.Count` property access is
/// constant-time (`List<T>`, arrays, `ICollection<T>`) and never matches.
fn is_count_expression(operand: Node<'_>, source: &str) -> bool {
    operand.kind() == "invocation_expression" && callee_name(operand, source) == Some("Count")
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1155_flags_only_comparisons_equivalent_to_empty() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        if (items.Count() <= 0) return;\n        if (0 >= items.Count()) return;\n        if (0 <= items.Count()) return;\n        if (items.Count() >= 0) return;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1155");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5); // document line 4
        assert_eq!(flagged[1].range.start.line, 6); // document line 5
    }

    #[test]
    fn s1155_keeps_nonzero_and_positive_comparisons_clean() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        if (items.Count() == 1) return;\n        if (items.Count >= 0) return;\n        if (items.Any()) return;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1155").is_empty());
    }

    #[test]
    fn s1155_keeps_constant_time_count_property_clean() {
        // `List<T>.Count`, `ICollection<T>.Count`, and array `.Length` are
        // O(1) property reads; the reference only reports the LINQ `Count()`
        // extension method, so property access is never flagged.
        let report = analyze_default(
            "using System.Collections.Generic;\n\
             public static class CountCheck\n{\n\
                 public static bool IsEmpty(List<string> values)\n\
                 {\n        return values.Count == 0;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1155").is_empty());

        let comparisons = analyze_default(
            "class A\n{\n    void M()\n    {\n        if (items.Count == 0) return;\n        if (items.Count > 0) return;\n        if (items.Count != 0) return;\n        if (0 == items.Count) return;\n        if (items.Length == 0) return;\n    }\n}\n",
        );
        assert!(with_key(&comparisons, "csharpsquid:S1155").is_empty());
    }

    #[test]
    fn s1155_still_flags_linq_count_invocations() {
        // The invocation form stays reportable even on `List<T>` receivers:
        // the reference flags the `Enumerable.Count()` extension call.
        let report = analyze_default(
            "using System.Collections.Generic;\n\
             class A\n{\n    bool M(List<string> values)\n    {\n        return values.Count() == 0;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1155");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 6);
    }
}
