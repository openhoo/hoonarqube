use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{overloaded_operators, overridden_names};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4050 — a `==` overload must come with `!=` and an `Equals`
/// override or equality semantics fall apart.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let operators = overloaded_operators(type_node);
        let equality_present = operators.contains(&"==") || operators.contains(&"!=");
        let arithmetic_present = operators
            .iter()
            .any(|operator| matches!(*operator, "+" | "-" | "*" | "/" | "%"));
        if equality_present || arithmetic_present {
            let overridden = overridden_names(type_node, source);
            let mut missing = Vec::new();
            if !operators.contains(&"==") {
                missing.push("operator==");
            }
            if !operators.contains(&"!=") {
                missing.push("operator!=");
            }
            if !overridden.contains("Equals") {
                missing.push("Object.Equals");
            }
            if !overridden.contains("GetHashCode") {
                missing.push("Object.GetHashCode");
            }
            if missing.is_empty() {
                continue;
            }
            issues.push(issue(
                language,
                "S4050",
                format!("Provide an implementation for: {}.", quoted_list(&missing)),
                range_of(name_anchor(type_node), source),
            ));
        }
    }
    issues
}

fn quoted_list(items: &[&str]) -> String {
    let quoted: Vec<String> = items.iter().map(|item| format!("'{item}'")).collect();
    match quoted.as_slice() {
        [] => String::new(),
        [only] => only.clone(),
        [first, second] => format!("{first} and {second}"),
        _ => format!(
            "{} and {}",
            quoted[..quoted.len() - 1].join(", "),
            quoted.last().expect("non-empty list")
        ),
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4050_operator_pair_without_equals_override_still_flags() {
        let report = analyze_default(
            "struct Value\n{\n    public static bool operator ==(Value a, Value b) => true;\n\n    public static bool operator !=(Value a, Value b) => false;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4050").len(), 1);
    }

    #[test]
    fn s4050_inequality_alone_requires_its_pair_and_object_contract() {
        let report = analyze_default(
            "struct Value\n{\n    public static bool operator !=(Value a, Value b) => false;\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4050").len(), 1);
    }
}
