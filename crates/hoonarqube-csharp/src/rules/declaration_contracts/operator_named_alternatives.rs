use super::support::operator_declaration_for;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{declared_method_names, overloaded_operators};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4069 — operator overloads deserve named method equivalents.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let names = declared_method_names(type_node, source);
        for token in overloaded_operators(type_node) {
            let alternative = match OPERATOR_ALTERNATIVES
                .iter()
                .find(|(operator, _)| *operator == token)
            {
                Some((_, method)) => Some(*method),
                None => matches!(token, "<" | "<=" | ">" | ">=").then_some("CompareTo"),
            };
            if let Some(alternative) = alternative
                && !names.contains(alternative)
                && let Some(declaration) = operator_declaration_for(type_node, token)
            {
                issues.push(issue(
                    language,
                    "S4069",
                    format!("Provide a named '{alternative}' method alongside this operator."),
                    range_of(declaration),
                ));
            }
        }
    }
    issues
}

/// Named methods that serve as operator alternatives.
const OPERATOR_ALTERNATIVES: [(&str, &str); 4] = [
    ("+", "Add"),
    ("-", "Subtract"),
    ("*", "Multiply"),
    ("/", "Divide"),
];
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4069_requires_compareto_for_relational_operators() {
        let missing = analyze_default(
            "struct Range\n{\n    public static bool operator <(Range a, Range b) => true;\n}\n",
        );
        assert_eq!(with_key(&missing, "csharpsquid:S4069").len(), 1);

        let provided = analyze_default(
            "struct Range\n{\n    public static bool operator <(Range a, Range b) => true;\n\n    public int CompareTo(Range other) => 0;\n}\n",
        );
        assert!(with_key(&provided, "csharpsquid:S4069").is_empty());
    }

    #[test]
    fn s4069_matches_exact_alternative_names_per_operator() {
        let both = analyze_default(
            "struct Money\n{\n    public static Money operator +(Money a, Money b) => a;\n\n    public static Money operator -(Money a, Money b) => a;\n}\n",
        );
        assert_eq!(with_key(&both, "csharpsquid:S4069").len(), 2);

        let partial = analyze_default(
            "struct Money\n{\n    public static Money operator -(Money a, Money b) => a;\n\n    public static Money Add(Money a, Money b) => a;\n}\n",
        );
        assert_eq!(with_key(&partial, "csharpsquid:S4069").len(), 1);

        let equality = analyze_default(
            "class Ref\n{\n    public static bool operator ==(Ref a, Ref b) => true;\n}\n",
        );
        assert!(with_key(&equality, "csharpsquid:S4069").is_empty());
    }
}
