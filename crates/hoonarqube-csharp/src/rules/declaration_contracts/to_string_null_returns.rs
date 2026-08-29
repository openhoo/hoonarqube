use super::support::owned_by_callable;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2225 — `ToString` returning null breaks formatting and
/// string interpolation.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method)
            || method
                .child_by_field_name("name")
                .is_none_or(|name| node_text(name, source) != "ToString")
            || !parameters_of(method).is_empty()
        {
            continue;
        }
        for candidate in collect_kinds(method, &["return_statement", "arrow_expression_clause"])
            .into_iter()
            .filter(|candidate| owned_by_callable(*candidate, method))
        {
            if first_named_child(candidate).is_some_and(|value| value.kind() == "null_literal") {
                issues.push(issue(
                    language,
                    "S2225",
                    "Return an empty string instead.",
                    range_of(candidate, source),
                ));
                break;
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2225_flags_arrow_bodied_null_returns() {
        let report =
            analyze_default("class C\n{\n    public override string ToString() => null;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S2225").len(), 1);
    }

    #[test]
    fn s2225_reports_only_the_first_null_return() {
        let report = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        if (Broken())\n        {\n            return null;\n        }\n        return null;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2225").len(), 1);
    }

    #[test]
    fn s2225_spares_empty_strings_and_other_members() {
        let empty = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        return \"\";\n    }\n}\n",
        );
        assert!(with_key(&empty, "csharpsquid:S2225").is_empty());

        let describe = analyze_default(
            "class C\n{\n    string Describe()\n    {\n        return null;\n    }\n}\n",
        );
        assert!(with_key(&describe, "csharpsquid:S2225").is_empty());
    }

    #[test]
    fn s2225_spares_overloads_and_nested_callable_returns() {
        let overload = analyze_default("class C\n{\n    string ToString(int radix) => null;\n}\n");
        assert!(with_key(&overload, "csharpsquid:S2225").is_empty());

        let nested = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        string Missing() => null;\n        System.Func<string> delayed = () => null;\n        return \"ok\";\n    }\n}\n",
        );
        assert!(with_key(&nested, "csharpsquid:S2225").is_empty());
    }
}
