use super::support::mentions_identifier_outside_parameter_list;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1172 — parameters no body ever reads mislead callers.
/// Visible, virtual, abstract, partial, and extern callables keep their
/// signatures; discard names (`_`) are exempt by convention.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration", "constructor_declaration"])
        .into_iter()
        .filter(|callable| {
            !modifiers_of(*callable, source)
                .iter()
                .any(|modifier| SIGNATURE_KEEPING_MODIFIERS.contains(modifier))
        })
        .flat_map(|callable| {
            parameters_of(callable)
                .into_iter()
                .map(move |parameter| (callable, parameter))
        })
        .filter_map(|(callable, parameter)| {
            let name = parameter.child_by_field_name("name")?;
            let text = node_text(name, source);
            (text != "_").then_some((callable, parameter, text))
        })
        .filter(|(callable, _, name)| {
            !mentions_identifier_outside_parameter_list(*callable, name, source)
        })
        .map(|(_, parameter, name)| {
            issue(
                language,
                "S1172",
                format!("Remove this unused method parameter '{name}'."),
                range_of(parameter, source),
            )
        })
        .collect()
}

/// Modifiers whose callables keep their signatures regardless of usage.
const SIGNATURE_KEEPING_MODIFIERS: [&str; 8] = [
    "public",
    "protected",
    "internal",
    "virtual",
    "override",
    "abstract",
    "partial",
    "extern",
];
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1172_flags_unused_constructor_parameters() {
        let report =
            analyze_default("class C\n{\n    C(int missing)\n    {\n        Log();\n    }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S1172");
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("'missing'"));
    }

    #[test]
    fn s1172_keeps_every_signature_bearing_modifier() {
        let report = analyze_default(
            "class C\n{\n    internal static void Drain(int gone)\n    {\n    }\n\n    protected void Fill(int gone)\n    {\n    }\n\n    virtual int Mix(int gone)\n    {\n        return 0;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1172").is_empty());
    }

    #[test]
    fn s1172_reports_each_unused_parameter_separately() {
        let report = analyze_default(
            "class C\n{\n    void Handle(int first, string second, bool third)\n    {\n        Log(first);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1172").len(), 2);
    }

    #[test]
    fn s1172_disregards_prose_in_strings_and_comments() {
        let report = analyze_default(
            "class C\n{\n    void Handle(int value)\n    {\n        // value will matter soon\n        Log(\"value\");\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1172").len(), 1);
    }

    #[test]
    fn s1172_reads_expression_bodied_usage() {
        let report = analyze_default("class C\n{\n    int Double(int v) => v * 2;\n}\n");
        assert!(with_key(&report, "csharpsquid:S1172").is_empty());
    }

    #[test]
    fn s1172_skips_lambdas_and_anonymous_methods() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        System.Action<int> a = (int orphan) => Log();\n        System.Action<int> b = delegate(int leftover) { Log(); };\n        a(1);\n        b(2);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1172").is_empty());
    }
}
