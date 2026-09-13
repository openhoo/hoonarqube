use crate::CsLanguage;
use crate::cst::{
    ancestors_of, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of,
    range_of,
};
use crate::rules::modifiers::has_any_accessibility;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::usage::support::mentions_identifier_outside_parameter_list;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1172 — parameters no body ever reads mislead callers.
/// Visible, virtual, abstract, partial, and extern callables keep their
/// signatures; interface methods are pure contract declarations, so their
/// parameters are never candidates; discard names (`_`) are exempt by
/// convention.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration", "constructor_declaration"])
        .into_iter()
        .filter(|callable| !is_error_tainted(*callable))
        .filter(|callable| {
            !modifiers_of(*callable, source)
                .iter()
                .any(|modifier| SIGNATURE_KEEPING_MODIFIERS.contains(modifier))
        })
        .filter(|callable| !interface_signature_without_accessibility(callable, source))
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

/// Interface methods without an explicit accessibility modifier are
/// implicitly public contract; implementers must keep their signatures
/// regardless of any body read.
fn interface_signature_without_accessibility(callable: &Node<'_>, source: &str) -> bool {
    !has_any_accessibility(&modifiers_of(*callable, source))
        && ancestors_of(*callable)
            .find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
            .is_some_and(|owner| owner.kind() == "interface_declaration")
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

    #[test]
    fn s1172_does_not_treat_named_argument_labels_as_reads() {
        let report = analyze_default(
            "class C\n{\n    void M(int value)\n    {\n        Other(value: 1);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1172").len(), 1);
    }

    #[test]
    fn s1172_does_not_treat_member_names_as_parameter_reads() {
        let report = analyze_default(
            "class C\n{\n    int value;\n    void M(int value)\n    {\n        this.value = 1;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1172").len(), 1);
    }

    #[test]
    fn s1172_interface_contract_parameters_are_not_unused() {
        // Issue #244: Dapper ICustomQueryParameter.AddParameter — interface
        // declarations have no implementation body reading the parameters.
        let interface = analyze_default(
            "public interface ICustomQueryParameter\n{\n\
                 void AddParameter(System.Data.IDbCommand command, string name);\n\
             }\n",
        );
        assert!(with_key(&interface, "csharpsquid:S1172").is_empty());

        // Control: an unused parameter of a private concrete method still
        // reports.
        let concrete = analyze_default(
            "class C\n{\n    void Handle(int value)\n    {\n        Log();\n    }\n}\n",
        );
        assert_eq!(with_key(&concrete, "csharpsquid:S1172").len(), 1);
    }
}
