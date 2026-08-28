use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4039 — explicit interface implementations on inheritable
/// classes cannot be called by derived types.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class in collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| !is_error_tainted(*class))
        .filter(|class| !has_modifier(&modifiers_of(*class, source), "sealed"))
    {
        let Some(class_name) = class.child_by_field_name("name") else {
            continue;
        };
        for method in member_declarations_of_kind(class, "method_declaration") {
            let Some(specifier) = collect_kinds(method, &["explicit_interface_specifier"])
                .into_iter()
                .next()
            else {
                continue;
            };
            let Some(method_name) = method.child_by_field_name("name") else {
                continue;
            };
            let interface_name = node_text(specifier, source).trim_end_matches('.');
            issues.push(issue(
                language,
                "S4039",
                format!(
                    "Make '{}' sealed, change to a non-explicit declaration or provide a new method exposing the functionality of '{}.{}'.",
                    node_text(class_name, source),
                    interface_name,
                    node_text(method_name, source)
                ),
                range_of(method_name, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4039_explicit_implementation_flags_regardless_of_calls() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        this.Greet();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4039");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s4039_derived_declaration_does_not_hide_base_problem() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Greet()\n    {\n    }\n    public void Run()\n    {\n        Greet();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4039").len(), 1);
    }

    #[test]
    fn s4039_implicitly_implemented_members_stay_clean() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    public void Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        Greet();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4039").is_empty());
    }

    #[test]
    fn s4039_other_receiver_shapes_do_not_change_declaration_finding() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run(BaseGreeter other)\n    {\n        other.Greet();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4039").len(), 1);
    }

    #[test]
    fn s4039_flags_each_explicit_only_member_distinctly() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n    void Wave();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n    void IGreeter.Wave()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        Greet();\n        Wave();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4039");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[1].range.start.line, 11);
    }
}
