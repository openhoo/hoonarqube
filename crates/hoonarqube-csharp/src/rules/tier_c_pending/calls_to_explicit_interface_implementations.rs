use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    enclosing_type, expression_name, first_named_child, invocation_function,
    member_declarations_of_kind,
};
use crate::rules::tier_c::{graph_reaches, local_inheritance_graph};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4039 — calls to members that only exist as explicit
/// interface implementations on a file-local base. Subset: bare invocations
/// inside a file-local derived class whose base chain declares the member
/// only explicitly and which does not declare the member itself;
/// `this.`-qualified calls, nested types, and cross-file bases stay
/// uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let explicit: std::collections::HashMap<&str, std::collections::HashSet<&str>> =
        collect_kinds(root, &["class_declaration"])
            .into_iter()
            .filter_map(|class| {
                let names: std::collections::HashSet<&str> =
                    member_declarations_of_kind(class, "method_declaration")
                        .into_iter()
                        .filter(|method| {
                            collect_kinds(*method, &["explicit_interface_specifier"]).len() == 1
                        })
                        .filter_map(|method| method.child_by_field_name("name"))
                        .map(|name| node_text(name, source))
                        .collect();
                let class_name = class.child_by_field_name("name")?;
                (!names.is_empty()).then_some((node_text(class_name, source), names))
            })
            .collect();
    if explicit.is_empty() {
        return Vec::new();
    }
    let graph = local_inheritance_graph(root, source);
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter_map(|call| {
            let function = invocation_function(call)?;
            let member = match function.kind() {
                "identifier" => Some(node_text(function, source)),
                "member_access_expression" => {
                    let object = first_named_child(function)?;
                    if object.kind() == "this_expression" {
                        expression_name(function, source)
                    } else {
                        None
                    }
                }
                _ => None,
            }?;
            let enclosing = enclosing_type(call)?;
            let class_name = node_text(enclosing.child_by_field_name("name")?, source);
            if member_declarations_of_kind(enclosing, "method_declaration")
                .into_iter()
                .any(|method| {
                    method
                        .child_by_field_name("name")
                        .is_some_and(|name| node_text(name, source) == member)
                })
            {
                return None;
            }
            base_explicitly_implements(&graph, &explicit, class_name, member).then_some(call)
        })
        .map(|call| {
            issue(
                language,
                "S4039",
                "Derived types cannot call this explicit interface implementation; make it protected or implement the interface implicitly.",
                range_of(call, source),
            )
        })
        .collect()
}

/// Whether any file-local base of `start` declares `member` as an explicit
/// interface implementation.
fn base_explicitly_implements(
    graph: &std::collections::HashMap<&str, Vec<&str>>,
    explicit: &std::collections::HashMap<&str, std::collections::HashSet<&str>>,
    start: &str,
    member: &str,
) -> bool {
    graph_reaches(graph, start, |current| {
        explicit
            .get(current)
            .is_some_and(|names| names.contains(member))
    })
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4039_this_qualified_calls_stay_uncovered() {
        // The receiver match requires a bare `identifier` function, so
        // `this.Greet()` stays outside the subset today.
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        this.Greet();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4039").is_empty());
    }

    #[test]
    fn s4039_own_declaration_suppresses_the_finding() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Greet()\n    {\n    }\n    public void Run()\n    {\n        Greet();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4039").is_empty());
    }

    #[test]
    fn s4039_implicitly_implemented_members_stay_clean() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    public void Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        Greet();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4039").is_empty());
    }

    #[test]
    fn s4039_other_receiver_shapes_stay_uncovered() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run(BaseGreeter other)\n    {\n        other.Greet();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4039").is_empty());
    }

    #[test]
    fn s4039_flags_each_explicit_only_member_distinctly() {
        let report = analyze_default(
            "interface IGreeter\n{\n    void Greet();\n    void Wave();\n}\nclass BaseGreeter : IGreeter\n{\n    void IGreeter.Greet()\n    {\n    }\n    void IGreeter.Wave()\n    {\n    }\n}\nclass DerivedGreeter : BaseGreeter\n{\n    public void Run()\n    {\n        Greet();\n        Wave();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4039");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 19);
        assert_eq!(flagged[1].range.start.line, 20);
    }
}
