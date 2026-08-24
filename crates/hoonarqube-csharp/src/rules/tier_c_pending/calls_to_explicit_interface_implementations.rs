use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{
    enclosing_type, expression_name, first_named_child, invocation_function,
    member_declarations_of_kind,
};
use crate::rules::tier_c::local_inheritance_graph;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4039 — calls to members that only exist as explicit
/// interface implementations on a file-local base. Subset: bare or
/// `this.`-qualified invocations inside a file-local derived class whose
/// base chain declares the member only explicitly and which does not
/// declare the member itself; nested types and cross-file bases stay
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
                range_of(call),
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
    let mut seen = std::collections::HashSet::new();
    let mut queue: Vec<&str> = graph.get(start).cloned().unwrap_or_default();
    while let Some(current) = queue.pop() {
        if explicit
            .get(current)
            .is_some_and(|names| names.contains(member))
        {
            return true;
        }
        if seen.insert(current)
            && let Some(successors) = graph.get(current)
        {
            queue.extend(successors.iter().copied());
        }
    }
    false
}
