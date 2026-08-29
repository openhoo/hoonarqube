use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_from_byte_offsets,
};
use crate::rules::expressions::{
    callee_name, enclosing_type, expression_name, invocation_arguments, invocation_function,
    invocation_receiver,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4220 — instance events must be raised with a non-null sender.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let events = instance_event_names(type_node, source);
        if events.is_empty() {
            continue;
        }
        for call in collect_kinds(type_node, &["invocation_expression"])
            .into_iter()
            .filter(|call| enclosing_type(*call).is_some_and(|owner| owner.id() == type_node.id()))
        {
            if event_invocation_with_null_sender(call, source, &events) {
                let call_text = node_text(call, source);
                let start = call_text
                    .find(".Invoke")
                    .map_or(call.start_byte(), |offset| call.start_byte() + offset);
                issues.push(issue(
                    language,
                    "S4220",
                    "Make the sender on this event invocation not null.",
                    range_from_byte_offsets(start, call.end_byte(), source),
                ));
            }
        }
    }
    issues
}

fn instance_event_names<'a>(
    type_node: Node<'_>,
    source: &'a str,
) -> std::collections::HashSet<&'a str> {
    let mut names = std::collections::HashSet::new();
    for member in type_members(type_node)
        .into_iter()
        .filter(|member| !has_modifier(&modifiers_of(*member, source), "static"))
    {
        match member.kind() {
            "event_field_declaration" => {
                for declarator in collect_kinds(member, &["variable_declarator"]) {
                    if let Some(name) = declarator.child_by_field_name("name") {
                        names.insert(node_text(name, source));
                    }
                }
            }
            "event_declaration" => {
                if let Some(name) = member.child_by_field_name("name") {
                    names.insert(node_text(name, source));
                }
            }
            _ => {}
        }
    }
    names
}

fn event_invocation_with_null_sender(
    call: Node<'_>,
    source: &str,
    events: &std::collections::HashSet<&str>,
) -> bool {
    if is_error_tainted(call) {
        return false;
    }
    let Some(receiver) = invoke_receiver(call, source) else {
        return false;
    };
    let Some(event_name) = expression_name(receiver, source) else {
        return false;
    };
    events.contains(event_name)
        && !bare_receiver_is_shadowed(call, receiver, event_name, source)
        && invocation_arguments(call).first().is_some_and(|argument| {
            let mut cursor = argument.walk();
            argument
                .named_children(&mut cursor)
                .last()
                .is_some_and(|value| value.kind() == "null_literal")
        })
}

fn invoke_receiver<'t>(call: Node<'t>, source: &str) -> Option<Node<'t>> {
    let function = invocation_function(call)?;
    match function.kind() {
        "member_access_expression" if callee_name(call, source) == Some("Invoke") => {
            invocation_receiver(call)
        }
        "conditional_access_expression" => {
            let binding = collect_kinds(function, &["member_binding_expression"])
                .into_iter()
                .next()?;
            let invokes = binding
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Invoke");
            invokes
                .then(|| function.child_by_field_name("condition"))
                .flatten()
        }
        _ => None,
    }
}

fn bare_receiver_is_shadowed(call: Node<'_>, receiver: Node<'_>, name: &str, source: &str) -> bool {
    if receiver.kind() != "identifier" {
        return false;
    }
    let Some(callable) = crate::cst::ancestors_of(call).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "method_declaration"
                | "constructor_declaration"
                | "destructor_declaration"
                | "operator_declaration"
                | "accessor_declaration"
                | "local_function_statement"
        )
    }) else {
        return false;
    };
    if crate::cst::parameters_of(callable).iter().any(|parameter| {
        parameter
            .child_by_field_name("name")
            .is_some_and(|parameter_name| node_text(parameter_name, source) == name)
    }) {
        return true;
    }
    collect_kinds(callable, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.start_byte() < call.start_byte())
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .any(|local_name| node_text(local_name, source) == name)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4220_arbitrary_delegate_invocation_is_not_an_event_raise() {
        let report = analyze_default(
            "class C { void Raise(Action<object, EventArgs> callback) { callback.Invoke(null, EventArgs.Empty); } }",
        );
        assert!(with_key(&report, "csharpsquid:S4220").is_empty());
    }

    #[test]
    fn s4220_static_event_allows_null_sender() {
        let report = analyze_default(
            "class C { static event EventHandler Changed; static void Raise() { Changed?.Invoke(null, EventArgs.Empty); } }",
        );
        assert!(with_key(&report, "csharpsquid:S4220").is_empty());
    }

    #[test]
    fn s4220_local_shadow_of_event_is_not_treated_as_event_raise() {
        let report = analyze_default(
            "class C { event EventHandler Changed; void Raise() { Action<object, EventArgs> Changed = Log; Changed.Invoke(null, EventArgs.Empty); } static void Log(object sender, EventArgs args) { } }",
        );
        assert!(with_key(&report, "csharpsquid:S4220").is_empty());
    }
}
