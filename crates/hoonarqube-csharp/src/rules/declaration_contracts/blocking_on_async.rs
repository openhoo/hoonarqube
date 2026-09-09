use super::support::enclosing_method;
use crate::CsLanguage;
use crate::cst::{
    canonical_identifier, collect_kinds, containing_namespace, is_error_tainted, issue,
    modifiers_of, node_text, parameters_of, range_of,
};
use crate::rules::expressions::{
    callee_name, expression_name, first_named_child, invocation_arguments, invocation_function,
    invocation_receiver, resolved_identifier_type,
};
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

fn normalized_type_name(text: &str) -> String {
    let mut text = text.trim().replace(' ', "");
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    text.trim_end_matches('?').to_string()
}

fn using_directive_text<'a>(using: Node<'_>, source: &'a str) -> &'a str {
    node_text(using, source)
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_start_matches("global")
        .trim()
        .trim_start_matches("using")
        .trim()
}

fn using_applies(using: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    let using_namespace = containing_namespace(using, source);
    using_namespace.is_empty() || using_namespace == containing_namespace(use_site, source)
}

fn using_alias_target(
    root: Node<'_>,
    use_site: Node<'_>,
    alias: &str,
    target: &str,
    source: &str,
) -> bool {
    let target = normalized_type_name(target);
    let target = target.strip_prefix("global::").unwrap_or(&target);
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, use_site, source))
        .any(|using| {
            let text = using_directive_text(using, source);
            let Some((left, right)) = text.split_once('=') else {
                return false;
            };
            let actual = normalized_type_name(right);
            let actual = actual.strip_prefix("global::").unwrap_or(&actual);
            canonical_identifier(left.trim()) == canonical_identifier(alias) && actual == target
        })
}

fn source_declares_task_type(root: Node<'_>, source: &str) -> bool {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .any(|name| canonical_identifier(node_text(name, source)) == "Task")
}

fn is_task_type(root: Node<'_>, use_site: Node<'_>, type_text: &str, source: &str) -> bool {
    let raw = normalized_type_name(type_text);
    let bare = raw.strip_prefix("global::").unwrap_or(&raw);
    if bare == "System.Threading.Tasks.Task" {
        return true;
    }
    if bare == "Task" {
        return !source_declares_task_type(root, source);
    }
    using_alias_target(
        root,
        use_site,
        canonical_identifier(type_text),
        "System.Threading.Tasks.Task",
        source,
    )
}

fn is_task_factory_receiver(root: Node<'_>, receiver: Node<'_>, source: &str) -> bool {
    if is_task_type(root, receiver, node_text(receiver, source), source) {
        return true;
    }
    receiver.kind() == "member_access_expression"
        && expression_name(receiver, source) == Some("Factory")
        && first_named_child(receiver)
            .is_some_and(|base| is_task_type(root, base, node_text(base, source), source))
}

fn is_task_origin_invocation(root: Node<'_>, invocation: Node<'_>, source: &str) -> bool {
    matches!(callee_name(invocation, source), Some("Run" | "StartNew"))
        && invocation_receiver(invocation)
            .is_some_and(|receiver| is_task_factory_receiver(root, receiver, source))
}
fn inferred_task_initializer<'t>(
    root: Node<'t>,
    identifier: Node<'t>,
    source: &str,
) -> Option<Node<'t>> {
    let wanted = canonical_identifier(node_text(identifier, source));
    collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.start_byte() < identifier.start_byte())
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            (canonical_identifier(node_text(name, source)) == wanted)
                .then(|| declarator_initializer(declarator, name))
                .flatten()
        })
        .max_by_key(tree_sitter::Node::start_byte)
}
fn is_task_producer(name: Option<&str>) -> bool {
    matches!(
        name,
        Some(
            "Run"
                | "StartNew"
                | "Delay"
                | "FromResult"
                | "FromException"
                | "FromCanceled"
                | "WhenAll"
                | "WhenAny"
        )
    )
}

fn is_task_expression(root: Node<'_>, expression: Node<'_>, source: &str) -> bool {
    match expression.kind() {
        "parenthesized_expression" => first_named_child(expression)
            .is_some_and(|inner| is_task_expression(root, inner, source)),
        "identifier" | "member_access_expression" => {
            if let Some(type_name) = resolved_identifier_type(expression, source) {
                if is_task_type(root, expression, type_name, source) {
                    return true;
                }
                if normalized_type_name(type_name) == "var" {
                    return inferred_task_initializer(root, expression, source)
                        .is_some_and(|initializer| is_task_expression(root, initializer, source));
                }
                return false;
            }
            is_task_type(root, expression, node_text(expression, source), source)
        }
        "invocation_expression" => {
            is_task_producer(callee_name(expression, source))
                && invocation_receiver(expression)
                    .is_some_and(|receiver| is_task_factory_receiver(root, receiver, source))
        }
        _ => false,
    }
}

fn is_entry_point_main(node: Node<'_>, source: &str) -> bool {
    let Some(method) = enclosing_method(node) else {
        return false;
    };
    let Some(name) = method.child_by_field_name("name") else {
        return false;
    };
    if canonical_identifier(node_text(name, source)) != "Main"
        || !has_modifier(&modifiers_of(method, source), "static")
    {
        return false;
    }
    let returns_valid = method
        .child_by_field_name("returns")
        .is_some_and(|returns| matches!(node_text(returns, source).trim(), "void" | "int"));
    if !returns_valid {
        return false;
    }
    let parameters = parameters_of(method);
    parameters.is_empty()
        || (parameters.len() == 1
            && parameters[0]
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    normalized_type_name(node_text(type_node, source)) == "string[]"
                }))
}

fn receiver_already_waited(
    root: Node<'_>,
    access: Node<'_>,
    receiver: Node<'_>,
    source: &str,
) -> bool {
    let Some(method) = enclosing_method(access) else {
        return false;
    };
    let receiver_text = node_text(receiver, source).trim();
    collect_kinds(method, &["invocation_expression"])
        .into_iter()
        .filter(|wait| wait.start_byte() < access.start_byte())
        .any(|wait| {
            callee_name(wait, source) == Some("Wait")
                && invocation_arguments(wait).is_empty()
                && invocation_receiver(wait).is_some_and(|wait_receiver| {
                    node_text(wait_receiver, source).trim() == receiver_text
                        && is_task_expression(root, wait_receiver, source)
                })
        })
}

fn is_task_awaiter(root: Node<'_>, invocation: Node<'_>, source: &str) -> bool {
    callee_name(invocation, source) == Some("GetAwaiter")
        && invocation_receiver(invocation)
            .is_some_and(|receiver| is_task_expression(root, receiver, source))
}

fn is_origin_awaiter_chain(root: Node<'_>, awaiter: Node<'_>, source: &str) -> bool {
    invocation_receiver(awaiter)
        .filter(|receiver| receiver.kind() == "invocation_expression")
        .is_some_and(|receiver| is_task_origin_invocation(root, receiver, source))
}
/// csharpsquid:S4462 — `.Result`, `.Wait()`, and `GetAwaiter().GetResult()`
/// deadlock thread-pool-synchronized contexts. Member identity is resolved
/// to the framework Task/awaiter API before reporting.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for access in collect_kinds(root, &["member_access_expression"]) {
        if is_error_tainted(access) || expression_name(access, source) != Some("Result") {
            continue;
        }
        let Some(receiver) = first_named_child(access) else {
            continue;
        };
        let called_like_a_method = access.parent().is_some_and(|parent| {
            parent.kind() == "invocation_expression" && invocation_function(parent) == Some(access)
        });
        let origin_exempt = receiver.kind().eq("invocation_expression")
            && is_task_origin_invocation(root, receiver, source);
        if called_like_a_method
            || is_entry_point_main(access, source)
            || origin_exempt
            || receiver_already_waited(root, access, receiver, source)
            || !is_task_expression(root, receiver, source)
        {
            continue;
        }
        issues.push(issue(
            language,
            "S4462",
            "Replace this use of 'Task.Result' with 'await'.",
            range_of(access, source),
        ));
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) || is_entry_point_main(invocation, source) {
            continue;
        }
        let receiver = invocation_receiver(invocation);
        let origin_exempt = receiver
            .filter(|receiver| receiver.kind() == "invocation_expression")
            .is_some_and(|receiver| is_task_origin_invocation(root, receiver, source));
        let zero_arg_wait = callee_name(invocation, source) == Some("Wait")
            && invocation_arguments(invocation).is_empty()
            && !origin_exempt
            && receiver.is_some_and(|receiver| is_task_expression(root, receiver, source));
        let get_result_chain = callee_name(invocation, source) == Some("GetResult")
            && invocation_arguments(invocation).is_empty()
            && !receiver
                .filter(|receiver| receiver.kind() == "invocation_expression")
                .is_some_and(|awaiter| is_origin_awaiter_chain(root, awaiter, source))
            && receiver.is_some_and(|receiver| is_task_awaiter(root, receiver, source));
        if zero_arg_wait || get_result_chain {
            let construct = if zero_arg_wait {
                "Task.Wait"
            } else {
                "Task.GetAwaiter.GetResult"
            };
            issues.push(issue(
                language,
                "S4462",
                format!("Replace this use of '{construct}' with 'await'."),
                range_of(
                    invocation_function(invocation).unwrap_or(invocation),
                    source,
                ),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4462_binds_result_and_wait_to_task_types() {
        let report = analyze_default(
            "class Counter\n\
             {\n\
                 public int Result => 42;\n\
                 public void Wait() { }\n\
             }\n\
             class C\n\
             {\n\
                 int Read(Counter counter) => counter.Result;\n\
                 void Block(Counter counter) => counter.Wait();\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S4462").is_empty());

        let task = analyze_default(
            "class C\n\
             {\n\
                 int Read(System.Threading.Tasks.Task<int> task) => task.Result;\n\
                 void Block(System.Threading.Tasks.Task task) => task.Wait();\n\
             }\n",
        );
        assert_eq!(with_key(&task, "csharpsquid:S4462").len(), 2);
    }

    #[test]
    fn s4462_handles_aliases_awaiter_and_main_exception() {
        let report = analyze_default(
            "using TaskAlias = System.Threading.Tasks.Task;\n\
             using GenericTaskAlias = System.Threading.Tasks.Task<int>;\n\
             class C\n\
             {\n\
                 int Read(GenericTaskAlias task) => task.Result;\n\
                 void Block(TaskAlias task) => task.Wait();\n\
                 int Awaiter(GenericTaskAlias task) => task.GetAwaiter().GetResult();\n\
                 static void Main() { System.Threading.Tasks.Task.Run(() => 1).Wait(); }\n\
             }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4462");
        assert_eq!(flagged.len(), 3);
    }

    #[test]
    fn s4462_preserves_task_producer_and_binding_controls() {
        let delay = analyze_default(
            "class C\n\
             {\n\
                 void Direct() { System.Threading.Tasks.Task.Delay(1).Wait(); }\n\
                 void Inferred() { var task = System.Threading.Tasks.Task.Delay(1); task.Wait(); }\n\
             }\n",
        );
        assert_eq!(with_key(&delay, "csharpsquid:S4462").len(), 2);

        let shadow = analyze_default(
            "class Counter { public void Wait() { } }\n\
             class C { void M(Counter Task) { Task.Wait(); } }\n",
        );
        assert!(with_key(&shadow, "csharpsquid:S4462").is_empty());

        let instance_main = analyze_default(
            "class C { public void Main(System.Threading.Tasks.Task task) { task.Wait(); } }\n",
        );
        assert_eq!(with_key(&instance_main, "csharpsquid:S4462").len(), 1);

        let wait_then_result = analyze_default(
            "class C\n\
             {\n\
                 int M(System.Threading.Tasks.Task<int> task)\n\
                 {\n\
                     task.Wait();\n\
                     return task.Result;\n\
                 }\n\
             }\n",
        );
        assert_eq!(with_key(&wait_then_result, "csharpsquid:S4462").len(), 1);
        let yielded = analyze_default(
            "class C\n\
             {\n\
                 int M() => System.Threading.Tasks.Task.Yield().GetAwaiter().GetResult();\n\
             }\n",
        );
        assert!(with_key(&yielded, "csharpsquid:S4462").is_empty());
    }
}
