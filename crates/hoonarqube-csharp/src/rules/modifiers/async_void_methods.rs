use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, containing_namespace, issue, modifiers_of,
    node_text, parameters_of, range_of,
};
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
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

fn has_system_import(root: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, use_site, source))
        .any(|using| using_directive_text(using, source) == "System")
        || containing_namespace(use_site, source) == "System"
}

fn source_declares_simple_type(root: Node<'_>, wanted: &str, source: &str) -> bool {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter_map(|declaration| declaration.child_by_field_name("name"))
        .any(|name| canonical_identifier(node_text(name, source)) == wanted)
}

fn is_system_type(
    root: Node<'_>,
    use_site: Node<'_>,
    type_node: Node<'_>,
    wanted: &str,
    source: &str,
) -> bool {
    let raw = normalized_type_name(node_text(type_node, source));
    let full = format!("System.{wanted}");
    if raw == format!("global::{full}") {
        return !source_declares_simple_type(root, wanted, source);
    }
    if raw == full {
        return !source_declares_simple_type(root, wanted, source);
    }
    if raw == wanted {
        return has_system_import(root, use_site, source)
            && !source_declares_simple_type(root, wanted, source);
    }
    type_node.kind() == "identifier"
        && using_alias_target(
            root,
            use_site,
            canonical_identifier(node_text(type_node, source)),
            &full,
            source,
        )
        && !source_declares_simple_type(root, wanted, source)
}

fn method_name<'a>(method: Node<'a>, source: &'a str) -> Option<&'a str> {
    method
        .child_by_field_name("name")
        .map(|name| canonical_identifier(node_text(name, source)))
}

fn parameter_type<'a>(parameter: Node<'a>, source: &'a str) -> Option<&'a str> {
    parameter
        .child_by_field_name("type")
        .map(|type_node| node_text(type_node, source))
}

fn is_event_handler_signature(root: Node<'_>, method: Node<'_>, source: &str) -> bool {
    let parameters = parameters_of(method);
    parameters.len() == 2
        && parameters[0]
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                is_system_type(root, method, type_node, "Object", source)
                    || node_text(type_node, source).trim() == "object"
            })
        && parameters[1]
            .child_by_field_name("type")
            .is_some_and(|type_node| is_system_type(root, method, type_node, "EventArgs", source))
}

fn same_parameter_types(left: Node<'_>, right: Node<'_>, source: &str) -> bool {
    let left = parameters_of(left);
    let right = parameters_of(right);
    left.len() == right.len()
        && left.iter().zip(right.iter()).all(|(left, right)| {
            let left_type = parameter_type(*left, source).map(|text| text.trim().replace(' ', ""));
            let right_type =
                parameter_type(*right, source).map(|text| text.trim().replace(' ', ""));
            let passing_kind = |parameter: Node<'_>| {
                ["ref", "out", "in"]
                    .into_iter()
                    .find(|modifier| has_modifier(&modifiers_of(parameter, source), modifier))
            };
            left_type == right_type && passing_kind(*left) == passing_kind(*right)
        })
}

fn generic_arity(method: Node<'_>) -> usize {
    method
        .child_by_field_name("type_parameters")
        .map_or(0, |parameters| {
            let mut cursor = parameters.walk();
            parameters
                .children(&mut cursor)
                .filter(|child| child.kind() == "type_parameter")
                .count()
        })
}

fn has_explicit_interface_specifier(method: Node<'_>) -> bool {
    let mut cursor = method.walk();
    method
        .children(&mut cursor)
        .any(|child| child.kind() == "explicit_interface_specifier")
}

fn direct_base_types(type_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(base_list) = ({
        let mut cursor = type_node.walk();
        type_node
            .children(&mut cursor)
            .find(|child| child.kind() == "base_list")
    }) else {
        return Vec::new();
    };
    let mut cursor = base_list.walk();
    base_list
        .children(&mut cursor)
        .filter(Node::is_named)
        .collect()
}

fn interface_identity(interface: Node<'_>, source: &str) -> Option<String> {
    let name = interface.child_by_field_name("name")?;
    let name = canonical_identifier(node_text(name, source));
    let namespace = containing_namespace(interface, source);
    Some(if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    })
}

fn base_resolves_to_interface(
    root: Node<'_>,
    owner: Node<'_>,
    base: Node<'_>,
    interface: Node<'_>,
    source: &str,
) -> bool {
    let base_text = normalized_type_name(node_text(base, source));
    let base_text = base_text.strip_prefix("global::").unwrap_or(&base_text);
    let Some(identity) = interface_identity(interface, source) else {
        return false;
    };
    let owner_namespace = containing_namespace(owner, source);
    if base_text.contains('.') {
        return base_text == identity
            || format!("{}.{}", containing_namespace(owner, source), base_text) == identity;
    }
    if identity == format!("{owner_namespace}.{base_text}") {
        return true;
    }
    if identity == base_text {
        return owner_namespace.is_empty()
            || !collect_kinds(root, &["interface_declaration"])
                .into_iter()
                .any(|candidate| {
                    interface_identity(candidate, source).is_some_and(|candidate| {
                        candidate == format!("{owner_namespace}.{base_text}")
                    })
                });
    }
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_applies(*using, owner, source))
        .any(|using| {
            let text = using_directive_text(using, source);
            let Some((left, right)) = text.split_once('=') else {
                return format!("{text}.{base_text}") == identity;
            };
            canonical_identifier(left.trim()) == base_text
                && normalized_type_name(right) == identity
        })
}

fn interface_method_matches(method: Node<'_>, member: Node<'_>, source: &str) -> bool {
    method_name(member, source) == method_name(method, source)
        && generic_arity(member) == generic_arity(method)
        && member
            .child_by_field_name("returns")
            .is_some_and(|returns| normalized_type_name(node_text(returns, source)) == "void")
        && same_parameter_types(method, member, source)
}

fn implements_interface_method(root: Node<'_>, method: Node<'_>, source: &str) -> bool {
    if has_explicit_interface_specifier(method) {
        return true;
    }
    let Some(owner) = ancestors_of(method).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "class_declaration" | "struct_declaration" | "record_declaration"
        )
    }) else {
        return false;
    };
    let modifiers = modifiers_of(method, source);
    if !has_modifier(&modifiers, "public") || has_modifier(&modifiers, "static") {
        return false;
    }
    direct_base_types(owner).into_iter().any(|base| {
        collect_kinds(root, &["interface_declaration"])
            .into_iter()
            .filter(|interface| base_resolves_to_interface(root, owner, base, *interface, source))
            .any(|interface| {
                type_members(interface)
                    .into_iter()
                    .any(|member| interface_method_matches(method, member, source))
            })
    })
}

fn is_on_event_pattern(method: Node<'_>, source: &str) -> bool {
    method_name(method, source).is_some_and(|name| {
        let mut chars = name.chars();
        matches!((chars.next(), chars.next()), (Some('O'), Some('n')))
            && chars
                .next()
                .is_some_and(|character| character.is_ascii_uppercase())
    })
}

/// csharpsquid:S3168 — async methods returning void swallow exceptions and
/// cannot be awaited, except for framework event-handler contracts and the
/// documented callback shapes.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        let Some(returns) = method
            .child_by_field_name("returns")
            .filter(|returns| node_text(*returns, source).trim() == "void")
        else {
            continue;
        };
        let modifiers = modifiers_of(method, source);
        if is_event_handler_signature(root, method, source)
            || has_modifier(&modifiers, "virtual")
            || has_modifier(&modifiers, "override")
            || implements_interface_method(root, method, source)
            || is_on_event_pattern(method, source)
        {
            continue;
        }
        issues.push(issue(
            language,
            "S3168",
            "Return 'Task' instead.",
            range_of(returns, source),
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3168_spares_event_handler_signatures_and_aliases() {
        let report = analyze_default(
            "using EventArgsAlias = System.EventArgs;\n\
             class C\n\
             {\n\
                 async void Handle(object sender, EventArgsAlias args) { await Task.Yield(); }\n\
                 async void Work() { await Task.Yield(); }\n\
             }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3168");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s3168_spares_documented_callback_shapes() {
        let report = analyze_default(
            "interface IHandler { void Handle(object sender, System.EventArgs args); }\n\
             class Base\n\
             {\n\
                 public virtual async void OnChanged(object sender, System.EventArgs args) { await Task.Yield(); }\n\
             }\n\
             class C : Base, IHandler\n\
             {\n\
                 public async void Handle(object sender, System.EventArgs args) { await Task.Yield(); }\n\
                 public override async void OnChanged(object sender, System.EventArgs args) { await Task.Yield(); }\n\
                 public async void OnMessage(object sender, System.EventArgs args) { await Task.Yield(); }\n\
             }\n",
        );
        assert!(with_key(&report, "csharpsquid:S3168").is_empty());
    }
    #[test]
    fn s3168_does_not_match_interface_methods_by_truncated_generic_types() {
        let report = analyze_default(
            "interface IHandler { void Work(System.Collections.Generic.List<int> values); }\n\
             class C : IHandler\n\
             {\n\
                 public void Work(System.Collections.Generic.List<int> values) { }\n\
                 public async void Work(System.Collections.Generic.List<string> values) { await Task.Yield(); }\n\
             }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3168").len(), 1);
    }

    #[test]
    fn s3168_distinguishes_parameter_passing_modifiers() {
        let report = analyze_default(
            "interface IHandler { void Work(ref int value); }\n\
             class C : IHandler\n\
             {\n\
                 public void Work(ref int value) { }\n\
                 public async void Work(int value) { await Task.Yield(); }\n\
             }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3168").len(), 1);
    }
}
