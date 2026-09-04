//! GitHub Code Quality queries for C#.
//!
//! These checks intentionally have their own identities and orchestration.  The
//! `SonarQube` rule walkers do not call into this module: a finding here must
//! therefore never alter the output of [`crate::analyze`].

use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, containing_namespace, modifiers_of,
    node_text, range_of, simple_name,
};
use crate::rules::expressions::{callee_name, enclosing_callable, enclosing_type};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use crate::rules::structure::for_clauses;
use hoonarqube_ir::{FlowLocation, Issue};
use std::collections::HashSet;
use tree_sitter::Node;

/// The identifier node of a type declaration, when tree-sitter recovered one.
fn type_name_node(type_node: Node<'_>) -> Option<Node<'_>> {
    type_node.child_by_field_name("name")
}

/// Normalizes a type reference without pretending that a syntax tree resolves
/// external assemblies.  Qualification is retained so two namespaces with
/// the same short name cannot be conflated.
fn normalized_type_name(text: &str) -> String {
    let mut text = text.trim().replace(' ', "");
    if let Some(index) = text.find('<') {
        text.truncate(index);
    }
    text.trim_end_matches('?').to_string()
}

fn enclosing_type_path(type_node: Node<'_>, source: &str) -> Vec<String> {
    let mut path: Vec<String> = ancestors_of(type_node)
        .filter(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
        .filter_map(|ancestor| type_name(ancestor, source).map(str::to_owned))
        .collect();
    path.reverse();
    path
}

fn type_identity(type_node: Node<'_>, source: &str) -> Option<String> {
    let name = type_name(type_node, source)?;
    let mut path = enclosing_type_path(type_node, source);
    path.push(name.to_string());
    let name = path.join(".");
    let namespace = containing_namespace(type_node, source);
    Some(if namespace.is_empty() {
        name
    } else {
        format!("{namespace}.{name}")
    })
}

fn base_type_nodes(type_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(base_list) = direct_named_children(type_node)
        .into_iter()
        .find(|child| child.kind() == "base_list")
    else {
        return Vec::new();
    };
    direct_named_children(base_list)
}

fn source_type_declarations(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
}

fn source_declares_type_identity(root: Node<'_>, wanted: &str, source: &str) -> bool {
    source_type_declarations(root)
        .into_iter()
        .any(|type_node| type_identity(type_node, source).as_deref() == Some(wanted))
}

fn source_declares_type_name(
    root: Node<'_>,
    use_site: Node<'_>,
    wanted: &str,
    source: &str,
) -> bool {
    declared_type_named(root, wanted, use_site, source).is_some()
}

fn using_directive_applies(using: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    let using_namespace = containing_namespace(using, source);
    let use_namespace = containing_namespace(use_site, source);
    using_namespace.is_empty() || using_namespace == use_namespace
}

fn using_directive_text(using: Node<'_>, source: &str) -> String {
    node_text(using, source)
        .trim()
        .trim_end_matches(';')
        .trim()
        .trim_start_matches("global")
        .trim()
        .trim_start_matches("using")
        .trim()
        .to_string()
}

fn has_namespace_import(root: Node<'_>, use_site: Node<'_>, namespace: &str, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_directive_applies(*using, use_site, source))
        .any(|using| using_directive_text(using, source) == namespace)
        || containing_namespace(use_site, source) == namespace
}

fn has_using_alias(root: Node<'_>, use_site: Node<'_>, alias: &str, source: &str) -> bool {
    collect_kinds(root, &["using_directive"])
        .into_iter()
        .filter(|using| using_directive_applies(*using, use_site, source))
        .any(|using| {
            using_directive_text(using, source)
                .split_once('=')
                .is_some_and(|(left, _)| left.trim() == alias)
        })
}

/// Exact framework-type evidence.  Bare names require a visible `using
/// System;` (or the `System` namespace), and all visible source shadows are
/// rejected.
fn is_known_system_type(
    root: Node<'_>,
    use_site: Node<'_>,
    type_node: Node<'_>,
    wanted: &str,
    source: &str,
) -> bool {
    let raw = normalized_type_name(node_text(type_node, source));
    let fully_qualified = format!("System.{wanted}");
    if raw == format!("global::{fully_qualified}") {
        return !source_declares_type_identity(root, &fully_qualified, source);
    }
    if raw == fully_qualified {
        return !source_declares_type_identity(root, &fully_qualified, source)
            && !has_using_alias(root, use_site, "System", source);
    }
    raw == wanted
        && has_namespace_import(root, use_site, "System", source)
        && !source_declares_type_name(root, use_site, wanted, source)
        && !has_using_alias(root, use_site, wanted, source)
}

/// Runs all C# CodeQL-quality checks in source order.
#[must_use]
pub(crate) fn check(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(local_shadows_member(root, source));
    issues.extend(nested_if_statements(root, source));
    issues.extend(static_field_written_by_instance(root, source));
    issues.extend(call_to_gc(root, source));
    issues.extend(type_test_of_this(root, source));
    issues.extend(unsafe_sync_on_field(root, source));
    issues.extend(catch_nullreferenceexception(root, source));
    issues.extend(rethrown_exception_variable(root, source));
    issues.extend(class_implements_icloneable(root, source));
    issues.extend(unused_labels(root, source));
    issues.extend(empty_lock_statements(root, source));
    issues.extend(lock_this(root, source));
    issues.extend(nested_loops_with_same_variable(root, source));
    hoonarqube_ir::sort_issues(&mut issues);
    issues
}

fn type_name<'a>(type_node: Node<'_>, source: &'a str) -> Option<&'a str> {
    type_node
        .child_by_field_name("name")
        .map(|name| canonical_identifier(node_text(name, source)))
}

fn direct_named_children(node: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).filter(Node::is_named).collect()
}

fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    direct_named_children(node).into_iter().next()
}

fn direct_field_declarators(member: Node<'_>) -> Vec<Node<'_>> {
    let Some(declaration) = direct_named_children(member)
        .into_iter()
        .find(|child| child.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    collect_kinds(declaration, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| {
            ancestors_of(*declarator)
                .find(|ancestor| ancestor.kind() == "variable_declaration")
                .is_some_and(|owner| owner.id() == declaration.id())
        })
        .collect()
}

fn member_name_node<'a>(member: Node<'a>, source: &str) -> Option<Node<'a>> {
    member
        .child_by_field_name("name")
        .or_else(|| {
            direct_field_declarators(member)
                .into_iter()
                .find_map(|declarator| declarator.child_by_field_name("name"))
        })
        .or_else(|| {
            collect_kinds(member, &["identifier"])
                .into_iter()
                .find(|identifier| !node_text(*identifier, source).is_empty())
        })
}

#[derive(Clone, Copy)]
struct Field<'t> {
    anchor: Node<'t>,
    name: &'t str,
    is_static: bool,
}

fn fields_of<'t>(owner: Node<'t>, source: &'t str) -> Vec<Field<'t>> {
    let mut fields = Vec::new();
    for member in type_members(owner) {
        if !matches!(
            member.kind(),
            "field_declaration" | "event_field_declaration"
        ) {
            continue;
        }
        let is_static = has_modifier(&modifiers_of(member, source), "static")
            || has_modifier(&modifiers_of(member, source), "const");
        for declarator in direct_field_declarators(member) {
            let Some(anchor) = declarator
                .child_by_field_name("name")
                .or_else(|| first_named_child(declarator))
            else {
                continue;
            };
            if anchor.kind() != "identifier" {
                continue;
            }
            fields.push(Field {
                anchor,
                name: canonical_identifier(node_text(anchor, source)),
                is_static,
            });
        }
    }
    fields
}

fn callable_is_static(callable: Node<'_>, source: &str) -> bool {
    if has_modifier(&modifiers_of(callable, source), "static") {
        return true;
    }
    if callable.kind() == "accessor_declaration" {
        return ancestors_of(callable)
            .find(|ancestor| {
                matches!(
                    ancestor.kind(),
                    "property_declaration" | "event_declaration"
                )
            })
            .is_some_and(|member| has_modifier(&modifiers_of(member, source), "static"));
    }
    false
}

fn declaration_scope(declaration: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(declaration).find(|ancestor| {
        matches!(
            ancestor.kind(),
            "block"
                | "for_statement"
                | "foreach_statement"
                | "using_statement"
                | "fixed_statement"
                | "switch_section"
        )
    })
}

fn binding_name<'a>(declaration: Node<'_>, source: &'a str) -> Option<&'a str> {
    declaration
        .child_by_field_name("name")
        .or_else(|| {
            (declaration.kind() == "foreach_statement")
                .then(|| declaration.child_by_field_name("left"))
                .flatten()
        })
        .filter(|name| name.kind() == "identifier")
        .map(|name| canonical_identifier(node_text(name, source)))
}

fn belongs_to_callable(node: Node<'_>, callable: Node<'_>) -> bool {
    enclosing_callable(node) == Some(callable)
}

fn has_local_binding_before(use_site: Node<'_>, wanted: &str, source: &str) -> bool {
    let Some(callable) = enclosing_callable(use_site) else {
        return false;
    };
    let parameters = collect_kinds(callable, &["parameter"])
        .into_iter()
        .filter(|parameter| enclosing_callable(*parameter) == Some(callable))
        .any(|parameter| binding_name(parameter, source).is_some_and(|name| name == wanted));
    if parameters {
        return true;
    }
    collect_kinds(callable, &["variable_declarator"])
        .into_iter()
        .filter(|declaration| {
            belongs_to_callable(*declaration, callable)
                && declaration.start_byte() < use_site.start_byte()
        })
        .filter(|declaration| {
            declaration_scope(*declaration)
                .is_some_and(|scope| ancestors_of(use_site).any(|ancestor| ancestor == scope))
        })
        .any(|declaration| binding_name(declaration, source) == Some(wanted))
}

fn member_is_static_for(
    owner: Node<'_>,
    fields: &[Field<'_>],
    member: Node<'_>,
    local_name: &str,
    source: &str,
) -> bool {
    fields
        .iter()
        .find(|field| field.anchor == member)
        .is_some_and(|field| field.is_static)
        || type_members(owner).into_iter().any(|member| {
            matches!(member.kind(), "property_declaration" | "event_declaration")
                && member_name_node(member, source)
                    .is_some_and(|name| canonical_identifier(node_text(name, source)) == local_name)
                && has_modifier(&modifiers_of(member, source), "static")
        })
}

fn owner_members<'t>(
    owner: Node<'t>,
    fields: &[Field<'t>],
    source: &'t str,
) -> Vec<(&'t str, Node<'t>)> {
    let mut members: Vec<(&'t str, Node<'t>)> = fields
        .iter()
        .map(|field| (field.name, field.anchor))
        .collect();
    for member in type_members(owner) {
        if !matches!(member.kind(), "property_declaration" | "event_declaration") {
            continue;
        }
        let Some(name) = member_name_node(member, source) else {
            continue;
        };
        members.push((canonical_identifier(node_text(name, source)), name));
    }
    members
}

fn local_name_node(local: Node<'_>) -> Option<Node<'_>> {
    local
        .child_by_field_name("name")
        .or_else(|| {
            matches!(local.kind(), "variable_declarator" | "foreach_statement")
                .then(|| {
                    local
                        .child_by_field_name("left")
                        .or_else(|| first_named_child(local))
                })
                .flatten()
        })
        .filter(|name| name.kind() == "identifier")
}

fn local_binding_name<'t>(local: Node<'t>, source: &'t str) -> Option<(Node<'t>, &'t str)> {
    local_name_node(local).map(|name| (name, canonical_identifier(node_text(name, source))))
}

fn is_constructor_or_deconstruct_parameter(
    callable: Node<'_>,
    local: Node<'_>,
    source: &str,
) -> bool {
    local.kind() == "parameter"
        && (callable.kind() == "constructor_declaration"
            || (callable.kind() == "method_declaration"
                && callable
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "Deconstruct")))
}

fn local_shadow_is_excluded(
    owner: Node<'_>,
    fields: &[Field<'_>],
    member: Node<'_>,
    callable: Node<'_>,
    local_name: &str,
    source: &str,
) -> bool {
    let member_is_static = member_is_static_for(owner, fields, member, local_name, source);
    callable_is_static(callable, source) && !member_is_static
}

fn has_explicit_this_qualification(callable: Node<'_>, local_name: &str, source: &str) -> bool {
    collect_kinds(callable, &["member_access_expression"])
        .into_iter()
        .filter(|access| enclosing_callable(*access) == Some(callable))
        .any(|access| {
            access
                .child_by_field_name("name")
                .is_some_and(|name| canonical_identifier(node_text(name, source)) == local_name)
                && access
                    .child_by_field_name("expression")
                    .is_some_and(|expression| is_this_node(expression))
        })
}

fn local_shadow_issue(
    owner_name: &str,
    local_name: &str,
    local_name_node: Node<'_>,
    member: Node<'_>,
    source: &str,
) -> Issue {
    let mut issue = Issue::new(
        "cs/local-shadows-member",
        format!("Local scope variable '{local_name}' shadows $@."),
        range_of(local_name_node, source),
    );
    issue = issue.with_flow(vec![FlowLocation::in_primary_file(
        format!("{owner_name}.{local_name}"),
        range_of(member, source),
    )]);
    issue
}

fn local_shadow_for_local<'t>(
    owner: Node<'t>,
    fields: &[Field<'t>],
    members: &[(&'t str, Node<'t>)],
    owner_name: &str,
    local: Node<'t>,
    source: &'t str,
) -> Option<Issue> {
    if enclosing_type(local) != Some(owner) {
        return None;
    }
    let callable = enclosing_callable(local)?;
    let (local_name_node, local_name) = local_binding_name(local, source)?;
    let member = members
        .iter()
        .find(|(name, _)| *name == local_name)
        .map(|(_, anchor)| *anchor)?;
    if is_constructor_or_deconstruct_parameter(callable, local, source) {
        return None;
    }
    if local_shadow_is_excluded(owner, fields, member, callable, local_name, source)
        || has_explicit_this_qualification(callable, local_name, source)
    {
        return None;
    }
    Some(local_shadow_issue(
        owner_name,
        local_name,
        local_name_node,
        member,
        source,
    ))
}

fn local_shadows_for_owner<'t>(owner: Node<'t>, source: &'t str) -> Vec<Issue> {
    let Some(owner_name) = type_name(owner, source) else {
        return Vec::new();
    };
    let fields = fields_of(owner, source);
    let members = owner_members(owner, &fields, source);
    if members.is_empty() {
        return Vec::new();
    }
    collect_kinds(
        owner,
        &["variable_declarator", "parameter", "foreach_statement"],
    )
    .into_iter()
    .filter_map(|local| local_shadow_for_local(owner, &fields, &members, owner_name, local, source))
    .collect()
}

fn local_shadows_member(root: Node<'_>, source: &str) -> Vec<Issue> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .flat_map(|owner| local_shadows_for_owner(owner, source))
        .collect()
}

fn direct_statement_bodies(node: Node<'_>) -> Vec<Node<'_>> {
    direct_named_children(node)
        .into_iter()
        .filter(|child| child.kind() == "block" || child.kind().ends_with("_statement"))
        .collect()
}

fn strip_singleton_blocks(mut node: Node<'_>) -> Option<Node<'_>> {
    loop {
        if node.kind() != "block" {
            return Some(node);
        }
        let statements = block_statements(node);
        if statements.len() != 1 {
            return None;
        }
        node = statements[0];
    }
}

fn has_else(if_statement: Node<'_>) -> bool {
    direct_named_children(if_statement)
        .into_iter()
        .any(|child| child.kind() == "else")
        || {
            let mut cursor = if_statement.walk();
            if_statement
                .children(&mut cursor)
                .any(|child| child.kind() == "else")
        }
}

fn nested_if_statements(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for outer in collect_kinds(root, &["if_statement"]) {
        if has_else(outer) {
            continue;
        }
        let Some(then_body) = direct_statement_bodies(outer).into_iter().next() else {
            continue;
        };
        let Some(inner) = strip_singleton_blocks(then_body) else {
            continue;
        };
        if inner.kind() != "if_statement" || has_else(inner) {
            continue;
        }
        issues.push(Issue::new(
            "cs/nested-if-statements",
            "These 'if' statements can be combined.",
            range_of(outer, source),
        ));
    }
    issues
}

fn operator_kind(node: Node<'_>) -> Option<&'static str> {
    const OPERATORS: [&str; 9] = ["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^="];
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| !child.is_named())
        .and_then(|child| {
            OPERATORS
                .iter()
                .find(|operator| **operator == child.kind())
                .copied()
        })
}

fn assignment_target(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "assignment_expression" {
        if operator_kind(node).is_some() {
            return direct_named_children(node).into_iter().next();
        }
        return None;
    }
    if matches!(
        node.kind(),
        "prefix_unary_expression" | "postfix_unary_expression"
    ) {
        let mut cursor = node.walk();
        if node
            .children(&mut cursor)
            .any(|child| matches!(child.kind(), "++" | "--"))
        {
            return first_named_child(node);
        }
    }
    if node.kind() == "argument" {
        let mut cursor = node.walk();
        if node
            .children(&mut cursor)
            .any(|child| matches!(child.kind(), "ref" | "out"))
        {
            return first_named_child(node);
        }
    }
    None
}

fn target_name<'a>(target: Node<'_>, source: &'a str) -> Option<&'a str> {
    match target.kind() {
        "identifier" => Some(canonical_identifier(node_text(target, source))),
        "member_access_expression" => target
            .child_by_field_name("name")
            .filter(|name| name.kind() == "identifier")
            .map(|name| canonical_identifier(node_text(name, source))),
        _ => None,
    }
}

fn target_is_this_or_owner(target: Node<'_>, owner: Node<'_>, source: &str) -> bool {
    if target.kind() != "member_access_expression" {
        return false;
    }
    let Some(receiver) = target.child_by_field_name("expression") else {
        return false;
    };
    if matches!(receiver.kind(), "this" | "this_expression") {
        return true;
    }
    type_name(owner, source).is_some_and(|name| node_text(receiver, source).trim() == name)
}

fn field_for_target<'t>(
    target: Node<'t>,
    owner: Node<'t>,
    fields: &[Field<'t>],
    source: &str,
) -> Option<Field<'t>> {
    let name = target_name(target, source)?;
    if target.kind() == "identifier" && has_local_binding_before(target, name, source) {
        return None;
    }
    if target.kind() == "member_access_expression"
        && !target_is_this_or_owner(target, owner, source)
    {
        return None;
    }
    fields.iter().copied().find(|field| field.name == name)
}

fn static_field_written_by_instance(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for owner in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let fields: Vec<Field<'_>> = fields_of(owner, source)
            .into_iter()
            .filter(|field| field.is_static)
            .collect();
        if fields.is_empty() {
            continue;
        }
        for write in collect_kinds(
            owner,
            &[
                "assignment_expression",
                "prefix_unary_expression",
                "postfix_unary_expression",
                "argument",
            ],
        ) {
            if enclosing_type(write) != Some(owner) {
                continue;
            }
            let Some(callable) = enclosing_callable(write) else {
                continue;
            };
            if callable_is_static(callable, source) {
                continue;
            }
            let Some(target) = assignment_target(write) else {
                continue;
            };
            let Some(_field) = field_for_target(target, owner, &fields, source) else {
                continue;
            };
            issues.push(Issue::new(
                "cs/static-field-written-by-instance",
                "Write to static field from instance method, property, or constructor.",
                range_of(target, source),
            ));
        }
    }
    issues
}

fn receiver_is_known_gc(root: Node<'_>, call: Node<'_>, receiver: Node<'_>, source: &str) -> bool {
    let raw = normalized_type_name(node_text(receiver, source));
    if raw == "global::System.GC" {
        return !source_declares_type_identity(root, "System.GC", source);
    }
    if raw == "System.GC" {
        return !source_declares_type_identity(root, "System.GC", source)
            && !has_using_alias(root, call, "System", source);
    }
    if raw != "GC" {
        return false;
    }
    if has_local_binding_before(receiver, "GC", source)
        || enclosing_type(receiver).is_some_and(|owner| {
            type_members(owner).into_iter().any(|member| {
                matches!(
                    member.kind(),
                    "field_declaration"
                        | "event_field_declaration"
                        | "property_declaration"
                        | "event_declaration"
                ) && member_name_node(member, source)
                    .is_some_and(|name| canonical_identifier(node_text(name, source)) == "GC")
            })
        })
    {
        return false;
    }
    is_known_system_type(root, call, receiver, "GC", source)
}

fn call_to_gc(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        let Some(function) = call
            .child_by_field_name("function")
            .or_else(|| first_named_child(call))
        else {
            continue;
        };
        if function.kind() != "member_access_expression" {
            continue;
        }
        let Some(name) = function.child_by_field_name("name") else {
            continue;
        };
        if canonical_identifier(node_text(name, source)) != "Collect" {
            continue;
        }
        let Some(receiver) = function
            .child_by_field_name("expression")
            .or_else(|| first_named_child(function))
        else {
            continue;
        };
        if !receiver_is_known_gc(root, call, receiver, source) {
            continue;
        }
        let arguments = direct_named_children(call)
            .into_iter()
            .find(|child| child.kind() == "argument_list")
            .map(direct_named_children)
            .unwrap_or_default();
        if !arguments.is_empty() {
            continue;
        }
        issues.push(Issue::new(
            "cs/call-to-gc",
            "Call to 'GC.Collect()'.",
            range_of(call, source),
        ));
    }
    issues
}

fn is_assertion_context(node: Node<'_>, source: &str) -> bool {
    ancestors_of(node).any(|ancestor| {
        ancestor.kind() == "invocation_expression"
            && callee_name(ancestor, source).is_some_and(|name| {
                matches!(
                    name,
                    "Assert"
                        | "Assume"
                        | "Requires"
                        | "Ensures"
                        | "IsTrue"
                        | "IsFalse"
                        | "That"
                        | "Fail"
                )
            })
    })
}

fn lookup_type_prefixes(scope: Node<'_>, source: &str) -> Vec<String> {
    let mut type_path = if TYPE_DECLARATION_KINDS.contains(&scope.kind()) {
        type_name(scope, source)
            .map(str::to_owned)
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    type_path.extend(enclosing_type_path(scope, source));
    type_path.reverse();
    let namespace = containing_namespace(scope, source);
    let namespace_parts: Vec<&str> = namespace
        .split('.')
        .filter(|part| !part.is_empty())
        .collect();
    let mut prefixes = Vec::new();
    for type_count in (0..=type_path.len()).rev() {
        let type_prefix = type_path[..type_count].join(".");
        for namespace_count in (0..=namespace_parts.len()).rev() {
            let namespace_prefix = namespace_parts[..namespace_count].join(".");
            let prefix = [namespace_prefix.as_str(), type_prefix.as_str()]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(".");
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
    }
    prefixes
}

fn declared_type_named<'t>(
    root: Node<'t>,
    wanted: &str,
    scope: Node<'_>,
    source: &str,
) -> Option<Node<'t>> {
    let wanted = normalized_type_name(wanted);
    let wanted = wanted.strip_prefix("global::").unwrap_or(&wanted);
    let mut candidates = Vec::new();
    if wanted.contains('.') {
        candidates.push(wanted.to_string());
        let namespace = containing_namespace(scope, source);
        if !namespace.is_empty() {
            candidates.push(format!("{namespace}.{wanted}"));
        }
    } else {
        candidates.extend(
            lookup_type_prefixes(scope, source)
                .into_iter()
                .map(|prefix| {
                    if prefix.is_empty() {
                        wanted.to_string()
                    } else {
                        format!("{prefix}.{wanted}")
                    }
                }),
        );
    }
    source_type_declarations(root)
        .into_iter()
        .find(|type_node| {
            type_identity(*type_node, source)
                .is_some_and(|identity| candidates.iter().any(|candidate| candidate == &identity))
        })
}

/// Resolves a locally declared inheritance edge without recursively walking
/// the syntax tree.  A visited node identity makes malformed-but-parseable
/// cyclic declarations fail closed rather than overflow the stack.
fn derives_from(root: Node<'_>, derived: Node<'_>, base: &str, source: &str) -> bool {
    let mut pending = vec![derived];
    let mut seen = HashSet::new();
    while let Some(current) = pending.pop() {
        if !seen.insert(current.id()) {
            continue;
        }
        for base_node in base_type_nodes(current) {
            let base_text = normalized_type_name(node_text(base_node, source));
            let Some(parent) = declared_type_named(root, &base_text, current, source) else {
                continue;
            };
            if type_identity(parent, source).as_deref() == Some(base) {
                return true;
            }
            pending.push(parent);
        }
    }
    false
}

fn is_this_node(node: Node<'_>) -> bool {
    matches!(node.kind(), "this" | "this_expression")
}
fn type_pattern_node(pattern: Node<'_>) -> Option<Node<'_>> {
    (pattern.kind() == "type_pattern").then_some(pattern)
}

fn type_test_of_this(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for test in collect_kinds(root, &["is_expression", "is_pattern_expression"]) {
        let Some(pattern) = test
            .child_by_field_name("right")
            .or_else(|| test.child_by_field_name("pattern"))
        else {
            continue;
        };
        let subject = test
            .child_by_field_name("left")
            .or_else(|| test.child_by_field_name("expression"))
            .or_else(|| {
                let mut cursor = test.walk();
                test.children(&mut cursor)
                    .find(|child| is_this_node(*child))
            });
        if !subject.is_some_and(is_this_node) || is_assertion_context(test, source) {
            continue;
        }
        let checked_type = if test.kind() == "is_expression" {
            pattern
        } else if let Some(type_pattern) = type_pattern_node(pattern) {
            let Some(checked_type) = type_pattern
                .child_by_field_name("type")
                .or_else(|| first_named_child(type_pattern))
            else {
                continue;
            };
            checked_type
        } else if pattern.kind() == "constant_pattern" {
            let Some(checked_type) = first_named_child(pattern) else {
                continue;
            };
            checked_type
        } else {
            continue;
        };
        let checked_name = simple_name(node_text(checked_type, source));
        let Some(current_type) = enclosing_type(test) else {
            continue;
        };
        let Some(current_name) = type_name(current_type, source) else {
            continue;
        };
        let Some(current_identity) = type_identity(current_type, source) else {
            continue;
        };
        let checked_reference = normalized_type_name(node_text(checked_type, source));
        let Some(checked_declaration) =
            declared_type_named(root, &checked_reference, current_type, source)
        else {
            continue;
        };
        if type_identity(checked_declaration, source).as_deref() == Some(&current_identity)
            || !derives_from(root, checked_declaration, &current_identity, source)
        {
            continue;
        }
        let checked_location = type_name_node(checked_declaration).unwrap_or(checked_type);
        let current_location = type_name_node(current_type).unwrap_or(current_type);
        let mut issue = Issue::new(
            "cs/type-test-of-this",
            "Testing whether 'this' is an instance of $@ in $@ introduces a dependency cycle between the two types.",
            range_of(test, source),
        );
        issue = issue.with_flow(vec![
            FlowLocation::in_primary_file(
                checked_name.to_string(),
                range_of(checked_location, source),
            ),
            FlowLocation::in_primary_file(
                current_name.to_string(),
                range_of(current_location, source),
            ),
        ]);
        issues.push(issue);
    }
    issues
}

fn lock_guard_expression(lock: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = lock.walk();
    let mut after_paren = false;
    for child in lock.children(&mut cursor) {
        if child.kind() == "(" {
            after_paren = true;
            continue;
        }
        if !after_paren {
            continue;
        }
        if child.kind() == ")" {
            break;
        }
        if child.kind() == "comment" {
            continue;
        }
        return (child.is_named() || child.kind() == "this").then_some(child);
    }
    None
}
fn direct_block(lock: Node<'_>) -> Option<Node<'_>> {
    direct_named_children(lock)
        .into_iter()
        .find(|child| child.kind() == "block")
}
fn block_statements(block: Node<'_>) -> Vec<Node<'_>> {
    direct_named_children(block)
}

fn unsafe_sync_on_field(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for lock in collect_kinds(root, &["lock_statement"]) {
        let Some(expression) = lock_guard_expression(lock) else {
            continue;
        };
        let Some(owner) = enclosing_type(lock) else {
            continue;
        };
        let fields = fields_of(owner, source);
        let Some(field) = field_for_target(expression, owner, &fields, source) else {
            continue;
        };
        let Some(body) = direct_block(lock) else {
            continue;
        };
        for write in collect_kinds(
            body,
            &[
                "assignment_expression",
                "prefix_unary_expression",
                "postfix_unary_expression",
                "argument",
            ],
        ) {
            let Some(target) = assignment_target(write) else {
                continue;
            };
            let Some(updated) = field_for_target(target, owner, &fields, source) else {
                continue;
            };
            if updated.name != field.name {
                continue;
            }
            let mut issue = Issue::new(
                "cs/unsafe-sync-on-field",
                "Locking field $@ guards the initial value, not the value which may be seen from another thread after $@.",
                range_of(expression, source),
            );
            issue = issue.with_flow(vec![
                FlowLocation::in_primary_file(
                    field.name.to_string(),
                    range_of(field.anchor, source),
                ),
                FlowLocation::in_primary_file("reassignment", range_of(write, source)),
            ]);
            issues.push(issue);
        }
    }
    issues
}

fn catch_type<'a>(catch: Node<'a>, _source: &str) -> Option<(Node<'a>, Node<'a>)> {
    let declaration = direct_named_children(catch)
        .into_iter()
        .find(|child| child.kind() == "catch_declaration")?;
    let type_node = declaration.child_by_field_name("type")?;
    Some((declaration, type_node))
}

fn catch_type_and_name<'a>(
    catch: Node<'a>,
    source: &'a str,
) -> Option<(Node<'a>, Node<'a>, &'a str)> {
    let (declaration, type_node) = catch_type(catch, source)?;
    let name = declaration.child_by_field_name("name")?;
    Some((
        declaration,
        type_node,
        canonical_identifier(node_text(name, source)),
    ))
}

fn catch_nullreferenceexception(root: Node<'_>, source: &str) -> Vec<Issue> {
    collect_kinds(root, &["catch_clause"])
        .into_iter()
        .filter(|catch| {
            catch_type(*catch, source).is_some_and(|(_, type_node)| {
                is_known_system_type(root, *catch, type_node, "NullReferenceException", source)
            })
        })
        .map(|catch| {
            Issue::new(
                "cs/catch-nullreferenceexception",
                "Poor error handling: try to fix the cause of the 'NullReferenceException'.",
                range_of(catch, source),
            )
        })
        .collect()
}

fn rethrown_exception_variable(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for catch in collect_kinds(root, &["catch_clause"]) {
        let Some((_, type_node, caught_name)) = catch_type_and_name(catch, source) else {
            continue;
        };
        if simple_name(node_text(type_node, source)).is_empty() {
            continue;
        }
        let Some(body) = direct_block(catch) else {
            continue;
        };
        let catch_callable = enclosing_callable(catch);
        for throw in collect_kinds(body, &["throw_statement"]) {
            if enclosing_callable(throw) != catch_callable
                || ancestors_of(throw)
                    .any(|ancestor| ancestor != catch && ancestor.kind() == "catch_clause")
            {
                continue;
            }
            let Some(expression) = first_named_child(throw) else {
                continue;
            };
            if expression.kind() != "identifier"
                || canonical_identifier(node_text(expression, source)) != caught_name
            {
                continue;
            }
            issues.push(Issue::new(
                "cs/rethrown-exception-variable",
                "Rethrowing exception variable.",
                range_of(throw, source),
            ));
        }
    }
    issues
}

fn type_implements_icloneable(root: Node<'_>, type_node: Node<'_>, source: &str) -> bool {
    let mut pending = vec![type_node];
    let mut seen = HashSet::new();
    while let Some(current) = pending.pop() {
        if !seen.insert(current.id()) {
            continue;
        }
        for base_node in base_type_nodes(current) {
            let base_text = normalized_type_name(node_text(base_node, source));
            if is_known_system_type(root, current, base_node, "ICloneable", source) {
                return true;
            }
            if let Some(parent) = declared_type_named(root, &base_text, current, source) {
                pending.push(parent);
            }
        }
    }
    false
}

fn class_implements_icloneable(root: Node<'_>, source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if has_modifier(&modifiers_of(type_node, source), "sealed")
            || !type_implements_icloneable(root, type_node, source)
        {
            continue;
        }
        let has_clone = type_members(type_node).into_iter().any(|member| {
            member.kind() == "method_declaration"
                && member
                    .child_by_field_name("name")
                    .is_some_and(|name| simple_name(node_text(name, source)) == "Clone")
        });
        if !has_clone {
            continue;
        }
        let Some(name) = type_name(type_node, source) else {
            continue;
        };
        let anchor = type_node;
        issues.push(Issue::new(
            "cs/class-implements-icloneable",
            format!("Class '{name}' implements 'ICloneable'."),
            range_of(anchor, source),
        ));
    }
    issues
}

fn label_name<'a>(label: Node<'a>, source: &'a str) -> Option<(Node<'a>, &'a str)> {
    let name = label.child_by_field_name("label").or_else(|| {
        direct_named_children(label)
            .into_iter()
            .find(|child| child.kind() == "identifier")
    })?;
    (name.kind() == "identifier").then(|| (name, canonical_identifier(node_text(name, source))))
}

fn goto_label_name<'a>(goto: Node<'a>, source: &'a str) -> Option<&'a str> {
    let text = node_text(goto, source).trim_start();
    if text.strip_prefix("goto").is_some_and(|rest| {
        rest.trim_start().starts_with("case") || rest.trim_start().starts_with("default")
    }) {
        return None;
    }
    direct_named_children(goto)
        .into_iter()
        .find(|child| child.kind() == "identifier")
        .map(|name| canonical_identifier(node_text(name, source)))
}

fn unused_labels(root: Node<'_>, source: &str) -> Vec<Issue> {
    let labels = collect_kinds(root, &["labeled_statement", "label_statement"]);
    let gotos = collect_kinds(root, &["goto_statement"]);
    labels
        .into_iter()
        .filter_map(|label| {
            let (name_node, name) = label_name(label, source)?;
            let callable = enclosing_callable(label);
            let used = gotos.iter().any(|goto| {
                enclosing_callable(*goto) == callable
                    && goto_label_name(*goto, source) == Some(name)
            });
            (!used).then(|| {
                Issue::new(
                    "cs/unused-label",
                    "This label is not used.",
                    range_of(name_node, source),
                )
            })
        })
        .collect()
}

fn empty_lock_statements(root: Node<'_>, source: &str) -> Vec<Issue> {
    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter(|lock| direct_block(*lock).is_some_and(|body| block_statements(body).is_empty()))
        .map(|lock| {
            Issue::new(
                "cs/empty-lock-statement",
                "Empty lock statement.",
                range_of(lock, source),
            )
        })
        .collect()
}

fn lock_this(root: Node<'_>, source: &str) -> Vec<Issue> {
    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter_map(|lock| {
            let guard = lock_guard_expression(lock)?;
            is_this_node(guard).then(|| {
                Issue::new(
                    "cs/lock-this",
                    "'this' used in lock statement.",
                    range_of(guard, source),
                )
            })
        })
        .collect()
}

fn update_variable(update: Node<'_>) -> Option<(Node<'_>, bool)> {
    collect_kinds(
        update,
        &["prefix_unary_expression", "postfix_unary_expression"],
    )
    .into_iter()
    .find_map(|unary| {
        let mut cursor = unary.walk();
        let increment = unary
            .children(&mut cursor)
            .find_map(|child| match child.kind() {
                "++" => Some(true),
                "--" => Some(false),
                _ => None,
            })?;
        let operand = first_named_child(unary)?;
        (operand.kind() == "identifier").then_some((operand, increment))
    })
}

fn binding_declaration_before<'a>(
    use_site: Node<'a>,
    wanted: &str,
    source: &str,
) -> Option<Node<'a>> {
    let callable = enclosing_callable(use_site)?;
    let parameter = collect_kinds(callable, &["parameter"])
        .into_iter()
        .filter(|parameter| enclosing_callable(*parameter) == Some(callable))
        .find(|parameter| binding_name(*parameter, source) == Some(wanted));
    parameter.or_else(|| {
        collect_kinds(callable, &["variable_declarator"])
            .into_iter()
            .filter(|declaration| {
                belongs_to_callable(*declaration, callable)
                    && declaration.start_byte() < use_site.start_byte()
            })
            .filter(|declaration| {
                declaration_scope(*declaration)
                    .is_some_and(|scope| ancestors_of(use_site).any(|ancestor| ancestor == scope))
            })
            .filter(|declaration| binding_name(*declaration, source) == Some(wanted))
            .max_by_key(tree_sitter::Node::start_byte)
    })
}

fn resolved_binding_id(use_site: Node<'_>, wanted: &str, source: &str) -> Option<usize> {
    binding_declaration_before(use_site, wanted, source)
        .map(|declaration| declaration.id())
        .or_else(|| {
            let owner = enclosing_type(use_site)?;
            fields_of(owner, source)
                .into_iter()
                .find(|field| field.name == wanted)
                .map(|field| field.anchor.id())
        })
}

fn loop_binding<'a>(
    loop_node: Node<'a>,
    update: Node<'a>,
    source: &str,
) -> Option<(Node<'a>, usize)> {
    let (operand, _) = update_variable(update)?;
    let wanted = canonical_identifier(node_text(operand, source));
    if let Some(initializer) = for_clauses(loop_node).0
        && let Some(declaration) = collect_kinds(initializer, &["variable_declarator"])
            .into_iter()
            .find(|declaration| binding_name(*declaration, source) == Some(wanted))
    {
        return Some((operand, declaration.id()));
    }
    resolved_binding_id(operand, wanted, source).map(|id| (operand, id))
}

fn has_unguarded_access_after_inner(
    outer: Node<'_>,
    inner: Node<'_>,
    binding_id: usize,
    name: &str,
    source: &str,
) -> bool {
    let Some(body) = direct_block(outer) else {
        return false;
    };
    collect_kinds(body, &["identifier"])
        .into_iter()
        .filter(|access| access.start_byte() >= inner.end_byte())
        .filter(|access| same_callable_scope(*access, inner))
        .filter(|access| canonical_identifier(node_text(*access, source)) == name)
        .any(|access| resolved_binding_id(access, name, source) == Some(binding_id))
}

fn same_callable_scope(a: Node<'_>, b: Node<'_>) -> bool {
    enclosing_callable(a) == enclosing_callable(b)
}

fn nested_loops_with_same_variable(root: Node<'_>, source: &str) -> Vec<Issue> {
    let loops = collect_kinds(root, &["for_statement"]);
    let mut issues = Vec::new();
    for inner in &loops {
        let Some(inner_update) = for_clauses(*inner).2 else {
            continue;
        };
        let Some((inner_operand, inner_binding)) = loop_binding(*inner, inner_update, source)
        else {
            continue;
        };
        let Some(inner_increment) = update_variable(inner_update).map(|(_, increment)| increment)
        else {
            continue;
        };
        let Some(condition) = for_clauses(*inner).1 else {
            continue;
        };
        let Some((outer, _outer_condition)) = ancestors_of(*inner)
            .filter(|ancestor| {
                ancestor.kind() == "for_statement" && same_callable_scope(*inner, *ancestor)
            })
            .find_map(|outer| {
                let outer_update = for_clauses(outer).2?;
                let (_, outer_binding) = loop_binding(outer, outer_update, source)?;
                let outer_increment =
                    update_variable(outer_update).map(|(_, increment)| increment)?;
                if inner_binding != outer_binding || inner_increment != outer_increment {
                    return None;
                }
                let outer_condition = for_clauses(outer).1?;
                let same_condition = node_text(outer_condition, source).trim()
                    == node_text(condition, source).trim();
                if same_condition
                    && !has_unguarded_access_after_inner(
                        outer,
                        *inner,
                        inner_binding,
                        canonical_identifier(node_text(inner_operand, source)),
                        source,
                    )
                {
                    return None;
                }
                Some((outer, outer_condition))
            })
        else {
            continue;
        };
        let line = outer.start_position().row.saturating_add(1);
        issues.push(Issue::new(
            "cs/nested-loops-with-same-variable",
            format!(
                "Nested for statement uses loop variable {} of enclosing for statement (on line {line}).",
                canonical_identifier(node_text(inner_operand, source))
            ),
            range_of(condition, source),
        ));
    }
    issues
}
