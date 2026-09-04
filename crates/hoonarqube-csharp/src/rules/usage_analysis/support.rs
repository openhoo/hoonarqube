use crate::cst::{ancestors_of, canonical_identifier, collect_kinds, node_text, simple_name};
use crate::rules::expressions::resolved_identifier_type;
use crate::rules::modifiers::type_parameter_list_of;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::structure::CALLABLE_BODY_OWNER_KINDS;
use crate::symbol_table::{MemberSymbol, UsageSymbols};
use tree_sitter::Node;

const CLOSURE_KINDS: [&str; 2] = ["lambda_expression", "anonymous_method_expression"];

/// Nearest callable or closure that owns a node's lexical bindings.
pub(crate) fn enclosing_callable(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| {
        CALLABLE_BODY_OWNER_KINDS.contains(&ancestor.kind())
            || CLOSURE_KINDS.contains(&ancestor.kind())
    })
}

/// Descendants of `root` with the requested kind, excluding nested
/// functions and closures. Their execution and bindings are independent.
pub(crate) fn collect_in_callable<'t>(root: Node<'t>, kind: &str) -> Vec<Node<'t>> {
    let mut matches = Vec::new();
    let mut pending = vec![root];
    while let Some(node) = pending.pop() {
        if node.id() != root.id()
            && (CALLABLE_BODY_OWNER_KINDS.contains(&node.kind())
                || CLOSURE_KINDS.contains(&node.kind()))
        {
            continue;
        }
        if node.kind() == kind {
            matches.push(node);
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node> = node.children(&mut cursor).collect();
        children.reverse();
        pending.extend(children);
    }
    matches
}

pub(crate) fn enclosing_type(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
}

fn type_is_within(mut candidate: Node<'_>, owner: Node<'_>) -> bool {
    loop {
        if candidate == owner {
            return true;
        }
        let Some(parent) = ancestors_of(candidate)
            .find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
        else {
            return false;
        };
        candidate = parent;
    }
}

fn closest_named_member_owner<'t>(
    symbols: &UsageSymbols<'t>,
    mut holder: Node<'t>,
    member: &MemberSymbol<'t>,
) -> Option<Node<'t>> {
    loop {
        if symbols
            .members
            .iter()
            .any(|candidate| candidate.owner == holder && candidate.name == member.name)
        {
            return Some(holder);
        }
        if holder == member.owner {
            return None;
        }
        holder = ancestors_of(holder)
            .find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))?;
    }
}

fn is_member_access_name(reference: Node<'_>) -> Option<Node<'_>> {
    let parent = reference.parent()?;
    if parent.kind() != "member_access_expression"
        || parent.child_by_field_name("name") != Some(reference)
    {
        return None;
    }
    parent.child(0)
}

fn callable_declares_name(
    callable: Node<'_>,
    reference: Node<'_>,
    name: &str,
    source: &str,
) -> bool {
    collect_kinds(
        callable,
        &[
            "parameter",
            "variable_declarator",
            "catch_declaration",
            "local_function_statement",
        ],
    )
    .into_iter()
    .filter(|binding| enclosing_callable(*binding) == Some(callable))
    .filter_map(|binding| binding.child_by_field_name("name"))
    .any(|binding| {
        canonical_identifier(node_text(binding, source)) == name
            && binding.start_byte() <= reference.start_byte()
    })
}

fn reference_resolves_to_member(
    reference: Node<'_>,
    member: &MemberSymbol<'_>,
    symbols: &UsageSymbols<'_>,
    source: &str,
) -> bool {
    let Some(holder) = enclosing_type(reference) else {
        return false;
    };
    if !type_is_within(holder, member.owner) {
        return false;
    }
    if let Some(receiver) = is_member_access_name(reference) {
        if matches!(receiver.kind(), "this" | "this_expression") {
            return holder == member.owner;
        }
        let owner_name = member.owner.child_by_field_name("name");
        return holder == member.owner
            || receiver.kind() == "identifier"
                && owner_name.is_some_and(|name| {
                    let owner_name = canonical_identifier(node_text(name, source));
                    owner_name == canonical_identifier(node_text(receiver, source))
                        || resolved_identifier_type(receiver, source)
                            .is_some_and(|type_name| simple_name(type_name) == owner_name)
                });
    }
    if closest_named_member_owner(symbols, holder, member) != Some(member.owner) {
        return false;
    }
    !enclosing_callable(reference)
        .is_some_and(|callable| callable_declares_name(callable, reference, member.name, source))
}

/// References that can resolve to this exact member, rather than merely
/// sharing its spelling elsewhere in the file.
pub(crate) fn member_uses<'t>(
    symbols: &UsageSymbols<'t>,
    member: &MemberSymbol<'t>,
    source: &str,
) -> Vec<Node<'t>> {
    symbols
        .uses_of(member.name)
        .into_iter()
        .filter(|reference| reference_resolves_to_member(*reference, member, symbols, source))
        .collect()
}

/// Write expressions targeting this exact member.
pub(crate) fn member_writes<'t>(
    symbols: &UsageSymbols<'t>,
    member: &MemberSymbol<'t>,
    source: &str,
) -> Vec<Node<'t>> {
    symbols
        .writes_of(member.name)
        .into_iter()
        .filter(|write| {
            collect_kinds(*write, &["identifier"])
                .into_iter()
                .find(|identifier| {
                    canonical_identifier(node_text(*identifier, source)) == member.name
                })
                .is_some_and(|identifier| {
                    reference_resolves_to_member(identifier, member, symbols, source)
                })
        })
        .collect()
}

/// Uses sharing the lexical callable that owns a local declaration.
pub(crate) fn local_uses<'t>(
    symbols: &UsageSymbols<'t>,
    declaration: Node<'t>,
    name: &str,
) -> Vec<Node<'t>> {
    let Some(callable) = enclosing_callable(declaration) else {
        return Vec::new();
    };
    let span = callable.byte_range();
    symbols
        .uses_of(name)
        .into_iter()
        .filter(|use_site| {
            let site = use_site.byte_range();
            site.start >= span.start && site.end <= span.end
        })
        .collect()
}

/// Unconstrained generic parameter names of one declaration.
pub(crate) fn unconstrained_generic_parameters(
    declaration: Node<'_>,
    source: &str,
) -> Option<std::collections::HashSet<String>> {
    let (list, _) = type_parameter_list_of(declaration)?;
    let mut unconstrained: std::collections::HashSet<String> = collect_kinds(list, &["identifier"])
        .into_iter()
        .map(|identifier| node_text(identifier, source).to_string())
        .collect();
    if unconstrained.is_empty() {
        return None;
    }
    let mut cursor = declaration.walk();
    for child in declaration.children(&mut cursor) {
        if child.kind() != "type_parameter_constraints_clause" {
            continue;
        }
        let clause = node_text(child, source);
        if let Some((head, tail)) = clause.split_once(':') {
            let constrained = tail
                .split(',')
                .map(str::trim)
                .filter_map(|bound| bound.split_whitespace().next())
                .any(|bound| matches!(bound, "class" | "struct" | "notnull"));
            if !constrained {
                continue;
            }
            let Some(name) = head.split_whitespace().last() else {
                continue;
            };
            unconstrained.remove(name);
        }
    }
    (!unconstrained.is_empty()).then_some(unconstrained)
}

/// Explicitly typed variables as `(name, declared simple type)` pairs.
pub(crate) fn typed_variables<'a>(root: Node<'a>, source: &'a str) -> Vec<(&'a str, &'a str)> {
    collect_in_callable(root, "variable_declarator")
        .into_iter()
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let declaration = declarator.parent()?;
            let type_node = declaration.child_by_field_name("type")?;
            Some((
                node_text(name, source),
                simple_name(node_text(type_node, source)),
            ))
        })
        .collect()
}
