//! S1612: prove the forwarded method accepts the by-value item of a known
//! standard adapter. An identical-looking call on an owned String can borrow
//! or dereference its receiver, making the suggested method pointer ill-typed.

use super::{
    Issue, Node, node_issue, normalized_node, pattern_binds_name, s920_context_binds_name,
    standard_import_matches, standard_name_is_shadowed, text, visible_standard_imports,
};

#[derive(Clone, Copy)]
enum Item {
    Char,
    NonZeroUsize,
}

pub(super) fn check(closure: Node<'_>, source: &str, issues: &mut Vec<Issue>) {
    if proves_method_reference(closure, source).is_some() {
        issues.push(node_issue(
            "rust:S1612",
            "Replace this closure with a method reference.",
            closure,
            source,
        ));
    }
}

fn children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    (0..node.named_child_count())
        .filter_map(move |i| node.named_child(i))
        .filter(|n| !n.is_extra())
}

fn single(node: Node<'_>) -> Option<Node<'_>> {
    let mut nodes = children(node);
    let first = nodes.next()?;
    nodes.next().is_none().then_some(first)
}

fn proves_method_reference(closure: Node<'_>, source: &str) -> Option<()> {
    let parameter = single(closure.child_by_field_name("parameters")?)?;
    if parameter.kind() != "identifier" {
        return None;
    }
    let body = closure.child_by_field_name("body")?;
    if body.kind() != "call_expression"
        || children(body.child_by_field_name("arguments")?)
            .next()
            .is_some()
    {
        return None;
    }
    let callee = body.child_by_field_name("function")?;
    if callee.kind() != "field_expression" {
        return None;
    }
    let receiver = callee.child_by_field_name("value")?;
    if receiver.kind() != "identifier" || text(receiver, source) != text(parameter, source) {
        return None;
    }
    let method = text(callee.child_by_field_name("field")?, source);
    if method != "get" && !char_value_method(method) {
        return None;
    }
    let args = closure.parent()?;
    if args.kind() != "arguments" {
        return None;
    }
    let adapter = args.parent()?.child_by_field_name("function")?;
    if adapter.kind() != "field_expression" {
        return None;
    }
    let name = text(adapter.child_by_field_name("field")?, source);
    let mut arguments = children(args);
    if name == "map_or" {
        arguments.next()?;
    } else if name != "map" {
        return None;
    }
    if arguments.next()? != closure || arguments.next().is_some() {
        return None;
    }
    let carrier = adapter.child_by_field_name("value")?;
    let item = if carrier.kind() == "identifier" {
        binding_item(carrier, source)?
    } else {
        constructor_item(carrier, source)?
    };
    match item {
        Item::Char => char_value_method(method),
        Item::NonZeroUsize => method == "get",
    }
    .then_some(())
}

// No-argument inherent methods whose first argument is exactly `char` by
// value. In particular, ASCII predicates take `&char` and are not included.
fn char_value_method(name: &str) -> bool {
    matches!(
        name,
        "to_uppercase"
            | "to_lowercase"
            | "is_alphabetic"
            | "is_alphanumeric"
            | "is_control"
            | "is_lowercase"
            | "is_numeric"
            | "is_uppercase"
            | "is_whitespace"
            | "len_utf8"
            | "len_utf16"
            | "escape_debug"
            | "escape_default"
            | "escape_unicode"
    )
}

fn constructor_item(call: Node<'_>, source: &str) -> Option<Item> {
    if call.kind() != "call_expression" {
        return None;
    }
    let name = call.child_by_field_name("function")?;
    let args = call.child_by_field_name("arguments")?;
    if children(args).next().is_none()
        && known_path(name, source, &["std::thread::available_parallelism"], None)
    {
        return Some(Item::NonZeroUsize);
    }
    let inner = single(args)?;
    (inner.kind() == "char_literal"
        && known_path(
            name,
            source,
            &["std::option::Option::Some", "core::option::Option::Some"],
            Some("Some"),
        ))
    .then_some(Item::Char)
}

fn option_item(ty: Node<'_>, source: &str) -> Option<Item> {
    if ty.kind() != "generic_type"
        || !known_path(
            ty.child_by_field_name("type")?,
            source,
            &["std::option::Option", "core::option::Option"],
            Some("Option"),
        )
    {
        return None;
    }
    let arg = single(ty.child_by_field_name("type_arguments")?)?;
    if arg.kind() == "primitive_type"
        && text(arg, source) == "char"
        && !visible_standard_imports(arg, source)
            .iter()
            .any(|(alias, _)| alias == "char")
        && !ambiguous_item(arg, "char", source)
        && !standard_name_is_shadowed(arg, "char", source, false)
    {
        return Some(Item::Char);
    }
    known_path(
        arg,
        source,
        &["std::num::NonZeroUsize", "core::num::NonZeroUsize"],
        None,
    )
    .then_some(Item::NonZeroUsize)
}

fn binding_item(site: Node<'_>, source: &str) -> Option<Item> {
    let name = text(site, source);
    let mut child = site;
    while let Some(parent) = child.parent() {
        if parent.kind() == "block"
            && let Some(decl) = previous_binding(child, name, source)
        {
            return declared_item(decl, source);
        }
        if parent.kind() == "function_item" {
            let params = parent.child_by_field_name("parameters")?;
            let p = children(params).find(|p| {
                p.child_by_field_name("pattern")
                    .is_some_and(|n| n.kind() == "identifier" && text(n, source) == name)
            })?;
            return option_item(p.child_by_field_name("type")?, source);
        }
        if parent.kind() == "closure_expression"
            || s920_context_binds_name(parent, site, name, source)
        {
            return None;
        }
        child = parent;
    }
    None
}

// A matching pattern stops lookup even when its type is unknown. Falling
// through would pick up a shadowed binding from an outer scope.
fn previous_binding<'a>(child: Node<'a>, name: &str, source: &str) -> Option<Node<'a>> {
    std::iter::successors(child.prev_named_sibling(), Node::prev_named_sibling).find(|sibling| {
        sibling.kind() == "let_declaration"
            && sibling
                .child_by_field_name("pattern")
                .is_some_and(|pattern| pattern_binds_name(pattern, name, source))
    })
}

fn declared_item(decl: Node<'_>, source: &str) -> Option<Item> {
    if decl.child_by_field_name("pattern")?.kind() != "identifier" {
        return None;
    }
    if let Some(ty) = decl.child_by_field_name("type") {
        option_item(ty, source)
    } else {
        constructor_item(decl.child_by_field_name("value")?, source)
    }
}

fn known_path(node: Node<'_>, source: &str, paths: &[&str], prelude: Option<&str>) -> bool {
    let spelling = normalized_node(node, source);
    let root = spelling
        .trim_start_matches("::")
        .split("::")
        .next()
        .unwrap_or("");
    let absolute = spelling.starts_with("::");
    if !absolute && ambiguous_item(node, root, source) {
        return false;
    }
    let imports = visible_standard_imports(node, source);
    let mut candidates = imports.iter().filter(|(alias, _)| alias == root);
    let imported = candidates.next();
    if !absolute && let Some((_, path)) = imported {
        let import_root = path.split("::").next().unwrap_or_default();
        if matches!(root, "std" | "core")
            || candidates.any(|(_, other)| other != path)
            || ambiguous_item(node, import_root, source)
            || standard_name_is_shadowed(node, import_root, source, true)
            || imports.iter().any(|(alias, _)| alias == import_root)
        {
            return false;
        }
    }
    (prelude == Some(spelling.as_str())
        && imported.is_none()
        && !standard_name_is_shadowed(node, root, source, false))
        || standard_import_matches(node, source, paths)
}

// Items are visible even before their declaration. A glob can introduce names
// that this file does not define, so a source-only pass cannot resolve it.
fn ambiguous_item(node: Node<'_>, name: &str, source: &str) -> bool {
    std::iter::successors(node.parent(), Node::parent).any(|scope| {
        if scope
            .child_by_field_name("type_parameters")
            .is_some_and(|params| {
                children(params).any(|p| {
                    p.child_by_field_name("name")
                        .is_some_and(|n| text(n, source) == name)
                })
            })
        {
            return true;
        }
        if !matches!(scope.kind(), "source_file" | "block" | "declaration_list") {
            return false;
        }
        children(scope).any(|item| {
            (item.kind().ends_with("_item")
                && item
                    .child_by_field_name("name")
                    .is_some_and(|n| text(n, source) == name))
                || (item.kind() == "use_declaration" && normalized_node(item, source).contains('*'))
        })
    })
}
