use super::support::{ParameterUnit, local_type_declarations, local_type_table, parameter_units};
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text,
    range_from_byte_offsets, range_of,
};
use crate::project_index::{ProjectTypeIndex, indexed_parameters};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::{has_modifier, type_parameter_list_of};
use crate::rules::naming::support::full_type_identity;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1006 — overrides adding, changing, or dropping a default
/// parameter value. Compiler-compatible local subset: class overrides and
/// file-local interface implementations, plus cross-file base classes when
/// a [`ProjectTypeIndex`] is supplied. Missing defaults and
/// explicit-interface defaults use the same bound parameter identity as
/// the compiler helper.
#[derive(Clone, Copy)]
enum PairKind {
    Override,
    ImplicitInterface,
    ExplicitInterface,
}
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut pairs = local_override_pairs(root, source)
        .into_iter()
        .map(|(method, base)| (method, base, PairKind::Override))
        .collect::<Vec<_>>();
    pairs.extend(interface_pairs(root, source));
    for (overriding, base, pair_kind) in pairs {
        let Some(difference) = first_default_difference_range(pair_kind, overriding, base, source)
        else {
            continue;
        };
        issues.push(issue(
            language,
            "S1006",
            difference.message(),
            difference.range,
        ));
    }
    issues.extend(cross_file_override_issues(
        root,
        source,
        language,
        options.project_type_index.as_deref(),
    ));
    issues
}

/// One default-value divergence: the anchor range plus the message the
/// reference platform emits for that divergence shape.
struct DefaultDifference {
    range: hoonarqube_ir::Range,
    kind: DefaultDifferenceKind,
}

enum DefaultDifferenceKind {
    Add,
    Use,
    Remove,
}

impl DefaultDifference {
    fn message(&self) -> &'static str {
        match self.kind {
            DefaultDifferenceKind::Add => {
                "Add the default parameter value defined in the overridden method."
            }
            DefaultDifferenceKind::Use => {
                "Use the default parameter value defined in the overridden method."
            }
            DefaultDifferenceKind::Remove => {
                "Remove the default parameter value to match the signature of overridden method."
            }
        }
    }
}

/// S1006 local overrides paired with the same direct-base signature.
/// Method type parameters use declaration position; containing parameters
/// use the written direct-base arguments in the derived type's scope.
fn local_override_pairs<'t>(root: Node<'t>, source: &'t str) -> Vec<(Node<'t>, Node<'t>)> {
    let types = local_type_table(root, source);
    let mut pairs = Vec::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(base_name) = base_simple_names(declaration, source).first().copied() else {
            continue;
        };
        let Some(base) = types.get(base_name).copied() else {
            continue;
        };
        let derived_bindings = local_type_parameter_names(declaration, source)
            .into_iter()
            .enumerate()
            .map(|(position, name)| (name, format!("$local-type:{position}")))
            .collect::<std::collections::HashMap<_, _>>();
        let Some(base_bindings) = local_base_bindings(declaration, base, source, &derived_bindings)
        else {
            continue;
        };
        let base_methods = member_declarations_of_kind(base, "method_declaration");
        for method in member_declarations_of_kind(declaration, "method_declaration") {
            if let Some(candidate) = local_override_base(
                method,
                &base_methods,
                source,
                &derived_bindings,
                &base_bindings,
            ) {
                pairs.push((method, candidate));
            }
        }
    }
    pairs
}

fn local_override_base<'t>(
    method: Node<'t>,
    candidates: &[Node<'t>],
    source: &str,
    derived_bindings: &std::collections::HashMap<String, String>,
    base_bindings: &std::collections::HashMap<String, String>,
) -> Option<Node<'t>> {
    if !has_modifier(&modifiers_of(method, source), "override") {
        return None;
    }
    let name = node_text(method.child_by_field_name("name")?, source);
    let arity = type_parameter_list_of(method).map_or(0, |(_, count)| count);
    let parameters = local_signature_parameters(method, source, derived_bindings)?;
    candidates.iter().copied().find(|candidate| {
        candidate
            .child_by_field_name("name")
            .is_some_and(|base_name| {
                node_text(base_name, source) == name
                    && type_parameter_list_of(*candidate).map_or(0, |(_, count)| count) == arity
                    && local_signature_parameters(*candidate, source, base_bindings).is_some_and(
                        |base| {
                            same_signature(&parameters.parameters, &base.parameters)
                                && local_identity_pair_eligible(
                                    method,
                                    *candidate,
                                    source,
                                    parameters.uncertain_identity || base.uncertain_identity,
                                )
                        },
                    )
            })
    })
}

fn local_type_parameter_names(declaration: Node<'_>, source: &str) -> Vec<String> {
    let Some((list, _)) = type_parameter_list_of(declaration) else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    list.named_children(&mut cursor)
        .filter(|child| child.kind() == "type_parameter")
        .filter_map(|parameter| parameter.child_by_field_name("name"))
        .map(|name| node_text(name, source).trim_start_matches('@').to_string())
        .collect()
}

fn local_base_bindings(
    declaration: Node<'_>,
    base: Node<'_>,
    source: &str,
    derived_bindings: &std::collections::HashMap<String, String>,
) -> Option<std::collections::HashMap<String, String>> {
    let names = local_type_parameter_names(base, source);
    let mut cursor = declaration.walk();
    let list = declaration
        .named_children(&mut cursor)
        .find(|child| child.kind() == "base_list")?;
    let mut list_cursor = list.walk();
    let first = list.named_children(&mut list_cursor).next()?;
    let mut base_type = first.child_by_field_name("type").unwrap_or(first);
    while matches!(base_type.kind(), "qualified_name" | "alias_qualified_name") {
        base_type = base_type.child_by_field_name("name")?;
    }
    let mut type_cursor = base_type.walk();
    let arguments = base_type
        .named_children(&mut type_cursor)
        .find(|child| child.kind() == "type_argument_list")
        .map(|list| {
            let mut cursor = list.walk();
            list.named_children(&mut cursor)
                .filter(|child| child.kind() != "comment")
                .map(|argument| local_type_key(argument, source, derived_bindings))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    (names.len() == arguments.len()).then(|| names.into_iter().zip(arguments).collect())
}

struct LocalSignature {
    parameters: Vec<crate::project_index::IndexedParameter>,
    uncertain_identity: bool,
}

fn local_signature_parameters(
    method: Node<'_>,
    source: &str,
    type_bindings: &std::collections::HashMap<String, String>,
) -> Option<LocalSignature> {
    let mut bindings = type_bindings.clone();
    for (position, name) in local_type_parameter_names(method, source)
        .into_iter()
        .enumerate()
    {
        bindings.insert(name, format!("$local-method:{position}"));
    }
    let types = local_parameter_type_nodes(method);
    let mut parameters = indexed_parameters(method, source);
    if parameters.len() != types.len() {
        return None;
    }
    let mut uncertain_identity = false;
    for (parameter, node) in parameters.iter_mut().zip(types) {
        let node = node?;
        parameter.type_key = local_type_key(node, source, &bindings);
        uncertain_identity |= local_uncertain_parameter_type(node, source, &bindings);
    }
    Some(LocalSignature {
        parameters,
        uncertain_identity,
    })
}

/// Legacy Add/Use comparison stays available for unproven type identities;
/// a new Remove requires a signature whose identity is established locally.
fn local_identity_pair_eligible(
    method: Node<'_>,
    base: Node<'_>,
    source: &str,
    uncertain_identity: bool,
) -> bool {
    !uncertain_identity
        || first_default_difference_range(PairKind::Override, method, base, source)
            .is_none_or(|difference| !matches!(difference.kind, DefaultDifferenceKind::Remove))
}

fn local_uncertain_parameter_type(
    node: Node<'_>,
    source: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> bool {
    collect_kinds(
        node,
        &[
            "nullable_type",
            "generic_name",
            "identifier",
            "qualified_name",
            "alias_qualified_name",
        ],
    )
    .into_iter()
    .any(|part| local_uncertain_type_component(part, source, bindings))
}

fn local_uncertain_type_component(
    node: Node<'_>,
    source: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> bool {
    if node.kind() == "generic_name" {
        return true;
    }
    if node.kind() == "nullable_type" {
        let Some(inner) = node.child_by_field_name("type") else {
            return true;
        };
        let rendered = local_render_type(inner, source, bindings, None, 0);
        return local_nullable_value_kind(inner, source, &rendered).is_none();
    }
    if node.kind() == "identifier" && !local_type_parameter_identifier(node) {
        return false;
    }
    let rendered = local_render_type(node, source, bindings, None, 0);
    ![
        "$local-method:",
        "$local-type:",
        "$local-bcl:",
        "$local-named:",
        "global::",
    ]
    .iter()
    .any(|prefix| rendered.starts_with(prefix))
}

/// Known local value declarations and BCL scalar identities prove whether
/// `?` changes the parameter type. Unknown named/generic types stay unknown.
fn local_nullable_value_kind(inner: Node<'_>, source: &str, rendered: &str) -> Option<bool> {
    if let Some(scalar) = rendered.strip_prefix("$local-bcl:") {
        return Some(!matches!(scalar, "Object" | "String"));
    }
    if inner.kind() == "tuple_type" {
        return Some(true);
    }
    if inner.kind() == "array_type" {
        return Some(false);
    }
    let path = rendered.strip_prefix("$local-named:")?;
    let root = crate::cst::ancestors_of(inner).last().unwrap_or(inner);
    collect_kinds(root, &crate::rules::naming::support::TYPE_DECLARATION_KINDS)
        .into_iter()
        .find(|declaration| full_type_identity(*declaration, source).as_deref() == Some(path))
        .and_then(|declaration| match declaration.kind() {
            "struct_declaration" | "enum_declaration" => Some(true),
            "class_declaration" | "interface_declaration" => Some(false),
            _ => None,
        })
}

/// Keep the shared signature grouping, including flattened `params T name`.
fn local_parameter_type_nodes(method: Node<'_>) -> Vec<Option<Node<'_>>> {
    let Some(list) = method.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    let mut groups = vec![Vec::new()];
    for child in list.children(&mut cursor) {
        if child.kind() == "," {
            groups.push(Vec::new());
        } else if let Some(group) = groups.last_mut() {
            group.push(child);
        }
    }
    groups
        .into_iter()
        .filter(|group| group.iter().any(Node::is_named))
        .map(|mut group| {
            let flattened = group.iter().any(|child| child.kind() == "params");
            group.retain(Node::is_named);
            if !flattened
                && let [only] = group.as_slice()
                && only.kind() == "parameter"
            {
                only.child_by_field_name("type")
            } else {
                group.into_iter().find(|child| child.kind() != "identifier")
            }
        })
        .collect()
}

/// Replace only unqualified type-position identifiers. Qualified member
/// names, generic type names and tuple element names remain concrete text.
fn local_type_key(
    type_node: Node<'_>,
    source: &str,
    bindings: &std::collections::HashMap<String, String>,
) -> String {
    crate::cst::normalize_type_key(&local_render_type(type_node, source, bindings, None, 0))
}

/// Render the signature-local identity recursively so composite types keep
/// their shape while scalar spellings and scoped aliases share one identity.
fn local_render_type(
    node: Node<'_>,
    source: &str,
    bindings: &std::collections::HashMap<String, String>,
    blocked_alias_scope: Option<Node<'_>>,
    depth: usize,
) -> String {
    if depth > 16 {
        return node_text(node, source).to_string();
    }
    if let Some(replacement) =
        local_type_replacement(node, source, bindings, blocked_alias_scope, depth)
    {
        return replacement;
    }
    let mut rendered = String::new();
    let mut cursor = node.start_byte();
    let mut walk = node.walk();
    for child in node.children(&mut walk) {
        rendered.push_str(&source[cursor..child.start_byte()]);
        rendered.push_str(&local_render_type(
            child,
            source,
            bindings,
            blocked_alias_scope,
            depth,
        ));
        cursor = child.end_byte();
    }
    rendered.push_str(&source[cursor..node.end_byte()]);
    rendered
}

fn local_type_replacement(
    node: Node<'_>,
    source: &str,
    bindings: &std::collections::HashMap<String, String>,
    blocked_alias_scope: Option<Node<'_>>,
    depth: usize,
) -> Option<String> {
    if node.kind() == "nullable_type" {
        let inner = node.child_by_field_name("type")?;
        let rendered = local_render_type(inner, source, bindings, blocked_alias_scope, depth);
        if local_nullable_value_kind(inner, source, &rendered) == Some(true) {
            return Some(format!("$local-nullable<{rendered}>"));
        }
    }
    if node.kind() == "predefined_type" {
        return local_bcl_scalar(node_text(node, source))
            .map(|scalar| format!("$local-bcl:{scalar}"));
    }
    if node.kind() == "identifier" && local_type_parameter_identifier(node) {
        let name = node_text(node, source).trim_start_matches('@');
        if let Some(replacement) = bindings.get(name) {
            return Some(replacement.clone());
        }
        if let Some((target, scope)) = local_alias_target(node, source, name, blocked_alias_scope) {
            return Some(local_render_type(
                target,
                source,
                &std::collections::HashMap::new(),
                Some(scope),
                depth + 1,
            ));
        }
    }
    if node.kind() == "identifier" && !local_type_parameter_identifier(node) {
        return None;
    }
    if !matches!(
        node.kind(),
        "identifier" | "qualified_name" | "alias_qualified_name"
    ) {
        return None;
    }
    let (path, absolute, aliased) = local_named_path(node, source, blocked_alias_scope, depth)?;
    if let Some(scalar) = local_bcl_scalar(&path)
        && (absolute || !bindings.contains_key("System"))
        && !local_declares_system_scalar(node, source, &path)
    {
        return Some(format!("$local-bcl:{scalar}"));
    }
    if (absolute || aliased) && local_declares_type(node, source, &path) {
        return Some(format!("$local-named:{path}"));
    }
    aliased.then_some(path)
}

fn local_bcl_scalar(path: &str) -> Option<&'static str> {
    Some(match path {
        "bool" | "System.Boolean" => "Boolean",
        "byte" | "System.Byte" => "Byte",
        "char" | "System.Char" => "Char",
        "decimal" | "System.Decimal" => "Decimal",
        "double" | "System.Double" => "Double",
        "float" | "System.Single" => "Single",
        "int" | "System.Int32" => "Int32",
        "long" | "System.Int64" => "Int64",
        "object" | "System.Object" => "Object",
        "sbyte" | "System.SByte" => "SByte",
        "short" | "System.Int16" => "Int16",
        "string" | "System.String" => "String",
        "uint" | "System.UInt32" => "UInt32",
        "ulong" | "System.UInt64" => "UInt64",
        "ushort" | "System.UInt16" => "UInt16",
        "nint" | "System.IntPtr" => "IntPtr",
        "nuint" | "System.UIntPtr" => "UIntPtr",
        _ => return None,
    })
}

/// Resolve only an alias used as the leading named-type segment. Every
/// candidate is drawn from a direct using directive in a lexical ancestor.
fn local_named_path(
    node: Node<'_>,
    source: &str,
    blocked_alias_scope: Option<Node<'_>>,
    depth: usize,
) -> Option<(String, bool, bool)> {
    if depth > 16 || node_text(node, source).contains('<') {
        return None;
    }
    let written = crate::cst::normalize_type_key(node_text(node, source)).replace('@', "");
    let absolute = written.starts_with("global::");
    let path = written
        .strip_prefix("global::")
        .unwrap_or(&written)
        .replace("::", ".");
    let (first, suffix) = path
        .split_once('.')
        .map_or((path.as_str(), ""), |(first, suffix)| (first, suffix));
    if absolute {
        return Some((path, true, false));
    }
    let Some((target, alias_scope)) = local_alias_target(node, source, first, blocked_alias_scope)
    else {
        if first == "System"
            && let Some(shadow) = local_shadowed_system_namespace(node, source)
        {
            let expanded = if suffix.is_empty() {
                shadow
            } else {
                format!("{shadow}.{suffix}")
            };
            return Some((expanded, false, true));
        }
        if suffix.is_empty()
            && let Some(local) = local_visible_type(node, source, first, blocked_alias_scope)
        {
            return Some((local, false, true));
        }
        return Some((path, absolute, false));
    };
    let (target_path, target_absolute, _) =
        local_named_path(target, source, Some(alias_scope), depth + 1)?;
    let expanded = if suffix.is_empty() {
        target_path
    } else {
        format!("{target_path}.{suffix}")
    };
    Some((expanded, target_absolute, true))
}

fn local_alias_target<'t>(
    node: Node<'t>,
    source: &str,
    alias_name: &str,
    blocked_scope: Option<Node<'t>>,
) -> Option<(Node<'t>, Node<'t>)> {
    for scope in crate::cst::ancestors_of(node).filter(|ancestor| {
        matches!(
            ancestor.kind(),
            "compilation_unit"
                | "declaration_list"
                | "namespace_declaration"
                | "file_scoped_namespace_declaration"
        )
    }) {
        if blocked_scope == Some(scope) {
            continue;
        }
        if let Some(target) = local_scope_alias(scope, source, alias_name) {
            return Some((target, scope));
        }
    }
    None
}

fn local_scope_alias<'t>(scope: Node<'t>, source: &str, alias_name: &str) -> Option<Node<'t>> {
    let mut walk = scope.walk();
    scope
        .named_children(&mut walk)
        .filter(|child| child.kind() == "using_directive")
        .find_map(|directive| {
            let name = directive.child_by_field_name("name")?;
            if node_text(name, source).trim_start_matches('@') != alias_name {
                return None;
            }
            let mut children = directive.walk();
            let named = directive
                .named_children(&mut children)
                .filter(|child| *child != name && child.kind() != "comment")
                .collect::<Vec<_>>();
            let target = *named.last()?;
            let between = &source[name.end_byte()..target.start_byte()];
            between.contains('=').then_some(target)
        })
}

fn local_shadowed_system_namespace(node: Node<'_>, source: &str) -> Option<String> {
    for declaration in crate::cst::ancestors_of(node).filter(|ancestor| {
        crate::rules::naming::support::TYPE_DECLARATION_KINDS.contains(&ancestor.kind())
    }) {
        if let Some(candidate) = local_nested_type(declaration, source, "System") {
            return Some(candidate);
        }
    }
    let namespace = crate::cst::containing_namespace(node, source);
    let mut prefixes = namespace.split('.').collect::<Vec<_>>();
    loop {
        let candidate = if prefixes.is_empty() {
            "System".to_string()
        } else {
            format!("{}.System", prefixes.join("."))
        };
        if (candidate != "System" && local_declares_namespace(node, source, &candidate))
            || local_declares_type(node, source, &candidate)
        {
            return Some(candidate);
        }
        prefixes.pop()?;
    }
}

/// Follow the same first file-local base admitted by the override selector.
/// The declaration count bounds malformed/cyclic inheritance chains.
fn local_nested_type<'t>(mut declaration: Node<'t>, source: &'t str, name: &str) -> Option<String> {
    let root = crate::cst::ancestors_of(declaration)
        .last()
        .unwrap_or(declaration);
    let types = local_type_table(root, source);
    for _ in 0..=types.len() {
        let candidate = format!("{}.{name}", full_type_identity(declaration, source)?);
        if local_declares_type(root, source, &candidate) {
            return Some(candidate);
        }
        let base_name = base_simple_names(declaration, source).first().copied()?;
        declaration = *types.get(base_name)?;
    }
    None
}

/// Resolve bare names only to actual file-local declarations visible through
/// enclosing types, namespaces, or one unambiguous namespace import.
fn local_visible_type(
    node: Node<'_>,
    source: &str,
    name: &str,
    blocked_scope: Option<Node<'_>>,
) -> Option<String> {
    crate::cst::ancestors_of(node)
        .find_map(|scope| local_scope_visible_type(scope, source, name, blocked_scope))
}

fn local_scope_visible_type(
    scope: Node<'_>,
    source: &str,
    name: &str,
    blocked_scope: Option<Node<'_>>,
) -> Option<String> {
    if crate::rules::naming::support::TYPE_DECLARATION_KINDS.contains(&scope.kind()) {
        return local_nested_type(scope, source, name);
    }
    if !matches!(scope.kind(), "declaration_list" | "compilation_unit") {
        return None;
    }
    let namespace = crate::cst::containing_namespace(scope, source);
    let candidate = if namespace.is_empty() {
        name.to_string()
    } else {
        format!("{namespace}.{name}")
    };
    if local_declares_type(scope, source, &candidate) {
        return Some(candidate);
    }
    (blocked_scope != Some(scope))
        .then(|| local_scope_imported_type(scope, source, name))
        .flatten()
}

fn local_scope_imported_type(scope: Node<'_>, source: &str, name: &str) -> Option<String> {
    let mut walk = scope.walk();
    let candidates = scope
        .named_children(&mut walk)
        .filter(|child| child.kind() == "using_directive")
        .filter_map(|directive| local_namespace_import(directive, source))
        .map(|namespace| format!("{namespace}.{name}"))
        .filter(|candidate| local_declares_type(scope, source, candidate))
        .collect::<std::collections::BTreeSet<_>>();
    (candidates.len() == 1)
        .then(|| candidates.into_iter().next())
        .flatten()
}

fn local_namespace_import(directive: Node<'_>, source: &str) -> Option<String> {
    if directive.child_by_field_name("name").is_some() {
        return None;
    }
    let mut walk = directive.walk();
    if directive
        .children(&mut walk)
        .any(|child| child.kind() == "static")
    {
        return None;
    }
    let mut walk = directive.walk();
    let target = directive
        .named_children(&mut walk)
        .find(|child| child.kind() != "comment")?;
    let written = crate::cst::normalize_type_key(node_text(target, source)).replace('@', "");
    if let Some(absolute) = written.strip_prefix("global::") {
        return Some(absolute.to_string());
    }
    let namespace = crate::cst::containing_namespace(directive, source);
    let mut prefixes = namespace
        .split('.')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    loop {
        let candidate = if prefixes.is_empty() {
            written.clone()
        } else {
            format!("{}.{written}", prefixes.join("."))
        };
        if local_declares_namespace(directive, source, &candidate) {
            return Some(candidate);
        }
        prefixes.pop()?;
    }
}

fn local_declares_namespace(node: Node<'_>, source: &str, expected: &str) -> bool {
    let root = crate::cst::ancestors_of(node).last().unwrap_or(node);
    collect_kinds(
        root,
        &["namespace_declaration", "file_scoped_namespace_declaration"],
    )
    .into_iter()
    .any(|declaration| {
        let Some(name) = declaration.child_by_field_name("name") else {
            return false;
        };
        let declared = node_text(name, source).replace('@', "");
        let prefix = crate::cst::containing_namespace(declaration, source);
        let full = if prefix.is_empty() {
            declared
        } else {
            format!("{prefix}.{declared}")
        };
        full == expected || full.starts_with(&format!("{expected}."))
    })
}

fn local_declares_system_scalar(node: Node<'_>, source: &str, path: &str) -> bool {
    if !path.starts_with("System.") {
        return false;
    }
    local_declares_type(node, source, path)
}

fn local_declares_type(node: Node<'_>, source: &str, path: &str) -> bool {
    let root = crate::cst::ancestors_of(node).last().unwrap_or(node);
    collect_kinds(root, &crate::rules::naming::support::TYPE_DECLARATION_KINDS)
        .into_iter()
        .any(|declaration| full_type_identity(declaration, source).as_deref() == Some(path))
}

fn local_type_parameter_identifier(identifier: Node<'_>) -> bool {
    identifier.parent().is_none_or(|parent| {
        !(matches!(
            parent.kind(),
            "qualified_name" | "alias_qualified_name" | "generic_name"
        ) || parent.kind() == "tuple_element"
            && parent.child_by_field_name("name") == Some(identifier))
    })
}

/// Overrides whose base class lives in another indexed file: the project
/// index supplies the base signatures (including written defaults) that a
/// per-file pass cannot see. File-local bases stay on the CST path above,
/// and the querying type's own partial declarations never count as bases.
fn cross_file_override_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    project: Option<&ProjectTypeIndex>,
) -> Vec<Issue> {
    let Some(project) = project else {
        return Vec::new();
    };
    let types = local_type_table(root, source);
    let mut issues = Vec::new();
    for declaration in local_type_declarations(root) {
        if declaration.kind() != "class_declaration" || is_error_tainted(declaration) {
            continue;
        }
        let Some(base_name) = base_simple_names(declaration, source).first().copied() else {
            continue;
        };
        if types.contains_key(base_name) {
            continue;
        }
        for method in member_declarations_of_kind(declaration, "method_declaration") {
            issues.extend(indexed_override_issue(
                declaration,
                method,
                base_name,
                source,
                language,
                project,
            ));
        }
    }
    issues
}

/// The S1006 issue one override earns against the indexed bases of
/// `base_name`, skipping the querying type's own partial declarations and
/// interface bases.
fn indexed_override_issue(
    declaration: Node<'_>,
    method: Node<'_>,
    base_name: &str,
    source: &str,
    language: CsLanguage,
    project: &ProjectTypeIndex,
) -> Option<Issue> {
    if is_error_tainted(method) || !has_modifier(&modifiers_of(method, source), "override") {
        return None;
    }
    let name = method.child_by_field_name("name")?;
    let own_identity = full_type_identity(declaration, source);
    let own_arity = type_parameter_list_of(declaration).map_or(0, |(_, count)| count);
    let derived = indexed_parameters(method, source);
    let units = parameter_units(method, source);
    project
        .same_name_methods(base_name, node_text(name, source))
        .into_iter()
        .filter(|(base_type, _)| {
            !base_type.is_interface
                && (Some(base_type.identity.as_str()) != own_identity.as_deref()
                    || base_type.arity != own_arity)
        })
        .filter(|(_, base_method)| same_signature(&derived, &base_method.parameters))
        .find_map(|(_, base_method)| {
            indexed_default_difference(&units, &derived, &base_method.parameters, source)
        })
        .map(|difference| issue(language, "S1006", difference.message(), difference.range))
}

/// Whether an override's normalized signature equals the indexed base
/// signature exactly (`ref`-kind and type key per position).
fn same_signature(
    derived: &[crate::project_index::IndexedParameter],
    base: &[crate::project_index::IndexedParameter],
) -> bool {
    derived.len() == base.len()
        && derived
            .iter()
            .zip(base.iter())
            .all(|(left, right)| left.ref_kind == right.ref_kind && left.type_key == right.type_key)
}

/// The first default-value divergence between an override's CST
/// parameters and its indexed base parameters: a dropped default anchors
/// the parameter name, a changed default anchors the written value, and an
/// added default anchors the complete default clause.
fn indexed_default_difference(
    units: &[ParameterUnit<'_>],
    derived: &[crate::project_index::IndexedParameter],
    base: &[crate::project_index::IndexedParameter],
    source: &str,
) -> Option<DefaultDifference> {
    let removal_eligible = indexed_remove_signature_proven(derived, base);
    units.iter().zip(derived.iter().zip(base.iter())).find_map(
        |(unit, (derived_parameter, base_parameter))| {
            let derived_default = unit
                .default_value
                .map(|value| node_text(value, source))
                .map(|text| {
                    text.chars()
                        .filter(|c| !c.is_whitespace())
                        .collect::<String>()
                })
                .or_else(|| derived_parameter.default_value.clone());
            match (unit.default_value, &base_parameter.default_value) {
                (None, Some(_)) => unit.name.map(|name| DefaultDifference {
                    range: range_of(name, source),
                    kind: DefaultDifferenceKind::Add,
                }),
                (Some(value), None) if removal_eligible => Some(DefaultDifference {
                    range: default_clause_range(value, source),
                    kind: DefaultDifferenceKind::Remove,
                }),
                (Some(value), Some(base_value)) if Some(base_value) != derived_default.as_ref() => {
                    Some(DefaultDifference {
                        range: range_of(value, source),
                        kind: DefaultDifferenceKind::Use,
                    })
                }
                _ => None,
            }
        },
    )
}

/// The index keeps written types but no lexical scope for aliases or names.
/// Only matching keyword scalar identities can justify a new indexed Remove;
/// legacy Add/Use differences still run when that proof is unavailable.
fn indexed_remove_signature_proven(
    derived: &[crate::project_index::IndexedParameter],
    base: &[crate::project_index::IndexedParameter],
) -> bool {
    derived.len() == base.len()
        && derived.iter().zip(base).all(|(left, right)| {
            indexed_keyword_type_key(&left.display)
                .zip(indexed_keyword_type_key(&right.display))
                .is_some_and(|(left, right)| left == right)
        })
}

fn indexed_keyword_type_key(display: &str) -> Option<String> {
    let written = display
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();
    let (keyword, nullable) = written
        .strip_suffix('?')
        .map_or((written.as_str(), false), |inner| (inner, true));
    if keyword.contains('.') || keyword.contains(':') {
        return None;
    }
    let scalar = local_bcl_scalar(keyword)?;
    if nullable && !matches!(scalar, "Object" | "String") {
        Some(format!("$indexed-nullable:{scalar}"))
    } else {
        Some(scalar.to_string())
    }
}

fn first_default_difference_range(
    pair_kind: PairKind,
    overriding: Node<'_>,
    base: Node<'_>,
    source: &str,
) -> Option<DefaultDifference> {
    let overriding_parameters = parameter_units(overriding, source);
    let base_parameters = parameter_units(base, source);
    overriding_parameters
        .iter()
        .zip(base_parameters.iter())
        .find_map(|(unit, base_unit)| default_difference_range(pair_kind, unit, base_unit, source))
}

fn default_difference_range(
    pair_kind: PairKind,
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<DefaultDifference> {
    match pair_kind {
        PairKind::ExplicitInterface => unit.default_value.map(|value| DefaultDifference {
            range: default_clause_range(value, source),
            kind: DefaultDifferenceKind::Use,
        }),
        PairKind::ImplicitInterface => interface_default_difference(unit, base_unit, source),
        PairKind::Override => override_default_difference(unit, base_unit, source),
    }
}

fn interface_default_difference(
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<DefaultDifference> {
    match (unit.default_value, base_unit.default_value) {
        (Some(value), None) => Some(DefaultDifference {
            range: default_clause_range(value, source),
            kind: DefaultDifferenceKind::Use,
        }),
        (None, Some(_)) => unit.name.map(|name| DefaultDifference {
            range: range_of(name, source),
            kind: DefaultDifferenceKind::Add,
        }),
        (Some(value), Some(base_value))
            if node_text(value, source) != node_text(base_value, source) =>
        {
            Some(DefaultDifference {
                range: range_of(value, source),
                kind: DefaultDifferenceKind::Use,
            })
        }
        _ => None,
    }
}

fn override_default_difference(
    unit: &ParameterUnit<'_>,
    base_unit: &ParameterUnit<'_>,
    source: &str,
) -> Option<DefaultDifference> {
    match (unit.default_value, base_unit.default_value) {
        (None, Some(_)) => unit.name.map(|name| DefaultDifference {
            range: range_of(name, source),
            kind: DefaultDifferenceKind::Add,
        }),
        (Some(value), None) => Some(DefaultDifference {
            range: default_clause_range(value, source),
            kind: DefaultDifferenceKind::Remove,
        }),
        (Some(value), Some(base_value))
            if node_text(value, source) != node_text(base_value, source) =>
        {
            Some(DefaultDifference {
                range: range_of(value, source),
                kind: DefaultDifferenceKind::Use,
            })
        }
        _ => None,
    }
}

enum ExplicitInterface<'a> {
    Absent,
    Unresolved,
    Resolved(Node<'a>),
}

fn explicit_interface<'a>(
    method: Node<'a>,
    types: &std::collections::HashMap<&'a str, Node<'a>>,
    source: &'a str,
) -> ExplicitInterface<'a> {
    let Some(specifier) = collect_kinds(method, &["explicit_interface_specifier"])
        .into_iter()
        .next()
    else {
        return ExplicitInterface::Absent;
    };
    let interface_name = node_text(specifier, source).trim_end_matches('.');
    match types
        .get(interface_name)
        .copied()
        .filter(|node| node.kind() == "interface_declaration")
    {
        Some(interface) => ExplicitInterface::Resolved(interface),
        None => ExplicitInterface::Unresolved,
    }
}

fn matching_interface_method<'a>(
    interface: Node<'a>,
    method: Node<'a>,
    name: Node<'a>,
    source: &'a str,
) -> Option<Node<'a>> {
    member_declarations_of_kind(interface, "method_declaration")
        .into_iter()
        .find(|candidate| {
            candidate
                .child_by_field_name("name")
                .is_some_and(|candidate_name| {
                    node_text(candidate_name, source) == node_text(name, source)
                        && parameter_units(*candidate, source).len()
                            == parameter_units(method, source).len()
                })
        })
}

fn append_interface_pair<'a>(
    pairs: &mut Vec<(Node<'a>, Node<'a>, PairKind)>,
    method: Node<'a>,
    interface: Node<'a>,
    name: Node<'a>,
    pair_kind: PairKind,
    source: &'a str,
) {
    if let Some(interface_method) = matching_interface_method(interface, method, name, source) {
        pairs.push((method, interface_method, pair_kind));
    }
}

fn append_implicit_interface_pair<'a>(
    pairs: &mut Vec<(Node<'a>, Node<'a>, PairKind)>,
    declaration: Node<'a>,
    method: Node<'a>,
    name: Node<'a>,
    types: &std::collections::HashMap<&'a str, Node<'a>>,
    source: &'a str,
) {
    for base_name in base_simple_names(declaration, source) {
        let Some(interface) = types
            .get(base_name)
            .copied()
            .filter(|node| node.kind() == "interface_declaration")
        else {
            continue;
        };
        if let Some(interface_method) = matching_interface_method(interface, method, name, source) {
            pairs.push((method, interface_method, PairKind::ImplicitInterface));
            break;
        }
    }
}

fn interface_pairs<'a>(root: Node<'a>, source: &'a str) -> Vec<(Node<'a>, Node<'a>, PairKind)> {
    let types = local_type_table(root, source);
    let mut pairs = Vec::new();
    for declaration in local_type_declarations(root) {
        if declaration.kind() != "class_declaration" {
            continue;
        }
        let methods = member_declarations_of_kind(declaration, "method_declaration");
        for method in methods.iter().copied() {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            match explicit_interface(method, &types, source) {
                ExplicitInterface::Resolved(interface) => {
                    append_interface_pair(
                        &mut pairs,
                        method,
                        interface,
                        name,
                        PairKind::ExplicitInterface,
                        source,
                    );
                    continue;
                }
                ExplicitInterface::Unresolved | ExplicitInterface::Absent => {}
            }
            append_implicit_interface_pair(&mut pairs, declaration, method, name, &types, source);
        }
    }
    pairs
}

fn default_clause_range(value: Node<'_>, source: &str) -> hoonarqube_ir::Range {
    let start = value
        .parent()
        .filter(|parameter| parameter.kind() == "parameter")
        .and_then(|parameter| {
            let mut cursor = parameter.walk();
            parameter
                .children(&mut cursor)
                .find(|child| child.kind() == "=" && child.end_byte() <= value.start_byte())
                .map(|equals| equals.start_byte())
        })
        .unwrap_or(value.start_byte());
    range_from_byte_offsets(start, value.end_byte(), source)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S1006";

    #[test]
    fn s1006_minimal_class_without_overrides_is_clean() {
        let report = analyze_default("class C {\n    void M(int x = 1) {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_matching_defaults_stay_clean() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x = 1) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_changed_default_value_flags_the_override_name() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x = 2) {\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
    }

    #[test]
    fn s1006_explicit_default_range_starts_at_equals() {
        let with_comment = analyze_default(
            "public interface I { void M(int x = /* note */ 1); }\npublic sealed class C : I { void I.M(int x = /* note */ 1) { } }\n",
        );
        let found = with_key(&with_comment, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[0].range.start.column, 43);
        assert_eq!(found[0].range.end.column, 57);

        let compact = analyze_default(
            "public interface I { void M(int x=1); }\npublic sealed class C : I { void I.M(int x=1) { } }\n",
        );
        let found = with_key(&compact, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
        assert_eq!(found[0].range.start.column, 42);
        assert_eq!(found[0].range.end.column, 44);
    }

    #[test]
    fn s1006_dropped_default_flags_the_parameter_name() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public override void M(int x) {\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
        assert_eq!(
            found[0].message,
            "Add the default parameter value defined in the overridden method."
        );
    }

    #[test]
    fn s1006_cross_file_base_defaults_resolve_through_the_project_index() {
        let base = "public abstract class BulkCopy\n{\n    public abstract System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken = default);\n    public abstract System.Threading.Tasks.Task WriteToServerAsync(System.Data.DataTable source, System.Threading.CancellationToken cancellationToken = default);\n}\n";
        let derived = "class DynamicBulkCopy : BulkCopy\n{\n    public override System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken)\n        => null;\n    public override System.Threading.Tasks.Task WriteToServerAsync(System.Data.DataTable source, System.Threading.CancellationToken cancellationToken)\n        => null;\n}\n";
        let snapshots = [
            crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("BulkCopy.cs"), base),
            crate::semantic::SourceSnapshot::new(
                std::path::PathBuf::from("DynamicBulkCopy.cs"),
                derived,
            ),
        ];
        let options = crate::AnalyzerOptions {
            project_type_index: Some(std::sync::Arc::new(crate::ProjectTypeIndex::build(
                &snapshots,
            ))),
            ..crate::AnalyzerOptions::default()
        };
        let report = crate::tests::analyze_options(derived, &options);
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 5);
        assert_eq!(
            found[0].message,
            "Add the default parameter value defined in the overridden method."
        );
    }

    #[test]
    fn s1006_cross_file_matching_defaults_stay_clean() {
        let base = "public abstract class BulkCopy\n{\n    public abstract System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken = default);\n}\n";
        let derived = "class DynamicBulkCopy : BulkCopy\n{\n    public override System.Threading.Tasks.Task WriteToServerAsync(System.Data.Common.DbDataReader source, System.Threading.CancellationToken cancellationToken = default)\n        => null;\n}\n";
        let snapshots = [
            crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("BulkCopy.cs"), base),
            crate::semantic::SourceSnapshot::new(
                std::path::PathBuf::from("DynamicBulkCopy.cs"),
                derived,
            ),
        ];
        let options = crate::AnalyzerOptions {
            project_type_index: Some(std::sync::Arc::new(crate::ProjectTypeIndex::build(
                &snapshots,
            ))),
            ..crate::AnalyzerOptions::default()
        };
        let report = crate::tests::analyze_options(derived, &options);
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1006_added_override_default_flags_the_complete_default_clause() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x) {\n    }\n}\nclass D : B {\n    public override void M(int x = 2) {\n    }\n}\n",
        );
        assert_removal(&report, (6, 33, 36));
    }

    fn assert_removal(report: &hoonarqube_ir::FileReport, expected: (u32, u32, u32)) {
        let found = with_key(report, KEY);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].message,
            "Remove the default parameter value to match the signature of overridden method."
        );
        let range = &found[0].range;
        assert_eq!(
            (range.start.line, range.start.column, range.end.column),
            expected
        );
        assert_eq!(range.start.line, range.end.line);
        assert!(found[0].fix.is_none());
        assert!(found[0].alternatives.is_empty());
        assert!(found[0].flows.is_empty());
    }

    #[test]
    fn s1006_added_default_preserves_comment_unicode_and_crlf_coordinates() {
        let source = "namespace Triage; // π\r\nclass B { public virtual int M(int x) => x; }\r\nclass D : B { /* π */ public override int M(int x = /* note */ 2) => x; }\r\n";
        assert_removal(&analyze_default(source), (3, 50, 64));
    }

    #[test]
    fn s1006_added_defaults_keep_the_first_parameter_difference() {
        for source in [
            "namespace Triage;\nclass B { public virtual int M(int a, int b = 1) => a + b; }\nclass D : B { public override int M(int a = 2, int b = 3) => a + b; }\n",
            "namespace Triage;\nclass B { public virtual int M(int a, int b) => a + b; }\nclass D : B { public override int M(int a = 2, int b = 3) => a + b; }\n",
        ] {
            assert_removal(&analyze_default(source), (3, 42, 45));
        }
    }

    #[test]
    fn s1006_indexed_added_defaults_keep_exact_signature_and_first_difference() {
        for (base, derived) in [
            (
                "namespace Triage;\npublic class B { public virtual int M(int x) => x; }\n",
                "namespace Triage;\npublic class D : B { public override int M(int x = 2) => x; }\n",
            ),
            (
                "namespace Triage;\npublic class B { public virtual int M(int a, int b = 1) => a + b; }\n",
                "namespace Triage;\npublic class D : B { public override int M(int a = 2, int b = 3) => a + b; }\n",
            ),
        ] {
            let snapshots = [
                crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("Base.cs"), base),
                crate::semantic::SourceSnapshot::new(
                    std::path::PathBuf::from("Derived.cs"),
                    derived,
                ),
            ];
            let options = crate::AnalyzerOptions {
                project_type_index: Some(std::sync::Arc::new(crate::ProjectTypeIndex::build(
                    &snapshots,
                ))),
                ..crate::AnalyzerOptions::default()
            };
            assert_removal(
                &crate::tests::analyze_options(derived, &options),
                (2, 49, 52),
            );
            let mismatch = "namespace Triage;\npublic class D : B { public override int M(string x = \"x\") => x.Length; }\n";
            assert!(with_key(&crate::tests::analyze_options(mismatch, &options), KEY).is_empty());
        }
    }

    #[test]
    fn s1006_non_override_same_signature_is_ignored() {
        let report = analyze_default(
            "class B {\n    public virtual void M(int x = 1) {\n    }\n}\nclass D : B {\n    public new void M(int x = 2) {\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    fn overload_source(base_methods: &str, method: &str) -> String {
        format!("namespace Triage;\nclass B {{ {base_methods} }}\nclass D : B {{ {method} }}\n")
    }

    #[test]
    fn s1006_local_overloads_keep_matching_defaults_clean_in_both_orders() {
        for methods in [
            "public virtual int M(int x = 1) => x; public virtual int M(string x) => x.Length;",
            "public virtual int M(string x) => x.Length; public virtual int M(int x = 1) => x;",
            "public virtual int M(int x = 1) => x; public virtual int M(string x = \"hi\") => x.Length;",
        ] {
            let source = overload_source(methods, "public override int M(int x = 1) => x;");
            assert!(with_key(&analyze_default(&source), KEY).is_empty());
        }
    }

    #[test]
    fn s1006_local_overloads_select_added_changed_and_dropped_defaults() {
        let unrelated = "public virtual int M(string x) => x.Length;";
        for methods in [
            format!("public virtual int M(int x) => x; {unrelated}"),
            format!("{unrelated} public virtual int M(int x) => x;"),
            "public virtual int M(int x) => x; public virtual int M(string x = \"x\") => x.Length;"
                .to_string(),
            "public virtual int M(string x = \"x\") => x.Length; public virtual int M(int x) => x;"
                .to_string(),
        ] {
            let source = overload_source(&methods, "public override int M(int x = 2) => x;");
            assert_removal(&analyze_default(&source), (3, 42, 45));
        }
        let methods = format!("public virtual int M(int x = 1) => x; {unrelated}");
        for (method, message, start, end) in [
            (
                "public override int M(int x = 2) => x;",
                "Use the default parameter value defined in the overridden method.",
                44,
                45,
            ),
            (
                "public override int M(int x) => x;",
                "Add the default parameter value defined in the overridden method.",
                40,
                41,
            ),
        ] {
            let source = overload_source(&methods, method);
            let report = analyze_default(&source);
            let issues = with_key(&report, KEY);
            assert_eq!(issues.len(), 1, "{issues:?}");
            assert_eq!(issues[0].message, message);
            assert_eq!(issues[0].range.start.line, 3);
            assert_eq!(issues[0].range.end.line, 3);
            assert_eq!(issues[0].range.start.column, start);
            assert_eq!(issues[0].range.end.column, end);
        }
    }

    #[test]
    fn s1006_local_overloads_reject_ref_kind_and_parameter_count_decoys() {
        for decoy in [
            "public virtual int M(ref int x) => x;",
            "public virtual int M(int x, int y) => x + y;",
        ] {
            for methods in [
                format!("public virtual int M(int x = 1) => x; {decoy}"),
                format!("{decoy} public virtual int M(int x = 1) => x;"),
            ] {
                let source = overload_source(&methods, "public override int M(int x = 1) => x;");
                assert!(with_key(&analyze_default(&source), KEY).is_empty());
            }
        }
    }

    #[test]
    fn s1006_local_overloads_match_method_generic_arity_in_both_orders() {
        for (matching, decoy, method) in [
            (
                "public virtual int M(int x = 1) => x;",
                "public virtual int M<T>(int x) => x;",
                "public override int M(int x = 1) => x;",
            ),
            (
                "public virtual int M<T>(int x = 1) => x;",
                "public virtual int M(int x) => x;",
                "public override int M<T>(int x = 1) => x;",
            ),
            (
                "public virtual int M<T>(int x = 1) => x;",
                "public virtual int M<T, U>(int x) => x;",
                "public override int M<T>(int x = 1) => x;",
            ),
        ] {
            for methods in [format!("{matching} {decoy}"), format!("{decoy} {matching}")] {
                assert!(
                    with_key(&analyze_default(&overload_source(&methods, method)), KEY).is_empty()
                );
            }
        }
        for (matching, decoy, method, span) in [
            (
                "public virtual int M(int x) => x;",
                "public virtual int M<T>(int x = 1) => x;",
                "public override int M(int x = 2) => x;",
                (3, 42, 45),
            ),
            (
                "public virtual int M<T>(int x) => x;",
                "public virtual int M(int x = 1) => x;",
                "public override int M<T>(int x = 2) => x;",
                (3, 45, 48),
            ),
            (
                "public virtual int M<T>(int x) => x;",
                "public virtual int M<T, U>(int x = 2) => x;",
                "public override int M<T>(int x = 1) => x;",
                (3, 45, 48),
            ),
        ] {
            for methods in [format!("{matching} {decoy}"), format!("{decoy} {matching}")] {
                assert_removal(&analyze_default(&overload_source(&methods, method)), span);
            }
        }
    }

    fn assert_local_generic_difference(
        source: &str,
        message: Option<&str>,
        span: Option<(u32, u32, u32)>,
    ) {
        let report = analyze_default(source);
        let issues = with_key(&report, KEY);
        if let Some(message) = message {
            let (line, start, end) = span.expect("known generic finding span");
            assert_eq!(issues.len(), 1, "{issues:?}");
            assert_eq!(issues[0].message, message);
            assert_eq!(issues[0].range.start.line, line);
            assert_eq!(issues[0].range.end.line, line);
            assert_eq!(issues[0].range.start.column, start);
            assert_eq!(issues[0].range.end.column, end);
            assert!(issues[0].fix.is_none());
            assert!(issues[0].alternatives.is_empty());
        } else {
            assert!(issues.is_empty(), "{issues:?}");
        }
    }

    #[test]
    fn s1006_local_renamed_method_type_parameters_preserve_default_differences() {
        for (source, message, span) in [
            (
                "using System;\nnamespace Triage;\npublic class B { public virtual T M<T>(T x = default) => x; }\npublic class D : B { public override U M<U>(U x) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M<int>(1)); } }\n",
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 46, 47)),
            ),
            (
                "using System;\nnamespace Triage;\npublic class B { public virtual T M<T>(T x = default) => x; }\npublic class D : B { public override U M<U>(U x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M<int>(1)); } }\n",
                None,
                None,
            ),
            (
                "using System;\nnamespace Triage;\npublic class B { public virtual T M<T>(T x) => x; }\npublic class D : B { public override U M<U>(U x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M<int>(1)); } }\n",
                Some(
                    "Remove the default parameter value to match the signature of overridden method.",
                ),
                Some((4, 48, 57)),
            ),
        ] {
            assert_local_generic_difference(source, message, span);
        }
    }

    #[test]
    fn s1006_local_constructed_base_types_preserve_default_differences() {
        for (source, message, span) in [
            (
                "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; }\npublic class D : B<int> { public override int M(int x) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 52, 53)),
            ),
            (
                "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; }\npublic class D : B<int> { public override int M(int x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
                None,
                None,
            ),
            (
                "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x) => x; }\npublic class D : B<int> { public override int M(int x = default) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
                Some(
                    "Remove the default parameter value to match the signature of overridden method.",
                ),
                Some((4, 54, 63)),
            ),
            (
                "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; }\npublic class D : B<int> { public override int M(int x = 2) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n",
                Some("Use the default parameter value defined in the overridden method."),
                Some((4, 56, 57)),
            ),
        ] {
            assert_local_generic_difference(source, message, span);
        }
    }

    #[test]
    fn s1006_local_generic_identity_covers_arrays_qualified_arguments_and_overloads() {
        for (source, message, span) in [
            (
                "using System;\nnamespace Triage;\npublic class B { public virtual T[] M<T>(T[] x = null) => x; }\npublic class D : B { public override U[] M<U>(U[] x) => x; }\n",
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 50, 51)),
            ),
            (
                "using System;\nnamespace Triage;\npublic class B { public virtual System.Collections.Generic.List<T> M<T>(System.Collections.Generic.List<T> x = null) => x; }\npublic class D : B { public override System.Collections.Generic.List<U> M<U>(System.Collections.Generic.List<U> x) => x; }\n",
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 112, 113)),
            ),
            (
                "using System;\nnamespace Triage;\npublic class B<T> { public virtual T[] M(T[] x = null) => x; }\npublic class D : B<int> { public override int[] M(int[] x) => x; }\n",
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 56, 57)),
            ),
            (
                "using System;\nnamespace Triage;\npublic class B<T> { public virtual T M(T x = default) => x; public virtual int M(string x) => x.Length; }\npublic class D : B<int> { public override int M(int x) => x; }\n",
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 52, 53)),
            ),
            (
                "using System;\nnamespace Triage;\npublic class B<T> { public virtual U M<U>(T x, U y = default) => y; }\npublic class D<T> : B<int> { public override V M<V>(int x, V y) => y; }\n",
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 61, 62)),
            ),
        ] {
            assert_local_generic_difference(source, message, span);
        }
    }
    #[test]
    fn s1006_local_generic_scope_preserves_method_shadowing_and_concrete_qualified_names() {
        let source = "using System;\n#pragma warning disable CS0693\nnamespace Concrete { public sealed class T {} }\nnamespace Triage {\npublic class B<T> { public virtual U Combined<U>(T x, U y = default) => y; public virtual T Shadow<T>(T x = default) => x; public virtual Concrete.T Qualified<U>(Concrete.T x = null, U y = default) => x; }\npublic class D<U> : B<U> { public override V Combined<V>(U x, V y) => y; public override V Shadow<V>(V x) => x; public override Concrete.T Qualified<V>(Concrete.T x, V y = default) => x; }\npublic static class Program { public static void Main() { D<int> d = new(); Console.WriteLine($\"{d.Combined<int>(1, 1)}:{d.Shadow<int>(1)}:{(d.Qualified<int>(new Concrete.T(), 1) is not null ? 1 : 0)}\"); } }\n}\n";
        let report = analyze_default(source);
        let issues = with_key(&report, KEY);
        assert_eq!(issues.len(), 3, "{issues:?}");
        for (issue, column) in issues.iter().zip([64, 103, 163]) {
            assert_eq!(
                issue.message,
                "Add the default parameter value defined in the overridden method."
            );
            assert_eq!(issue.range.start.line, 6);
            assert_eq!(issue.range.end.line, 6);
            assert_eq!(issue.range.start.column, column);
            assert_eq!(issue.range.end.column, column + 1);
        }
        let matching = source
            .replace("V y) =>", "V y = default) =>")
            .replace("V x) =>", "V x = default) =>")
            .replace(
                "Concrete.T x, V y = default",
                "Concrete.T x = null, V y = default",
            );
        assert!(with_key(&analyze_default(&matching), KEY).is_empty());
    }

    #[test]
    fn s1006_local_scalar_identity_preserves_bcl_keyword_add_and_use_findings() {
        for (keyword, framework) in [
            ("bool", "Boolean"),
            ("byte", "Byte"),
            ("char", "Char"),
            ("decimal", "Decimal"),
            ("double", "Double"),
            ("float", "Single"),
            ("int", "Int32"),
            ("long", "Int64"),
            ("object", "Object"),
            ("sbyte", "SByte"),
            ("short", "Int16"),
            ("string", "String"),
            ("uint", "UInt32"),
            ("ulong", "UInt64"),
            ("ushort", "UInt16"),
            ("nint", "IntPtr"),
            ("nuint", "UIntPtr"),
        ] {
            let source = format!(
                "using System;\nnamespace Triage;\npublic class B {{ public virtual int M(System.{framework} x = default) => 1; }}\npublic class D : B {{ public override int M({keyword} x) => 1; }}\n"
            );
            let column = 44 + u32::try_from(keyword.len()).expect("short keyword");
            assert_local_generic_difference(
                &source,
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, column, column + 1)),
            );
        }
        let source = "using System;\nnamespace Triage;\npublic class B { public virtual int M(System.Int32 x = 1) => x; }\npublic class D : B { public override int M(int x) => x; }\npublic static class Program { public static void Main() { Console.WriteLine(new D().M(1)); } }\n";
        assert_local_generic_difference(
            source,
            Some("Add the default parameter value defined in the overridden method."),
            Some((4, 47, 48)),
        );
        let changed = source.replace("M(int x)", "M(int x = 2)");
        assert_local_generic_difference(
            &changed,
            Some("Use the default parameter value defined in the overridden method."),
            Some((4, 51, 52)),
        );
        let matching = source.replace("M(int x)", "M(int x = 1)");
        assert_local_generic_difference(&matching, None, None);
    }

    #[test]
    fn s1006_local_scalar_identity_preserves_type_and_namespace_aliases() {
        for (using, base_type) in [
            ("using I = global::System.Int32;", "I"),
            ("using S = global::System;", "S.Int32"),
            ("using S = global::System;", "S::Int32"),
            ("", "global::System.Int32"),
        ] {
            let source = format!(
                "{using}\nnamespace Triage;\npublic class B {{ public virtual int M({base_type} x = 1) => x; }}\npublic class D : B {{ public override int M(int x) => x; }}\n"
            );
            assert_local_generic_difference(
                &source,
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, 47, 48)),
            );
            assert_local_generic_difference(
                &source.replace("M(int x)", "M(int x = 2)"),
                Some("Use the default parameter value defined in the overridden method."),
                Some((4, 51, 52)),
            );
            assert_local_generic_difference(
                &source.replace("M(int x)", "M(int x = 1)"),
                None,
                None,
            );
        }
        let source = "using I = global::System.Int64;\nnamespace Triage {\nusing I = global::System.Int32;\npublic class B<T> { public virtual T M(T x = default) => x; }\npublic class D : B<I> { public override int M(int x) => x; }\n}\n";
        assert_local_generic_difference(
            source,
            Some("Add the default parameter value defined in the overridden method."),
            Some((5, 50, 51)),
        );
        let source = "namespace BaseScope { using I = global::System.Int32; public class B { public virtual int M(I x = 1) => x; } }\nnamespace DerivedScope { using I = global::System.Int64; public class D : BaseScope.B { public override int M(int x) => x; } }\n";
        assert_local_generic_difference(
            source,
            Some("Add the default parameter value defined in the overridden method."),
            Some((2, 114, 115)),
        );
    }

    #[test]
    fn s1006_local_scalar_identity_normalizes_only_type_positions_in_composites() {
        for (base_type, derived_type, default) in [
            ("global::System.Int32[]", "int[]", "null"),
            (
                "System.Collections.Generic.List<global::System.Int32>",
                "System.Collections.Generic.List<int>",
                "null",
            ),
            (
                "(global::System.Int32 Left, int Right)",
                "(int Left, int Right)",
                "default",
            ),
        ] {
            let source = format!(
                "using System;\nnamespace Triage;\npublic class B {{ public virtual int M({base_type} x = {default}) => 1; }}\npublic class D : B {{ public override int M({derived_type} x) => 1; }}\n"
            );
            let column = 44 + u32::try_from(derived_type.len()).expect("short fixture type");
            assert_local_generic_difference(
                &source,
                Some("Add the default parameter value defined in the overridden method."),
                Some((4, column, column + 1)),
            );
        }
    }

    #[test]
    fn s1006_local_scalar_identity_rejects_system_namespace_overload_decoys() {
        for (prefix, scope_using) in [
            ("namespace Triage.System { public class Int32 {} }\n", ""),
            (
                "namespace Shadow { public class Int32 {} }\n",
                "using System = global::Shadow;\n",
            ),
        ] {
            let decoy = "public virtual int M(System.Int32 x = null) => 1;";
            let matching = "public virtual int M(int x) => x;";
            for methods in [format!("{matching} {decoy}"), format!("{decoy} {matching}")] {
                let source = format!(
                    "{prefix}namespace Triage {{\n{scope_using}public class B {{ {methods} }}\npublic class D : B {{ public override int M(int x = 2) => x; }}\n}}\n"
                );
                let line = u32::try_from(prefix.lines().count() + scope_using.lines().count())
                    .expect("short fixture prefix")
                    + 3;
                assert_removal(&analyze_default(&source), (line, 49, 52));
                let clean = source.replace("M(int x = 2)", "M(int x)");
                assert!(with_key(&analyze_default(&clean), KEY).is_empty());
            }
        }
    }

    #[test]
    fn s1006_local_review_inherited_nested_system_preserves_default_difference() {
        let source = "namespace Triage { public class B { public class System { public class Int32 {} } public virtual int M(System.Int32 x = null) => 1; } public class D : B { public override int M(System.Int32 x) => 1; } public static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(null)); } } }\n";
        assert_local_generic_difference(
            source,
            Some("Add the default parameter value defined in the overridden method."),
            Some((1, 190, 191)),
        );
        let matching = source.replace(
            "public override int M(System.Int32 x)",
            "public override int M(System.Int32 x = null)",
        );
        assert_local_generic_difference(&matching, None, None);
    }

    #[test]
    fn s1006_local_review_nullable_value_type_decoys_keep_matching_defaults_clean() {
        for source in [
            "namespace Triage {\npublic struct Value {}\npublic class B { public virtual int M(Value? x) => 0; public virtual int M(Value x = default) => 1; }\npublic class D : B { public override int M(Value x = default) => 1; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M()); } }\n}\n",
            "namespace Triage {\npublic class B {\n  public virtual int M(int? x) => 0;\n  public virtual int M(int x = 1) => x;\n}\npublic class D : B { public override int M(int x = 1) => x; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(1)); } }\n}\n",
            "namespace Triage {\npublic class B {\n  public virtual int M(int x = 1) => x;\n  public virtual int M(int? x) => 0;\n}\npublic class D : B { public override int M(int x = 1) => x; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(1)); } }\n}\n",
        ] {
            assert_local_generic_difference(source, None, None);
        }
    }

    #[test]
    fn s1006_local_review_distinct_namespace_import_decoys_keep_matching_defaults_clean() {
        for source in [
            "namespace A.Models { public class Item {} }\nnamespace B.Models { public class Item {} }\nnamespace A {\npublic class Base {\n  public virtual int M(Models.Item x) => 0;\n  public virtual int M(global::B.Models.Item x = null) => 1;\n}\n}\nnamespace B {\npublic class D : global::A.Base { public override int M(Models.Item x = null) => 1; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(new global::B.Models.Item())); } }\n}\n",
            "namespace Left { public class Item<T> {} }\nnamespace Right { public class Item<T> {} }\nnamespace Parent {\nusing Left;\npublic class B {\n  public virtual int M(Item<int> x) => 0;\n  public virtual int M(global::Right.Item<int> x = null) => 1;\n}\n}\nnamespace Child {\nusing Right;\npublic class D : Parent.B { public override int M(Item<int> x = null) => 1; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(new global::Right.Item<int>())); } }\n}\n",
            "namespace Left { public class Item {} }\nnamespace Right { public class Item {} }\nnamespace Parent {\nusing Left;\npublic class B {\n  public virtual int M(Item x) => 0;\n  public virtual int M(global::Right.Item x = null) => 1;\n}\n}\nnamespace Child {\nusing Right;\npublic class D : Parent.B { public override int M(Item x = null) => 1; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(new global::Right.Item())); } }\n}\n",
            "namespace Left { public class Item {} }\nnamespace Right { public class Item {} }\nnamespace Parent {\nusing Left;\npublic class B {\n  public virtual int M(global::Right.Item x = null) => 1;\n  public virtual int M(Item x) => 0;\n}\n}\nnamespace Child {\nusing Right;\npublic class D : Parent.B { public override int M(Item x = null) => 1; }\npublic static class Program { public static void Main() { global::System.Console.WriteLine(new D().M(new global::Right.Item())); } }\n}\n",
        ] {
            assert_local_generic_difference(source, None, None);
        }
    }

    #[test]
    fn s1006_indexed_review_nullable_decoys_keep_matching_defaults_clean() {
        for methods in [
            "public virtual int M(int? x) => 0; public virtual int M(int x = 1) => 1;",
            "public virtual int M(int x = 1) => 1; public virtual int M(int? x) => 0;",
            "public virtual int M(int? x) => 0; public virtual int M(global::System.Int32 x = 1) => 1;",
            "public virtual int M(global::System.Int32 x = 1) => 1; public virtual int M(int? x) => 0;",
        ] {
            let base = format!("namespace Triage;\npublic class B {{ {methods} }}\n");
            let derived = "namespace Triage;\npublic class D : B { public override int M(int x = 1) => 1; }\n";
            let snapshots = [
                crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("Base.cs"), &base),
                crate::semantic::SourceSnapshot::new(
                    std::path::PathBuf::from("Derived.cs"),
                    derived,
                ),
            ];
            let options = crate::AnalyzerOptions {
                project_type_index: Some(std::sync::Arc::new(crate::ProjectTypeIndex::build(
                    &snapshots,
                ))),
                ..crate::AnalyzerOptions::default()
            };
            assert!(
                with_key(&crate::tests::analyze_options(derived, &options), KEY).is_empty(),
                "{methods}"
            );
        }
    }

    #[test]
    fn s1006_indexed_review_unproven_remove_keeps_later_existing_difference() {
        let base = "namespace Triage;\npublic class Value {}\npublic class B { public virtual int M(Value value, int x = 1) => x; }\n";
        let derived = "namespace Triage;\npublic class D : B { public override int M(Value value = null, int x = 2) => x; }\n";
        let snapshots = [
            crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("Base.cs"), base),
            crate::semantic::SourceSnapshot::new(std::path::PathBuf::from("Derived.cs"), derived),
        ];
        let options = crate::AnalyzerOptions {
            project_type_index: Some(std::sync::Arc::new(crate::ProjectTypeIndex::build(
                &snapshots,
            ))),
            ..crate::AnalyzerOptions::default()
        };
        let report = crate::tests::analyze_options(derived, &options);
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(
            found[0].message,
            "Use the default parameter value defined in the overridden method."
        );
        let column = u32::try_from(
            derived
                .lines()
                .nth(1)
                .expect("override line")
                .find("2)")
                .expect("changed default"),
        )
        .expect("short source");
        assert_eq!(
            (
                found[0].range.start.line,
                found[0].range.start.column,
                found[0].range.end.line,
                found[0].range.end.column
            ),
            (2, column, 2, column + 1)
        );
    }
}
