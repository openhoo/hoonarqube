//! Tier-B usage-analysis symbol table: one pass collects declared types
//! and members, identifier references, and field write sites.

use crate::cst::{ancestors_of, collect_kinds, modifiers_of, node_text};
use crate::rules::expressions::{binary_operands, first_named_child};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use tree_sitter::Node;

/// Member-level declarations owning data or executable bodies. Deliberately
/// skips `accessor_declaration`, so lookups resolve to the whole property.
pub(crate) const TIER_B_MEMBER_KINDS: [&str; 6] = [
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "property_declaration",
    "indexer_declaration",
];

/// Flavors of tracked member declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MemberFlavor {
    Field,
    EventField,
    Method,
    Property,
}

impl MemberFlavor {
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Field => "field",
            Self::EventField => "event",
            Self::Method => "method",
            Self::Property => "property",
        }
    }
}

/// One tracked member declaration with its owning type.
pub(crate) struct MemberSymbol<'t> {
    pub(crate) flavor: MemberFlavor,
    pub(crate) name: &'t str,
    pub(crate) declaration: Node<'t>,
    pub(crate) anchor: Node<'t>,
    pub(crate) owner: Node<'t>,
    pub(crate) nested_type: bool,
    pub(crate) is_static_or_const: bool,
    pub(crate) has_initializer: bool,
}

/// One type declaration with its nearest enclosing type.
pub(crate) struct TypeSymbol<'t> {
    pub(crate) declaration: Node<'t>,
    pub(crate) parent: Option<Node<'t>>,
}

/// One identifier occurrence, classified as binding introduction or use.
pub(crate) struct Reference<'t> {
    pub(crate) name: &'t str,
    pub(crate) node: Node<'t>,
    introduces_binding: bool,
}

/// One field write site (`x = …`, `x += …`, `++x`, `x--`, `this.x = …`).
pub(crate) struct WriteSite<'t> {
    pub(crate) name: &'t str,
    pub(crate) node: Node<'t>,
}

/// File-scoped declarations and usages shared by the Tier-B checks.
pub(crate) struct UsageSymbols<'t> {
    pub(crate) types: Vec<TypeSymbol<'t>>,
    pub(crate) members: Vec<MemberSymbol<'t>>,
    pub(crate) references: Vec<Reference<'t>>,
    pub(crate) writes: Vec<WriteSite<'t>>,
}

impl<'t> UsageSymbols<'t> {
    pub(crate) fn uses_of(&self, name: &str) -> Vec<Node<'t>> {
        self.references
            .iter()
            .filter(|reference| reference.name == name && !reference.introduces_binding)
            .map(|reference| reference.node)
            .collect()
    }

    pub(crate) fn writes_of(&self, name: &str) -> Vec<Node<'t>> {
        self.writes
            .iter()
            .filter(|site| site.name == name)
            .map(|site| site.node)
            .collect()
    }

    fn member_names_of(&self, owner: Node<'t>) -> std::collections::HashSet<&'t str> {
        self.members
            .iter()
            .filter(|member| member.owner == owner)
            .map(|member| member.name)
            .collect()
    }

    pub(crate) fn static_members_of(&self, owner: Node<'t>) -> Vec<&MemberSymbol<'t>> {
        self.members
            .iter()
            .filter(|member| member.owner == owner && member.is_static_or_const)
            .collect()
    }
}

pub(crate) fn build_usage_symbols<'t>(root: Node<'t>, source: &'t str) -> UsageSymbols<'t> {
    let mut symbols = UsageSymbols {
        types: Vec::new(),
        members: Vec::new(),
        references: Vec::new(),
        writes: Vec::new(),
    };
    collect_usage_symbols(root, None, source, &mut symbols);
    symbols
}

fn collect_usage_symbols<'t>(
    node: Node<'t>,
    type_owner: Option<Node<'t>>,
    source: &'t str,
    symbols: &mut UsageSymbols<'t>,
) {
    if node.is_error() || node.is_missing() {
        return;
    }
    let mut inner_owner = type_owner;
    if TYPE_DECLARATION_KINDS.contains(&node.kind()) {
        symbols.types.push(TypeSymbol {
            declaration: node,
            parent: type_owner,
        });
        collect_declared_members(node, type_owner.is_some(), source, symbols);
        inner_owner = Some(node);
    } else if node.kind() == "identifier" {
        symbols.references.push(Reference {
            name: node_text(node, source),
            node,
            introduces_binding: introduces_binding(node),
        });
    } else if let Some(site) = write_site(node, source) {
        symbols.writes.push(site);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_usage_symbols(child, inner_owner, source, symbols);
    }
}

/// Whether an identifier introduces a declaration instead of referencing
/// an existing one: declaration names, variables, parameters, catch vars.
fn introduces_binding(identifier: Node<'_>) -> bool {
    let Some(parent) = identifier.parent() else {
        return false;
    };
    let kind = parent.kind();
    if matches!(
        kind,
        "variable_declarator" | "parameter" | "catch_declaration" | "enum_member_declaration"
    ) {
        return true;
    }
    kind.ends_with("_declaration") && parent.child_by_field_name("name") == Some(identifier)
}

/// The field a write expression targets: bare identifiers and `this.x`.
fn write_target_name<'a>(target: Node<'_>, source: &'a str) -> Option<&'a str> {
    match target.kind() {
        "identifier" => Some(node_text(target, source)),
        "member_access_expression" => {
            let mut cursor = target.walk();
            let named: Vec<Node> = target
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect();
            let receiver = named.first()?;
            let name = named.last()?;
            (receiver.kind() == "this_expression" && name.kind() == "identifier")
                .then(|| node_text(*name, source))
        }
        _ => None,
    }
}

/// Classifies an expression as a field write site when possible.
fn write_site<'t>(node: Node<'t>, source: &'t str) -> Option<WriteSite<'t>> {
    let target = match node.kind() {
        "assignment_expression" => binary_operands(node)?.0,
        "prefix_unary_expression" | "postfix_unary_expression" => {
            let mut cursor = node.walk();
            let increments = node
                .children(&mut cursor)
                .any(|child| !child.is_named() && matches!(child.kind(), "++" | "--"));
            if !increments {
                return None;
            }
            first_named_child(node)?
        }
        _ => return None,
    };
    let name = write_target_name(target, source)?;
    Some(WriteSite { name, node })
}

/// Registers the members declared directly by a type declaration.
fn collect_declared_members<'t>(
    type_node: Node<'t>,
    nested: bool,
    source: &'t str,
    symbols: &mut UsageSymbols<'t>,
) {
    for member in type_members(type_node) {
        let flavor = match member.kind() {
            "field_declaration" => MemberFlavor::Field,
            "event_field_declaration" => MemberFlavor::EventField,
            "method_declaration" => MemberFlavor::Method,
            "property_declaration" => MemberFlavor::Property,
            _ => continue,
        };
        let modifiers = modifiers_of(member, source);
        let is_static_or_const =
            has_modifier(&modifiers, "static") || has_modifier(&modifiers, "const");
        if matches!(flavor, MemberFlavor::Field | MemberFlavor::EventField) {
            for declarator in collect_kinds(member, &["variable_declarator"]) {
                let Some(anchor) = declarator.child_by_field_name("name").or_else(|| {
                    collect_kinds(declarator, &["identifier"])
                        .into_iter()
                        .next()
                }) else {
                    continue;
                };
                let mut declarator_cursor = declarator.walk();
                let has_initializer = declarator
                    .named_children(&mut declarator_cursor)
                    .any(|child| child.id() != anchor.id());
                symbols.members.push(MemberSymbol {
                    flavor,
                    name: node_text(anchor, source),
                    declaration: member,
                    anchor,
                    owner: type_node,
                    nested_type: nested,
                    is_static_or_const,
                    has_initializer,
                });
            }
        } else {
            let Some(anchor) = member.child_by_field_name("name") else {
                continue;
            };
            symbols.members.push(MemberSymbol {
                flavor,
                name: node_text(anchor, source),
                declaration: member,
                anchor,
                owner: type_node,
                nested_type: nested,
                is_static_or_const,
                has_initializer: false,
            });
        }
    }
}

/// Nearest ancestor among `kinds`, if any.
pub(crate) fn nearest_ancestor_of_kinds<'t>(node: Node<'t>, kinds: &[&str]) -> Option<Node<'t>> {
    ancestors_of(node).find(|ancestor| kinds.contains(&ancestor.kind()))
}

/// Effective private visibility: explicit modifiers win, nested members
/// default to private, top-level ones to internal.
pub(crate) fn is_private_member(declaration: Node<'_>, source: &str, nested_type: bool) -> bool {
    let modifiers = modifiers_of(declaration, source);
    if modifiers
        .iter()
        .any(|modifier| matches!(*modifier, "public" | "internal" | "protected"))
    {
        return false;
    }
    has_modifier(&modifiers, "private") || nested_type
}

/// Modifiers tying a member to inheritance or tooling contracts, where
/// usage-based rules must stay silent.
pub(crate) fn has_contract_modifier(modifiers: &[&str]) -> bool {
    modifiers.iter().any(|modifier| {
        matches!(
            *modifier,
            "override" | "virtual" | "abstract" | "extern" | "new" | "partial"
        )
    })
}

/// Whether the owning type is `partial` and may have siblings in other
/// files holding extra references.
pub(crate) fn owner_is_partial(member_owner: Node<'_>, source: &str) -> bool {
    has_modifier(&modifiers_of(member_owner, source), "partial")
}

/// Whether the reference passes its identifier by `ref` or `out`, hiding
/// an assignment from the write index.
pub(crate) fn is_ref_or_out_argument(reference: Node<'_>, source: &str) -> bool {
    reference
        .parent()
        .filter(|parent| parent.kind() == "argument")
        .is_some_and(|argument| {
            matches!(
                node_text(argument, source).split_whitespace().next(),
                Some("ref" | "out")
            )
        })
}

/// Whether a write lands in a constructor compatible with the field's
/// staticity, the only place a field becomes safely `readonly`.
pub(crate) fn is_matching_constructor_write(
    write: Node<'_>,
    field_is_static: bool,
    source: &str,
) -> bool {
    let Some(owner) = nearest_ancestor_of_kinds(write, &TIER_B_MEMBER_KINDS) else {
        return false;
    };
    owner.kind() == "constructor_declaration"
        && has_modifier(&modifiers_of(owner, source), "static") == field_is_static
}

/// Whether the member declares executable code (blocks or expression
/// arrows), separating real members from auto-properties.
pub(crate) fn declares_executable_code(declaration: Node<'_>) -> bool {
    !collect_kinds(declaration, &["block", "arrow_expression_clause"]).is_empty()
}

/// Whether the member touches instance state: sibling member references
/// or `this` anywhere in its declaration span.
pub(crate) fn touches_instance_data(member: &MemberSymbol<'_>, symbols: &UsageSymbols<'_>) -> bool {
    let span = member.declaration.byte_range();
    let owner_names = symbols.member_names_of(member.owner);
    let sibling_reference = symbols.references.iter().any(|reference| {
        let reference_span = reference.node.byte_range();
        reference_span.start >= span.start
            && reference_span.end <= span.end
            && !reference.introduces_binding
            && reference.name != member.name
            && owner_names.contains(reference.name)
    });
    sibling_reference || !collect_kinds(member.declaration, &["this_expression"]).is_empty()
}
