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
    collect_usage_symbols(root, source, &mut symbols);
    symbols
}

fn collect_usage_symbols<'t>(root: Node<'t>, source: &'t str, symbols: &mut UsageSymbols<'t>) {
    let mut pending = vec![(root, None)];
    while let Some((node, type_owner)) = pending.pop() {
        if node.is_error() || node.is_missing() {
            continue;
        }
        let mut child_owner = type_owner;
        match node.kind() {
            kind if TYPE_DECLARATION_KINDS.contains(&kind) => {
                symbols.types.push(TypeSymbol {
                    declaration: node,
                    parent: type_owner,
                });
                collect_declared_members(node, type_owner.is_some(), source, symbols);
                child_owner = Some(node);
            }
            "identifier" => symbols.references.push(Reference {
                name: node_text(node, source),
                node,
                introduces_binding: introduces_binding(node),
            }),
            _ => {
                if let Some(site) = write_site(node, source) {
                    symbols.writes.push(site);
                }
            }
        }
        let mut cursor = node.walk();
        let mut children: Vec<Node<'t>> = node.children(&mut cursor).collect();
        children.reverse();
        pending.extend(children.into_iter().map(|child| (child, child_owner)));
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
    if kind.ends_with("_declaration") && parent.child_by_field_name("name") == Some(identifier) {
        return true;
    }
    match kind {
        "foreach_statement" => parent.child_by_field_name("left") == Some(identifier),
        "declaration_expression"
        | "declaration_pattern"
        | "from_clause"
        | "list_pattern"
        | "local_function_statement"
        | "recursive_pattern"
        | "type_parameter" => parent.child_by_field_name("name") == Some(identifier),
        // Every direct identifier in these nodes introduces a name. Query
        // expressions used to compute it live below expression children.
        "implicit_parameter"
        | "join_clause"
        | "join_into_clause"
        | "let_clause"
        | "parenthesized_variable_designation"
        | "tuple_pattern" => true,
        _ => false,
    }
}

/// The field a write expression targets: bare identifiers and `this.x`.
fn write_target_name<'a>(target: Node<'_>, source: &'a str) -> Option<&'a str> {
    match target.kind() {
        "identifier" => Some(node_text(target, source)),
        "member_access_expression" => {
            let receiver = target.child(0)?;
            let name = target.child_by_field_name("name")?;
            (matches!(receiver.kind(), "this" | "this_expression") && name.kind() == "identifier")
                .then(|| node_text(name, source))
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
            for declarator in direct_variable_declarators(member) {
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

/// Variable declarators owned by a field/event declaration. Descendant
/// declarators inside lambda or anonymous-method initializers are locals,
/// not additional type members.
fn direct_variable_declarators(member: Node<'_>) -> Vec<Node<'_>> {
    let mut member_cursor = member.walk();
    let Some(declaration) = member
        .named_children(&mut member_cursor)
        .find(|child| child.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let mut declaration_cursor = declaration.walk();
    declaration
        .named_children(&mut declaration_cursor)
        .filter(|child| child.kind() == "variable_declarator")
        .collect()
}

/// Nearest ancestor among `kinds`, if any.
pub(crate) fn nearest_ancestor_of_kinds<'t>(node: Node<'t>, kinds: &[&str]) -> Option<Node<'t>> {
    ancestors_of(node).find(|ancestor| kinds.contains(&ancestor.kind()))
}

/// Effective private visibility: explicit modifiers win. Class, struct,
/// and record members default to private regardless of whether their owner
/// itself is nested; interface members default to public.
pub(crate) fn is_private_member(declaration: Node<'_>, source: &str, _nested_type: bool) -> bool {
    let modifiers = modifiers_of(declaration, source);
    if modifiers
        .iter()
        .any(|modifier| matches!(*modifier, "public" | "internal" | "protected"))
    {
        return false;
    }
    has_modifier(&modifiers, "private")
        || nearest_ancestor_of_kinds(declaration, &TYPE_DECLARATION_KINDS)
            .is_some_and(|owner| owner.kind() != "interface_declaration")
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
    if nearest_ancestor_of_kinds(
        write,
        &[
            "anonymous_method_expression",
            "lambda_expression",
            "local_function_statement",
        ],
    )
    .is_some()
    {
        return false;
    }
    let Some(owner) = nearest_ancestor_of_kinds(write, &TIER_B_MEMBER_KINDS) else {
        return false;
    };
    owner.kind() == "constructor_declaration"
        && has_modifier(&modifiers_of(owner, source), "static") == field_is_static
}

/// Whether the member declares executable code (blocks or expression
/// arrows), separating real members from auto-properties.
pub(crate) fn declares_executable_code(declaration: Node<'_>) -> bool {
    let mut pending = vec![declaration];
    while let Some(node) = pending.pop() {
        if node != declaration
            && matches!(
                node.kind(),
                "anonymous_method_expression"
                    | "lambda_expression"
                    | "local_function_statement"
                    | "class_declaration"
                    | "interface_declaration"
                    | "struct_declaration"
                    | "record_declaration"
                    | "enum_declaration"
            )
        {
            continue;
        }
        if matches!(node.kind(), "block" | "arrow_expression_clause") {
            return true;
        }
        let mut cursor = node.walk();
        pending.extend(node.children(&mut cursor));
    }
    false
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
    sibling_reference || !collect_kinds(member.declaration, &["this", "this_expression"]).is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        MemberFlavor, build_usage_symbols, declares_executable_code, is_matching_constructor_write,
        is_private_member, touches_instance_data,
    };
    use crate::parse;
    use std::fmt::Write as _;

    #[test]
    fn field_initializer_locals_are_not_registered_as_members() {
        let source = r"
class C
{
    private int first = 1, second = 2;
    private System.Func<int> compute = () =>
    {
        var scratch = 1;
        return scratch;
    };
}
";
        let tree = parse(source);
        let symbols = build_usage_symbols(tree.root_node(), source);
        let members: Vec<(&str, MemberFlavor)> = symbols
            .members
            .iter()
            .map(|member| (member.name, member.flavor))
            .collect();

        assert_eq!(
            members,
            vec![
                ("first", MemberFlavor::Field),
                ("second", MemberFlavor::Field),
                ("compute", MemberFlavor::Field),
            ]
        );
    }

    #[test]
    fn nested_types_keep_distinct_owners_and_unicode_names() {
        let source =
            "class Outer { int größe; class Inner { int größe; void M() { this.größe++; } } }";
        let tree = parse(source);
        let symbols = build_usage_symbols(tree.root_node(), source);
        let fields: Vec<_> = symbols
            .members
            .iter()
            .filter(|member| member.flavor == MemberFlavor::Field)
            .collect();

        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0].name, "größe");
        assert_eq!(fields[1].name, "größe");
        assert_ne!(fields[0].owner, fields[1].owner);
        assert_eq!(symbols.writes_of("größe").len(), 1);
        let method = symbols
            .members
            .iter()
            .find(|member| member.flavor == MemberFlavor::Method)
            .expect("nested method is indexed");
        assert!(touches_instance_data(method, &symbols));
    }

    #[test]
    fn usage_collection_handles_deeply_nested_types_iteratively() {
        const DEPTH: usize = 2_000;
        let mut source = String::new();
        for index in 0..DEPTH {
            write!(&mut source, "class C{index} {{").expect("writing to a String cannot fail");
        }
        source.push_str("int leaf;");
        for _ in 0..DEPTH {
            source.push('}');
        }

        let tree = parse(&source);
        let symbols = build_usage_symbols(tree.root_node(), &source);

        assert_eq!(symbols.types.len(), DEPTH);
        assert_eq!(symbols.members.len(), 1);
        assert_eq!(symbols.members[0].name, "leaf");
        assert_eq!(
            symbols
                .types
                .iter()
                .filter(|symbol| symbol.parent.is_none())
                .count(),
            1
        );
    }

    #[test]
    fn non_declaration_binding_forms_are_not_counted_as_uses() {
        let source = r"
class C<T>
{
    void M(int[] values, object value)
    {
        foreach (var item in values) { }
        if (value is int number) { }
        Local();
        void Local() { }
        var query = from entry in values
                    let doubled = entry * 2
                    select doubled;
        System.Action<int> action = parameter => parameter.ToString();
    }
}
";
        let tree = parse(source);
        let symbols = build_usage_symbols(tree.root_node(), source);
        let binding_names: Vec<&str> = symbols
            .references
            .iter()
            .filter(|reference| reference.introduces_binding)
            .map(|reference| reference.name)
            .collect();

        for expected in ["T", "item", "number", "Local", "entry", "doubled"] {
            assert!(
                binding_names.contains(&expected),
                "{expected} should introduce a binding; got {binding_names:?}"
            );
        }
    }

    #[test]
    fn default_member_visibility_comes_from_owner_kind_not_owner_nesting() {
        let source = "class Top { int Compute() => 1; interface Contract { int Compute() => 1; } }";
        let tree = parse(source);
        let symbols = build_usage_symbols(tree.root_node(), source);
        let methods: Vec<_> = symbols
            .members
            .iter()
            .filter(|member| member.flavor == MemberFlavor::Method)
            .collect();

        assert_eq!(methods.len(), 2);
        assert!(is_private_member(
            methods[0].declaration,
            source,
            methods[0].nested_type
        ));
        assert!(!is_private_member(
            methods[1].declaration,
            source,
            methods[1].nested_type
        ));
    }

    #[test]
    fn deferred_constructor_writes_do_not_qualify_fields_as_readonly() {
        let source = r"
class C
{
    int direct;
    int deferred;
    C()
    {
        direct = 1;
        System.Action assign = () => deferred = 1;
    }
}
";
        let tree = parse(source);
        let symbols = build_usage_symbols(tree.root_node(), source);
        let direct = symbols
            .writes
            .iter()
            .find(|write| write.name == "direct")
            .expect("direct write is indexed");
        let deferred = symbols
            .writes
            .iter()
            .find(|write| write.name == "deferred")
            .expect("deferred write is indexed");

        assert!(is_matching_constructor_write(direct.node, false, source));
        assert!(!is_matching_constructor_write(deferred.node, false, source));
    }

    #[test]
    fn lambda_initializer_block_does_not_make_auto_property_executable() {
        let source = r"
class C
{
    System.Func<int> Value { get; } = () => { return 1; };
    int Computed { get { return 1; } }
}
";
        let tree = parse(source);
        let symbols = build_usage_symbols(tree.root_node(), source);
        let properties: Vec<_> = symbols
            .members
            .iter()
            .filter(|member| member.flavor == MemberFlavor::Property)
            .collect();

        assert_eq!(properties.len(), 2);
        assert!(!declares_executable_code(properties[0].declaration));
        assert!(declares_executable_code(properties[1].declaration));
    }
}
