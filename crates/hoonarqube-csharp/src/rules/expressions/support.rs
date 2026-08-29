use crate::cst::{
    ancestors_of, attributes_of, canonical_identifier, collect_kinds, is_error_tainted,
    modifiers_of, node_text, parameters_of,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use crate::rules::structure::is_statement_kind;
use tree_sitter::Node;

/// The operator token of a binary, assignment, or prefix unary expression.
/// Anonymous tokens carry their spelling as node kind, so no source text is
/// needed.
pub(crate) fn operator_of(expression: Node<'_>) -> Option<&'static str> {
    const OPERATORS: [&str; 27] = [
        "==", "!=", "<", ">", "<=", ">=", "&&", "||", "??", "+", "-", "*", "/", "%", "&", "|", "^",
        "<<", ">>", ">>>", "=", "+=", "-=", "++", "--", "!", "~",
    ];
    let mut cursor = expression.walk();
    let kind = expression
        .children(&mut cursor)
        .find(|child| !child.is_named())?
        .kind();
    OPERATORS
        .iter()
        .find(|operator| **operator == kind)
        .copied()
}

/// The two operand expressions of a binary or assignment expression.
pub(crate) fn binary_operands<'t>(expression: Node<'t>) -> Option<(Node<'t>, Node<'t>)> {
    let mut cursor = expression.walk();
    let operands: Vec<Node<'t>> = expression
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect();
    match operands.as_slice() {
        [left, right] => Some((*left, *right)),
        _ => None,
    }
}

/// Comparison expressions as `(expression, left, right)` triples; tainted
/// subtrees are skipped.
pub(crate) fn comparisons(root: Node<'_>) -> Vec<(Node<'_>, Node<'_>, Node<'_>)> {
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|expression| !is_error_tainted(*expression))
        .filter_map(|expression| {
            let (left, right) = binary_operands(expression)?;
            matches!(
                operator_of(expression),
                Some("==" | "!=" | "<" | ">" | "<=" | ">=")
            )
            .then_some((expression, left, right))
        })
        .collect()
}

/// The first named child (the sole operand of a prefix unary expression).
pub(crate) fn first_named_child(node: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor).find(tree_sitter::Node::is_named)
}

/// The plain identifier an expression denotes: identifiers themselves and
/// the member name of a member access (`x.Count` → `Count`).
pub(crate) fn expression_name<'a>(expression: Node<'_>, source: &'a str) -> Option<&'a str> {
    match expression.kind() {
        "identifier" => Some(canonical_identifier(node_text(expression, source))),
        "member_access_expression" => {
            let mut cursor = expression.walk();
            let named: Vec<Node> = expression
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect();
            let last = named.last()?;
            (last.kind() == "identifier").then(|| canonical_identifier(node_text(*last, source)))
        }
        _ => None,
    }
}

/// Whether the operand is the literal `0`.
pub(crate) fn is_zero_literal(operand: Node<'_>, source: &str) -> bool {
    operand.kind() == "integer_literal"
        && integer_literal_value(node_text(operand, source)) == Some(0)
}

/// Parses an integer literal's binary, decimal, or hexadecimal value.
pub(crate) fn integer_literal_value(literal_text: &str) -> Option<u64> {
    let trimmed = literal_text.trim_end_matches(['u', 'U', 'l', 'L']);
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        let cleaned: String = hex.chars().filter(char::is_ascii_hexdigit).collect();
        return u64::from_str_radix(&cleaned, 16).ok();
    }
    if let Some(binary) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        let cleaned: String = binary
            .chars()
            .filter(|character| *character == '0' || *character == '1')
            .collect();
        return u64::from_str_radix(&cleaned, 2).ok();
    }
    if !trimmed.chars().all(|c| c.is_ascii_digit() || c == '_') {
        return None;
    }
    trimmed
        .chars()
        .filter(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

/// Names of fields and properties declared directly by a type.
pub(crate) fn field_and_property_names(
    type_declaration: Node<'_>,
    source: &str,
) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    for member in type_members(type_declaration) {
        match member.kind() {
            "field_declaration" | "event_field_declaration" => {
                for declarator in field_declarators(member) {
                    if let Some(identifier) = first_named_child(declarator)
                        && identifier.kind() == "identifier"
                    {
                        names.insert(
                            canonical_identifier(node_text(identifier, source)).to_string(),
                        );
                    }
                }
            }
            "property_declaration" => {
                if let Some(name) = member.child_by_field_name("name") {
                    names.insert(canonical_identifier(node_text(name, source)).to_string());
                }
            }
            _ => {}
        }
    }
    names
}

/// Variable declarators belonging directly to a field or event-field
/// declaration. Declarators inside lambda initializers are excluded.
pub(crate) fn field_declarators(field: Node<'_>) -> Vec<Node<'_>> {
    direct_named_children(field)
        .find(|child| child.kind() == "variable_declaration")
        .map(|declaration| {
            direct_named_children(declaration)
                .filter(|child| child.kind() == "variable_declarator")
                .collect()
        })
        .unwrap_or_default()
}

/// Boolean-literal value on either side of a comparison, if present.
pub(crate) fn boolean_literal_side(left: Node<'_>, right: Node<'_>, source: &str) -> Option<bool> {
    for operand in [left, right] {
        if operand.kind() == "boolean_literal" {
            return Some(node_text(operand, source) == "true");
        }
    }
    None
}

/// Attribute spellings that mark a method as part of a test suite.
const TEST_ATTRIBUTE_NAMES: [&str; 10] = [
    "Test",
    "Fact",
    "Theory",
    "TestCase",
    "TestMethod",
    "TestInitialize",
    "TestCleanup",
    "SetUp",
    "TearDown",
    "OneTimeSetUp",
];

/// Statements directly inside a plain block.
pub(crate) fn block_statements(block: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = block.walk();
    block
        .children(&mut cursor)
        .filter(|child| child.is_named() && is_statement_kind(child.kind()))
        .collect()
}

/// Whether a declaration carries a test-suite attribute.
pub(crate) fn is_test_attributed(declaration: Node<'_>, source: &str) -> bool {
    attributes_of(declaration, source)
        .iter()
        .any(|name| TEST_ATTRIBUTE_NAMES.contains(name))
}

/// The nearest enclosing type declaration, if any.
pub(crate) fn enclosing_type(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
}

/// The nearest callable declaration owning `node`. Lambdas and anonymous
/// methods count as separate callables so their declarations do not leak into
/// an enclosing method's analysis.
pub(crate) fn enclosing_callable(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| is_callable_kind(ancestor.kind()))
}

/// Type spelling of the visible declaration bound to a bare identifier.
/// Local declarations and parameters win over fields and properties.
pub(crate) fn resolved_identifier_type<'a>(
    identifier: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    local_identifier_type(identifier, source)
        .or_else(|| enclosing_type(identifier).and_then(|ty| member_type(ty, identifier, source)))
}

/// Type spelling of a visible local or parameter bound to a bare identifier.
pub(crate) fn local_identifier_type<'a>(identifier: Node<'_>, source: &'a str) -> Option<&'a str> {
    let wanted = (identifier.kind() == "identifier")
        .then(|| canonical_identifier(node_text(identifier, source)))?;
    let mut owner = identifier.parent();
    while let Some(node) = owner {
        if (is_callable_kind(node.kind()) || node.kind() == "compilation_unit")
            && let Some(declaration_type) = local_type_in_owner(node, identifier, wanted, source)
        {
            return Some(declaration_type);
        }
        owner = node.parent();
    }
    None
}

const CALLABLE_KINDS: [&str; 9] = [
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "conversion_operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "lambda_expression",
    "anonymous_method_expression",
];

fn is_callable_kind(kind: &str) -> bool {
    CALLABLE_KINDS.contains(&kind)
}

fn local_type_in_owner<'a>(
    owner: Node<'_>,
    identifier: Node<'_>,
    wanted: &str,
    source: &'a str,
) -> Option<&'a str> {
    collect_kinds(owner, &["parameter", "variable_declaration"])
        .into_iter()
        .filter(|declaration| is_local_declaration(*declaration))
        .filter(|declaration| declaration.start_byte() <= identifier.start_byte())
        .filter(|declaration| declaration_owned_by(*declaration, owner))
        .filter(|declaration| declaration_visible_at(*declaration, identifier))
        .filter_map(|declaration| {
            declaration_name_matches(declaration, wanted, source)
                .then(|| declaration.child_by_field_name("type"))
                .flatten()
        })
        .max_by_key(Node::start_byte)
        .map(|type_node| node_text(type_node, source))
}

fn is_local_declaration(declaration: Node<'_>) -> bool {
    declaration.kind() == "parameter"
        || !ancestors_of(declaration).any(|ancestor| {
            matches!(
                ancestor.kind(),
                "field_declaration" | "event_field_declaration"
            )
        })
}

fn declaration_owned_by(declaration: Node<'_>, owner: Node<'_>) -> bool {
    let actual_owner = ancestors_of(declaration).find(|ancestor| {
        is_callable_kind(ancestor.kind()) || ancestor.kind() == "compilation_unit"
    });
    actual_owner.is_some_and(|actual| actual.id() == owner.id())
}

fn declaration_visible_at(declaration: Node<'_>, identifier: Node<'_>) -> bool {
    if declaration.kind() == "parameter" {
        return true;
    }
    ancestors_of(declaration)
        .find(|ancestor| {
            matches!(
                ancestor.kind(),
                "block"
                    | "switch_section"
                    | "for_statement"
                    | "foreach_statement"
                    | "using_statement"
                    | "fixed_statement"
            )
        })
        .is_none_or(|scope| {
            scope.start_byte() <= identifier.start_byte()
                && scope.end_byte() >= identifier.end_byte()
        })
}

fn declaration_name_matches(declaration: Node<'_>, wanted: &str, source: &str) -> bool {
    if declaration.kind() == "parameter" {
        return declaration
            .child_by_field_name("name")
            .is_some_and(|name| canonical_identifier(node_text(name, source)) == wanted);
    }
    direct_named_children(declaration)
        .filter(|child| child.kind() == "variable_declarator")
        .any(|declarator| {
            declarator
                .child_by_field_name("name")
                .or_else(|| first_named_child(declarator))
                .is_some_and(|name| canonical_identifier(node_text(name, source)) == wanted)
        })
}

fn member_type<'a>(type_node: Node<'_>, identifier: Node<'_>, source: &'a str) -> Option<&'a str> {
    let wanted = canonical_identifier(node_text(identifier, source));
    for member in type_members(type_node) {
        if member.kind() == "property_declaration"
            && member
                .child_by_field_name("name")
                .is_some_and(|name| canonical_identifier(node_text(name, source)) == wanted)
        {
            return member
                .child_by_field_name("type")
                .map(|ty| node_text(ty, source));
        }
        if member.kind() != "field_declaration" {
            continue;
        }
        let Some(declaration) =
            direct_named_children(member).find(|child| child.kind() == "variable_declaration")
        else {
            continue;
        };
        if declaration_name_matches(declaration, wanted, source) {
            return declaration
                .child_by_field_name("type")
                .map(|ty| node_text(ty, source));
        }
    }
    None
}

fn direct_named_children(node: Node<'_>) -> impl Iterator<Item = Node<'_>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect::<Vec<_>>()
        .into_iter()
}

/// The function expression of an invocation (`f` of `f(args)`).
pub(crate) fn invocation_function(invocation: Node<'_>) -> Option<Node<'_>> {
    first_named_child(invocation)
}

/// Method name an invocation calls (`x.Where(...)` calls `Where`).
pub(crate) fn callee_name<'a>(invocation: Node<'_>, source: &'a str) -> Option<&'a str> {
    expression_name(invocation_function(invocation)?, source)
}

/// Receiver expression of an invocation (`r` of `r.M(args)`).
pub(crate) fn invocation_receiver(invocation: Node<'_>) -> Option<Node<'_>> {
    let function = invocation_function(invocation)?;
    (function.kind() == "member_access_expression").then_some(function)?;
    first_named_child(function)
}

/// Arguments of an invocation's own argument list (nested calls excluded).
pub(crate) fn invocation_arguments(invocation: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = invocation.walk();
    invocation
        .children(&mut cursor)
        .find(|child| child.kind() == "argument_list")
        .map(|list| {
            let mut inner = list.walk();
            list.children(&mut inner)
                .filter(tree_sitter::Node::is_named)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether any call further down the receiver chain satisfies `matches`.
pub(crate) fn receiver_chain_matches(
    invocation: Node<'_>,
    source: &str,
    matches: impl Fn(&str) -> bool,
) -> bool {
    let mut current = invocation_receiver(invocation);
    while let Some(receiver) = current {
        match receiver.kind() {
            "invocation_expression" => {
                if callee_name(receiver, source).is_some_and(&matches) {
                    return true;
                }
                current = invocation_receiver(receiver);
            }
            _ => break,
        }
    }
    false
}

/// Member accesses reading one of `tails` off an owner whose qualified
/// spelling ends with `owner` (`System.GC.Collect` matches owner `GC`).
pub(crate) fn banned_member_accesses<'t>(
    root: Node<'t>,
    source: &str,
    owner: &str,
    tails: &[&str],
) -> Vec<Node<'t>> {
    collect_kinds(root, &["member_access_expression"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| {
            tails.contains(&expression_name(*node, source).unwrap_or(""))
                && first_named_child(*node)
                    .is_some_and(|receiver| node_text(receiver, source).trim().ends_with(owner))
        })
        .collect()
}

/// Whether an invocation targets one of `tails`; when `owner` is given the
/// callee must sit on a matching owner, otherwise the callee must be a bare
/// identifier.
pub(crate) fn invocation_targets(
    invocation: Node<'_>,
    source: &str,
    owner: Option<&str>,
    tails: &[&str],
) -> bool {
    let Some(function) = invocation_function(invocation) else {
        return false;
    };
    let Some(name) = expression_name(function, source) else {
        return false;
    };
    if !tails.contains(&name) {
        return false;
    }
    match owner {
        None => function.kind() == "identifier",
        Some(owner) => {
            function.kind() == "member_access_expression"
                && first_named_child(function)
                    .is_some_and(|receiver| node_text(receiver, source).trim().ends_with(owner))
        }
    }
}

/// The type spelling of a `new T(...)` creation.
pub(crate) fn creation_type_text<'a>(creation: Node<'_>, source: &'a str) -> &'a str {
    first_named_child(creation).map_or("", |type_node| node_text(type_node, source))
}

/// Bare `new T(...)` expressions used directly as statements.
pub(crate) fn bare_creations(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .parent()
                .is_some_and(|parent| parent.kind() == "expression_statement")
        })
        .collect()
}

/// The operator token of an `operator_declaration` (`==`, `+`, ...).
pub(crate) fn overloaded_operator(declaration: Node<'_>) -> Option<&'static str> {
    const TOKENS: [&str; 15] = [
        "==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "%", "&", "|", "^", "<<",
    ];
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .filter(|child| !child.is_named())
        .find_map(|child| TOKENS.iter().find(|token| **token == child.kind()).copied())
}

/// Names of overridden methods declared directly by a type.
pub(crate) fn overridden_names(
    type_node: Node<'_>,
    source: &str,
) -> std::collections::HashSet<String> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter(|method| has_modifier(&modifiers_of(*method, source), "override"))
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| canonical_identifier(node_text(name, source)).to_string())
        .collect()
}

/// Members of a kind declared directly by a type.
pub(crate) fn member_declarations_of_kind<'t>(type_node: Node<'t>, kind: &str) -> Vec<Node<'t>> {
    type_members(type_node)
        .into_iter()
        .filter(|member| member.kind() == kind)
        .collect()
}

/// Names of every method declared directly by a type.
pub(crate) fn declared_method_names(
    type_node: Node<'_>,
    source: &str,
) -> std::collections::HashSet<String> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter_map(|method| method.child_by_field_name("name"))
        .map(|name| canonical_identifier(node_text(name, source)).to_string())
        .collect()
}

/// Operator tokens of every operator overload declared directly by a type.
pub(crate) fn overloaded_operators(type_node: Node<'_>) -> Vec<&'static str> {
    member_declarations_of_kind(type_node, "operator_declaration")
        .into_iter()
        .filter_map(overloaded_operator)
        .collect()
}

/// The first member of a kind carrying `name`, for anchoring issues.
pub(crate) fn member_named<'t>(
    type_node: Node<'t>,
    kind: &str,
    name: &str,
    source: &str,
) -> Option<Node<'t>> {
    member_declarations_of_kind(type_node, kind)
        .into_iter()
        .find(|member| {
            member
                .child_by_field_name("name")
                .is_some_and(|member_name| {
                    canonical_identifier(node_text(member_name, source))
                        == canonical_identifier(name)
                })
        })
}

/// Arity of every constructor declared directly by a type.
pub(crate) fn constructor_arities(type_node: Node<'_>) -> Vec<usize> {
    member_declarations_of_kind(type_node, "constructor_declaration")
        .into_iter()
        .map(|ctor| parameters_of(ctor).len())
        .collect()
}

/// Declarator names of fields declared directly by a type whose fields lack
/// `readonly` (and are not constants).
pub(crate) fn mutable_field_names<'t>(type_node: Node<'t>, source: &'t str) -> Vec<&'t str> {
    member_declarations_of_kind(type_node, "field_declaration")
        .into_iter()
        .filter(|field| {
            let modifiers = modifiers_of(*field, source);
            !has_modifier(&modifiers, "readonly") && !has_modifier(&modifiers, "const")
        })
        .flat_map(field_declarators)
        .filter_map(|declarator| first_named_child(declarator))
        .filter_map(|identifier| expression_name(identifier, source))
        .collect()
}

/// Whether `scope` mentions `name` as a bare identifier.
pub(crate) fn references_identifier(scope: Node<'_>, name: &str, source: &str) -> bool {
    collect_kinds(scope, &["identifier"])
        .iter()
        .any(|identifier| {
            canonical_identifier(node_text(*identifier, source)) == canonical_identifier(name)
        })
}

/// The member name invoked through `base.Member(...)` (`base.Equals(x)` →
/// `Equals`); `None` for other receivers.
pub(crate) fn base_call_name<'a>(invocation: Node<'_>, source: &'a str) -> Option<&'a str> {
    let function = invocation_function(invocation)?;
    if function.kind() != "member_access_expression" {
        return None;
    }
    // `base` is an unnamed keyword token, so the raw first child is needed.
    let mut cursor = function.walk();
    let receiver = function.children(&mut cursor).next()?;
    (node_text(receiver, source).trim() == "base")
        .then(|| expression_name(function, source))
        .flatten()
}

/// `(parameter name, body)` of a single-parameter lambda.
pub(crate) fn lambda_shape<'s>(lambda: Node<'s>, source: &'s str) -> Option<(&'s str, Node<'s>)> {
    let mut cursor = lambda.walk();
    let named: Vec<Node> = lambda
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .collect();
    let body = *named.last()?;
    let head = *named.first()?;
    let parameter = match head.kind() {
        // The whole name rides on the `implicit_parameter` node itself.
        "implicit_parameter" => canonical_identifier(node_text(head, source)),
        "parameter_list" => {
            let parameter = first_named_child(head)?;
            let identifiers = collect_kinds(parameter, &["identifier"]);
            identifiers
                .last()
                .map(|id| canonical_identifier(node_text(*id, source)))?
        }
        _ => return None,
    };
    (named.len() >= 2).then_some((parameter, body))
}

/// Whether any `string`-typed local declares `name` under `scope`.
pub(crate) fn declares_string_local(scope: Node<'_>, name: &str, source: &str) -> bool {
    collect_kinds(scope, &["variable_declaration"])
        .iter()
        .any(|declaration| {
            let typed_string = first_named_child(*declaration)
                .is_some_and(|type_node| node_text(type_node, source) == "string");
            collect_kinds(*declaration, &["variable_declarator"])
                .iter()
                .any(|declarator| {
                    let names_match = first_named_child(*declarator)
                        .and_then(|identifier| expression_name(identifier, source))
                        == Some(name);
                    names_match
                        && (typed_string
                            || !collect_kinds(*declarator, &["string_literal"]).is_empty())
                })
        })
}
