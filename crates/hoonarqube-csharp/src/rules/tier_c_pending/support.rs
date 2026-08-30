use crate::cst::{collect_kinds, is_error_tainted, node_text, simple_name};
use crate::rules::expressions::{expression_name, first_named_child, invocation_arguments};
use tree_sitter::Node;

/// File-local method declarations grouped by simple name.
pub(crate) fn local_method_table<'t>(
    root: Node<'t>,
    source: &'t str,
) -> std::collections::HashMap<&'t str, Vec<Node<'t>>> {
    let mut table: std::collections::HashMap<&'t str, Vec<Node<'t>>> =
        std::collections::HashMap::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        if let Some(name) = method.child_by_field_name("name") {
            table
                .entry(node_text(name, source))
                .or_default()
                .push(method);
        }
    }
    table
}

/// Whether every argument of the invocation is positional (no `name:` label).
pub(crate) fn invocation_is_positional(invocation: Node<'_>) -> bool {
    invocation_arguments(invocation).iter().all(|argument| {
        let mut cursor = argument.walk();
        !argument
            .children(&mut cursor)
            .any(|child| child.kind() == "name_colon")
    })
}

/// Declared-type node of a field or property member.
pub(crate) fn member_declared_type(member: Node<'_>) -> Option<Node<'_>> {
    if member.kind() == "property_declaration" {
        return member.child_by_field_name("type");
    }
    let mut cursor = member.walk();
    member
        .children(&mut cursor)
        .find(|child| child.kind() == "variable_declaration")
        .and_then(|declaration| declaration.child_by_field_name("type"))
}

/// The plain name a receiver expression denotes: a bare identifier or the
/// member of a `this.Name` access.
pub(crate) fn this_or_identifier_name<'a>(
    expression: Node<'_>,
    source: &'a str,
) -> Option<&'a str> {
    match expression.kind() {
        "identifier" => Some(node_text(expression, source)),
        "member_access_expression" => {
            let object = first_named_child(expression)?;
            if object.kind() == "this_expression" {
                expression_name(expression, source)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Well-known `IDisposable` API type names backing the disposal subsets.
/// Types outside the table stay uncovered (no semantic model).
pub(crate) const DISPOSABLE_TYPES: [&str; 30] = [
    "BinaryReader",
    "BinaryWriter",
    "Bitmap",
    "Brush",
    "CancellationTokenSource",
    "CryptoStream",
    "DbConnection",
    "Font",
    "FileStream",
    "Graphics",
    "GZipStream",
    "HttpClient",
    "Icon",
    "Image",
    "MemoryStream",
    "Mutex",
    "MySqlConnection",
    "NpgsqlConnection",
    "Pen",
    "Process",
    "RegistryKey",
    "Semaphore",
    "Socket",
    "SqlConnection",
    "SqlTransaction",
    "Stream",
    "StreamReader",
    "StreamWriter",
    "TcpClient",
    "WebClient",
];

/// Strips nullable and array suffixes, then qualification: `DateTime?` and
/// `Guid[]` reduce to their bare type names.
pub(crate) fn normalized_type_name(type_text: &str) -> &str {
    let mut bare = type_text.trim();
    while let Some(head) = bare.strip_suffix("[]").or_else(|| bare.strip_suffix('?')) {
        bare = head.trim_end();
    }
    simple_name(bare)
}
