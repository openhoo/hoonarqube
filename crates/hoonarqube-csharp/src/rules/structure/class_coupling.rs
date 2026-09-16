use crate::cst::{collect_kinds, is_error_tainted, is_pascal_case, issue, node_text, range_of};
use crate::rules::expressions::first_named_child;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use std::collections::HashSet;
use tree_sitter::Node;

/// csharpsquid:S1200 — a class depending on too many other types should be
/// split. The reference platform counts symbol-bound dependencies; this
/// file-local approximation counts the distinct type names a class
/// declaration references (base types, member and signature types, object
/// creations, generic arguments, and static member accesses on other
/// types), excluding the class itself, its type parameters, and `var`/`void`
/// spellings.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class) {
            continue;
        }
        let dependencies = class_dependencies(class, source);
        if dependencies.len() > options.maximum_class_dependencies as usize {
            let anchor = class.child_by_field_name("name").unwrap_or(class);
            issues.push(issue(
                language,
                "S1200",
                format!(
                    "Split this class into smaller and more specialized ones to reduce its dependencies on other types from {} to the maximum authorized {} or less.",
                    dependencies.len(),
                    options.maximum_class_dependencies
                ),
                range_of(anchor, source),
            ));
        }
    }
    issues
}

/// Distinct referenced type names of one class declaration.
fn class_dependencies(class: Node<'_>, source: &str) -> HashSet<String> {
    let mut excluded: HashSet<String> = class
        .child_by_field_name("name")
        .map(|name| node_text(name, source).to_string())
        .into_iter()
        .collect();
    excluded.extend(["var".to_string(), "void".to_string()]);
    for list in collect_kinds(class, &["type_parameter_list"]) {
        let mut cursor = list.walk();
        for parameter in list
            .children(&mut cursor)
            .filter(|child| child.kind() == "type_parameter")
        {
            if let Some(name) = first_named_child(parameter) {
                excluded.insert(node_text(name, source).to_string());
            }
        }
    }
    let declared_values = declared_value_names(class, source);
    let mut dependencies = HashSet::new();
    let mut cursor = class.walk();
    for child in class.children(&mut cursor) {
        collect_dependencies(
            child,
            source,
            &excluded,
            &declared_values,
            &mut dependencies,
        );
    }
    dependencies
}

/// Names of locals, parameters, fields, properties, methods, and catch
/// variables declared inside the class: a `member_access_expression` rooted
/// at one of these names is an instance chain, not a static type access.
fn declared_value_names(class: Node<'_>, source: &str) -> HashSet<String> {
    const OWNER_KINDS: [&str; 8] = [
        "variable_declarator",
        "parameter",
        "property_declaration",
        "method_declaration",
        "local_function_statement",
        "catch_declaration",
        "declaration_expression",
        "event_declaration",
    ];
    let mut names = HashSet::new();
    for owner in collect_kinds(class, &OWNER_KINDS) {
        if let Some(name) = owner.child_by_field_name("name") {
            names.insert(node_text(name, source).to_string());
        }
    }
    names
}

/// Type-position parents whose children are type spellings without a
/// dedicated `type`/`returns` field.
const TYPE_PARENT_KINDS: [&str; 6] = [
    "base_list",
    "type_argument_list",
    "attribute",
    "explicit_interface_specifier",
    "type_parameter_constraint",
    "function_pointer_type",
];

/// Whether `node` itself is written where the grammar expects a type.
fn in_type_position(node: Node<'_>) -> bool {
    let Some(parent) = node.parent() else {
        return false;
    };
    if parent
        .child_by_field_name("type")
        .is_some_and(|field| field.id() == node.id())
        || parent
            .child_by_field_name("returns")
            .is_some_and(|field| field.id() == node.id())
    {
        return true;
    }
    if matches!(parent.kind(), "as_expression" | "is_expression")
        && parent
            .child_by_field_name("right")
            .is_some_and(|field| field.id() == node.id())
    {
        return true;
    }
    TYPE_PARENT_KINDS.contains(&parent.kind())
}

/// The simple name a type-spelling node contributes (`List<int>` → `List`,
/// `System.Data.DbType` → `DbType`); `None` for non-name spellings.
fn type_spelling_name<'a>(node: Node<'_>, source: &'a str) -> Option<&'a str> {
    match node.kind() {
        "identifier" | "predefined_type" => Some(node_text(node, source)),
        "generic_name" => first_named_child(node)
            .filter(|name| name.kind() == "identifier")
            .map(|name| node_text(name, source)),
        "qualified_name" | "alias_qualified_name" => {
            let mut cursor = node.walk();
            let last = node
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .last()?;
            match last.kind() {
                "identifier" => Some(node_text(last, source)),
                "generic_name" => first_named_child(last)
                    .filter(|name| name.kind() == "identifier")
                    .map(|name| node_text(name, source)),
                _ => None,
            }
        }
        _ => None,
    }
}

/// The leftmost identifier of a dotted expression (`a.b.c` → `a`).
fn leftmost_identifier<'a>(mut node: Node<'a>, source: &'a str) -> Option<&'a str> {
    loop {
        match node.kind() {
            "identifier" => return Some(node_text(node, source)),
            "member_access_expression" => node = first_named_child(node)?,
            _ => return None,
        }
    }
}

/// The last identifier of a dotted expression (`a.b.c` → `c`).
fn last_identifier<'a>(node: Node<'a>, source: &'a str) -> Option<&'a str> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .filter(|child| child.is_named() && child.kind() == "identifier")
        .last()
        .map(|name| node_text(name, source))
}

/// Whether a `member_access_expression` reads a static member of another
/// type, contributing that type's name: `OpCodes.Ldloc` → `OpCodes`,
/// `System.Console.WriteLine` → `Console`. Instance chains rooted at a
/// declared value name or `this` contribute nothing.
fn static_accessed_type<'a>(
    node: Node<'a>,
    source: &'a str,
    declared: &HashSet<String>,
) -> Option<&'a str> {
    let receiver = first_named_child(node)?;
    match receiver.kind() {
        "identifier" => {
            let text = node_text(receiver, source);
            (is_pascal_case(text) && !declared.contains(text)).then_some(text)
        }
        "member_access_expression" => {
            let root = leftmost_identifier(receiver, source)?;
            (is_pascal_case(root) && !declared.contains(root))
                .then(|| last_identifier(receiver, source))
                .flatten()
        }
        _ => None,
    }
}

fn collect_dependencies(
    node: Node<'_>,
    source: &str,
    excluded: &HashSet<String>,
    declared: &HashSet<String>,
    dependencies: &mut HashSet<String>,
) {
    let kind = node.kind();
    if TYPE_DECLARATION_KINDS.contains(&kind) {
        // Nested type declarations own their own dependency sets.
        return;
    }
    if matches!(
        kind,
        "identifier"
            | "generic_name"
            | "qualified_name"
            | "alias_qualified_name"
            | "predefined_type"
    ) && in_type_position(node)
    {
        if let Some(name) = type_spelling_name(node, source)
            && !excluded.contains(name)
        {
            dependencies.insert(name.to_string());
        }
        // `generic_name` arguments are separate dependencies; a qualified
        // name collapses to its last segment, so only a generic tail keeps
        // walking into its argument list.
        if kind == "generic_name" {
            let mut cursor = node.walk();
            for child in node.children(&mut cursor) {
                collect_dependencies(child, source, excluded, declared, dependencies);
            }
        } else if matches!(kind, "qualified_name" | "alias_qualified_name") {
            let mut cursor = node.walk();
            if let Some(tail) = node
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .last()
                .filter(|tail| tail.kind() == "generic_name")
            {
                collect_dependencies(tail, source, excluded, declared, dependencies);
            }
        }
        return;
    }
    if kind == "member_access_expression"
        && node
            .parent()
            .is_none_or(|parent| parent.kind() != "member_access_expression")
        && let Some(name) = static_accessed_type(node, source, declared)
        && !excluded.contains(name)
    {
        dependencies.insert(name.to_string());
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_dependencies(child, source, excluded, declared, dependencies);
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S1200";

    fn coupled_class(dependency_count: usize) -> String {
        let mut fields = String::new();
        let mut deps = String::new();
        for index in 0..dependency_count {
            fields.push_str(format!("    private Dep{index} _f{index};\n").as_str());
            deps.push_str(format!("class Dep{index} {{}}\n").as_str());
        }
        format!("class Coupled\n{{\n{fields}}}\n{deps}")
    }

    #[test]
    fn s1200_flags_class_over_the_dependency_threshold() {
        let report = analyze_default(&coupled_class(31));
        let flagged = with_key(&report, KEY);
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 1);
        assert!(flagged[0].message.contains("from 31"));
    }

    #[test]
    fn s1200_ignores_class_at_the_dependency_threshold() {
        let report = analyze_default(&coupled_class(30));
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1200_ignores_small_classes() {
        let report = analyze_default(
            "class Small\n{\n    private Helper _helper;\n    int M(string text) => text.Length;\n}\nclass Helper {}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s1200_counts_generic_arguments_and_static_accesses() {
        let mut fields = String::new();
        let mut deps = String::new();
        for index in 0..28 {
            fields.push_str(format!("    private Dep{index} _f{index};\n").as_str());
            deps.push_str(format!("class Dep{index} {{}}\n").as_str());
        }
        let source = format!(
            "class Coupled\n{{\n{fields}    System.Collections.Generic.List<Extra> _list;\n    void M() {{ StaticHelper.Run(); }}\n}}\n{deps}class Extra {{}}\nclass StaticHelper {{}}\n"
        );
        let report = analyze_default(&source);
        let flagged = with_key(&report, KEY);
        assert_eq!(flagged.len(), 1);
        assert!(flagged[0].message.contains("from 31"));
    }

    #[test]
    fn s1200_excludes_self_type_parameters_and_var() {
        let mut fields = String::new();
        let mut deps = String::new();
        for index in 0..30 {
            fields.push_str(format!("    private Dep{index} _f{index};\n").as_str());
            deps.push_str(format!("class Dep{index} {{}}\n").as_str());
        }
        // 30 real dependencies plus self, T, and var spellings: still clean.
        let source = format!(
            "class Coupled<T>\n{{\n{fields}    private Coupled<T> _self;\n    T M<T>(T value)\n    {{\n        var local = value;\n        return local;\n    }}\n}}\n{deps}"
        );
        let report = analyze_default(&source);
        assert!(with_key(&report, KEY).is_empty());
    }
}
