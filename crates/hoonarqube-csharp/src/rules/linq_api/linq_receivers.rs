use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::project_index::ProjectTypeIndex;
use crate::rules::expressions::{
    callee_name, expression_name, first_named_child, invocation_arguments, invocation_function,
    invocation_receiver,
};
use crate::rules::literals::declarator_initializer;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use crate::rules::tier_c::support::local_type_table;
use crate::symbol_table::nearest_ancestor_of_kinds;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6602/S6603/S6605/S6608/S6609/S6613 — list-like and
/// set-like receivers have dedicated instance members that beat the
/// LINQ extensions. Bound: receivers resolvable through the local type
/// map, through a file-local or indexed method's spelled return type, or
/// through `this`; unknown receivers are never flagged.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let types = local_type_table(root, source);
    let project = options.project_type_index.as_deref();
    // One type map per enclosing type, built on first use.
    let mut cached_scope: Option<(usize, std::collections::HashMap<String, String>)> = None;
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) {
            continue;
        }
        let scope_root = nearest_ancestor_of_kinds(call, &TYPE_DECLARATION_KINDS).unwrap_or(root);
        let scope_id = scope_root.id();
        if cached_scope.as_ref().map(|(id, _)| *id) != Some(scope_id) {
            cached_scope = Some((scope_id, build_local_type_map(scope_root, source)));
        }
        let Some((_, type_map)) = cached_scope.as_ref() else {
            continue;
        };
        if let Some(issue) = linq_receiver_issue(call, source, language, type_map, &types, project)
        {
            issues.push(issue);
        }
    }
    issues
}

fn linq_receiver_issue(
    call: Node<'_>,
    source: &str,
    language: CsLanguage,
    type_map: &std::collections::HashMap<String, String>,
    types: &std::collections::HashMap<&str, Node<'_>>,
    project: Option<&ProjectTypeIndex>,
) -> Option<Issue> {
    let receiver = invocation_receiver(call)?;
    let receiver_type = mapped_receiver_type(receiver, source, type_map)
        .or_else(|| invocation_return_type(receiver, source, type_map, types, project))?;
    let callee = callee_name(call, source).unwrap_or("");
    let rule = linq_receiver_rule(&receiver_type, callee, invocation_arguments(call).len())?;
    let anchor = invocation_function(call)
        .and_then(|function| function.child_by_field_name("name"))
        .unwrap_or(call);
    Some(issue(
        language,
        rule,
        linq_receiver_message(rule, callee),
        range_of(anchor, source),
    ))
}

fn linq_receiver_rule(receiver_type: &str, callee: &str, arguments: usize) -> Option<&'static str> {
    if LIST_LIKE_TYPES.contains(&receiver_type) {
        return match (callee, arguments) {
            ("FirstOrDefault", 1..=2) => Some("S6602"),
            ("All", 1) => Some("S6603"),
            ("Any", 1) => Some("S6605"),
            ("ElementAt", 1) | ("First" | "Last", 0) => Some("S6608"),
            _ => None,
        };
    }
    // Arrays index directly; the reference platform reports the same
    // indexing suggestion for `First`/`Last`/`ElementAt` on them.
    if receiver_type.ends_with("[]") {
        return match (callee, arguments) {
            ("ElementAt", 1) | ("First" | "Last", 0) => Some("S6608"),
            _ => None,
        };
    }
    match (callee, arguments, receiver_type) {
        ("Min" | "Max", 0, "SortedSet" | "ImmutableSortedSet") => Some("S6609"),
        ("First" | "Last", 0, "LinkedList") => Some("S6613"),
        _ => None,
    }
}

fn linq_receiver_message(rule: &str, callee: &str) -> String {
    match (rule, callee) {
        ("S6602", _) => "\"Find\" method should be used instead of the \"FirstOrDefault\" extension method.".to_owned(),
        ("S6603", _) => "The collection-specific \"TrueForAll\" method should be used instead of the \"All\" extension".to_owned(),
        ("S6605", _) => "Collection-specific \"Exists\" method should be used instead of the \"Any\" extension.".to_owned(),
        ("S6608", "First") => "Indexing at 0 should be used instead of the \"Enumerable\" extension method \"First\"".to_owned(),
        ("S6608", "Last") => "Indexing at Count-1 should be used instead of the \"Enumerable\" extension method \"Last\"".to_owned(),
        ("S6608", _) => "Indexing should be used instead of the \"Enumerable\" extension method \"ElementAt\"".to_owned(),
        ("S6609", _) => format!("\"{callee}\" property of Set type should be used instead of the \"{callee}()\" extension method."),
        _ => format!("'{callee}' property of 'LinkedList' should be used instead of the '{callee}()' extension method."),
    }
}

/// Collection types with instance members that beat their LINQ
/// counterparts.
const LIST_LIKE_TYPES: [&str; 4] = ["List", "IList", "IReadOnlyList", "ArrayList"];

/// The inferred type of an expression, if the local type map knows it.
fn mapped_receiver_type(
    expression: Node<'_>,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
) -> Option<String> {
    match expression.kind() {
        "identifier" => type_map.get(node_text(expression, source)).cloned(),
        "member_access_expression" => expression_name(expression, source).and_then(|name| {
            type_map
                .get(name)
                .cloned()
                .or_else(|| Some(name.to_owned()))
        }),
        "this_expression" => nearest_ancestor_of_kinds(expression, &TYPE_DECLARATION_KINDS)
            .and_then(|owner| owner.child_by_field_name("name"))
            .map(|name| node_text(name, source).to_owned()),
        _ => None,
    }
}

/// The spelled return type of the method an invocation binds to, resolved
/// through the file-local type table or the project index. The receiver's
/// own type comes from the local type map (`_db.Fetch<Post>(…)` →
/// `Database.Fetch` → `List<T>`); unresolvable receivers stay unknown.
fn invocation_return_type(
    expression: Node<'_>,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
    types: &std::collections::HashMap<&str, Node<'_>>,
    project: Option<&ProjectTypeIndex>,
) -> Option<String> {
    if expression.kind() != "invocation_expression" {
        return None;
    }
    let owner_type = invocation_owner_type(expression, source, type_map)?;

    let method_name = invocation_method_name(expression, source)?;
    let arity = invocation_arguments(expression).len();
    if let Some(declaration) = types.get(owner_type.as_str()).copied() {
        for member in type_members(declaration) {
            if member.kind() != "method_declaration" {
                continue;
            }
            let Some(name) = member.child_by_field_name("name") else {
                continue;
            };
            if node_text(name, source) != method_name {
                continue;
            }
            let Some(returns) = member
                .child_by_field_name("returns")
                .map(|node| simple_name(node_text(node, source)).to_owned())
            else {
                continue;
            };
            return Some(returns);
        }
    }
    let project = project?;
    let mut matches = project
        .same_name_methods(&owner_type, method_name)
        .into_iter()
        .map(|(_, method)| method);
    let selected = matches
        .clone()
        .find(|method| method.parameters.len() == arity)
        .or_else(|| matches.next())?;
    (!selected.return_type.is_empty()).then(|| simple_name(&selected.return_type).to_owned())
}
/// The type an invocation binds on: the receiver's mapped type, the
/// enclosing type for `this.`/unqualified calls, or `None` for `base.` and
/// unresolvable receivers.
fn invocation_owner_type(
    expression: Node<'_>,
    source: &str,
    type_map: &std::collections::HashMap<String, String>,
) -> Option<String> {
    let function = invocation_function(expression)?;
    if function.kind() != "member_access_expression" {
        // Unqualified call: the method binds on the enclosing type.
        return enclosing_type_name(expression, source);
    }
    // `this`/`base` are anonymous tokens, so the first child decides the
    // receiver shape before the named receiver expression is consulted.
    let mut cursor = function.walk();
    match function.children(&mut cursor).next()?.kind() {
        "this" => enclosing_type_name(expression, source),
        "base" => None,
        _ => {
            let receiver = first_named_child(function)?;
            (receiver.kind() != "member_access_expression")
                .then(|| mapped_receiver_type(receiver, source, type_map))
                .flatten()
        }
    }
}

/// The simple name of the nearest enclosing type declaration.
fn enclosing_type_name(expression: Node<'_>, source: &str) -> Option<String> {
    nearest_ancestor_of_kinds(expression, &TYPE_DECLARATION_KINDS)
        .and_then(|owner| owner.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_owned())
}

/// The invoked method's simple name, covering generic callees
/// (`Fetch<Post>` → `Fetch`) that `callee_name` cannot spell.
fn invocation_method_name<'a>(invocation: Node<'a>, source: &'a str) -> Option<&'a str> {
    let function = invocation_function(invocation)?;
    let last = match function.kind() {
        "member_access_expression" => {
            let mut cursor = function.walk();
            function
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .last()?
        }
        _ => function,
    };
    match last.kind() {
        "identifier" => Some(node_text(last, source)),
        "generic_name" => first_named_child(last)
            .filter(|name| name.kind() == "identifier")
            .map(|name| node_text(name, source)),
        _ => None,
    }
}

/// Builds the per-member local type map: declarations whose type is
/// spelled (`List<int> xs`) or inferable from a constructor initializer
/// (`var xs = new List<int>()`).
fn build_local_type_map(body: Node<'_>, source: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for declaration in collect_kinds(body, &["variable_declaration", "field_declaration"]) {
        // `field_declaration` wraps its `variable_declaration`, so fall
        // back to that child when the declaration has no direct type.
        let type_node = declaration.child_by_field_name("type").or_else(|| {
            collect_kinds(declaration, &["variable_declaration"])
                .into_iter()
                .next()
                .and_then(|variable| variable.child_by_field_name("type"))
        });
        let Some(type_node) = type_node else {
            continue;
        };
        let explicit_type = simple_name(node_text(type_node, source));
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name_text = node_text(name, source).to_owned();
            if explicit_type != "var" {
                map.insert(name_text, explicit_type.to_owned());
                continue;
            }
            let inferred = declarator_initializer(declarator, name).and_then(|value| {
                value
                    .child_by_field_name("type")
                    .filter(|_| value.kind() == "object_creation_expression")
                    .map(|type_node| simple_name(node_text(type_node, source)).to_owned())
            });
            if let Some(inferred) = inferred {
                map.insert(name_text, inferred);
            }
        }
    }
    for parameter in collect_kinds(body, &["parameter"]) {
        if let (Some(type_node), Some(name)) = (
            parameter.child_by_field_name("type"),
            parameter.child_by_field_name("name"),
        ) {
            map.insert(
                node_text(name, source).to_owned(),
                simple_name(node_text(type_node, source)).to_owned(),
            );
        }
    }
    for property in collect_kinds(body, &["property_declaration"]) {
        if let (Some(type_node), Some(name)) = (
            property.child_by_field_name("type"),
            property.child_by_field_name("name"),
        ) {
            map.insert(
                node_text(name, source).to_owned(),
                simple_name(node_text(type_node, source)).to_owned(),
            );
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6608_covers_indexing_equivalents_on_list_like_receivers() {
        let report = analyze_default(
            "using System.Collections.Generic;\nclass C\n{\n    List<int> field = new List<int>();\n    int M(List<int> xs)\n    {\n        var local = new List<int>();\n        var a = xs.ElementAt(0);\n        var b = field.Last();\n        Log(a, b);\n        return 0;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6608");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 8); // document line 7
        assert_eq!(flagged[1].range.start.line, 9); // document line 8
    }

    #[test]
    fn s6608_flags_first_on_array_receivers() {
        let report = analyze_default(
            "class C\n{\n    private static readonly int[] ErrZeroRows = new int[0];\n    void M()\n    {\n        var a = ErrZeroRows.First();\n        var b = ErrZeroRows.Last();\n        var c = ErrZeroRows.ElementAt(1);\n        Log(a, b, c);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6608");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 6);
        assert_eq!(flagged[1].range.start.line, 7);
        assert_eq!(flagged[2].range.start.line, 8);
    }

    #[test]
    fn s6608_flags_first_on_file_local_list_returning_methods() {
        let report = analyze_default(
            "using System.Collections.Generic;\nclass C\n{\n    List<int> Fetch(int id) => new List<int>();\n    int M()\n    {\n        var a = Fetch(1).First();\n        var b = this.Fetch(2).First();\n        return a + b;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6608");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[1].range.start.line, 8);
    }

    #[test]
    fn s6608_unknown_or_non_list_receivers_stay_clean() {
        let report = analyze_default(
            "using System.Collections.Generic;\nclass C\n{\n    int M(string text)\n    {\n        var local = new List<int>();\n        var c = local.FirstOrDefault();\n        var d = local.Max();\n        var f = Make().First();\n        var g = text.First();\n        var h = Missing().First();\n        Log(c, d, f, g, h);\n        return 0;\n    }\n    IEnumerable<int> Make() => new List<int>();\n}\n",
        );
        for key in ["S6602", "S6603", "S6605", "S6608", "S6609", "S6613"] {
            assert!(
                with_key(&report, &format!("csharpsquid:{key}")).is_empty(),
                "{key} fired unexpectedly"
            );
        }
    }

    #[test]
    fn s6609_and_s6613_cover_set_like_receiver_shapes() {
        let report = analyze_default(
            "using System.Collections.Generic;\nclass C\n{\n    HashSet<int> hash = new HashSet<int>();\n    SortedSet<int> sorted = new SortedSet<int>();\n    LinkedList<int> chain = new LinkedList<int>();\n    IReadOnlyList<int> ro = new List<int>();\n    ArrayList raw = new ArrayList();\n    int M()\n    {\n        var b = sorted.Min(Selector);\n        var c = sorted.Max();\n        var d = chain.Last();\n        var e = ro.FirstOrDefault(x => x > 0);\n        var f = raw.All(x => x != null);\n        Log(b, c, d, e, f);\n        return 0;\n    }\n    int Selector(int x) => x;\n}\n",
        );
        let min_max = with_key(&report, "csharpsquid:S6609");
        assert_eq!(min_max[0].range.start.line, 12); // document line 11
        let ends = with_key(&report, "csharpsquid:S6613");
        assert_eq!(ends.len(), 1);
        assert_eq!(ends[0].range.start.line, 13); // document line 12
        let find = with_key(&report, "csharpsquid:S6602");
        assert_eq!(find.len(), 1);
        assert_eq!(find[0].range.start.line, 14); // document line 13
        let all = with_key(&report, "csharpsquid:S6603");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].range.start.line, 15); // document line 14
    }
}
