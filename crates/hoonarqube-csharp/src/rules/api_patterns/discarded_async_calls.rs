use crate::CsLanguage;
use crate::cst::{
    canonical_identifier, collect_kinds, is_error_tainted, issue, node_text, range_of,
};
use crate::rules::expressions::{
    callee_name, enclosing_callable, invocation_receiver, resolved_identifier_type,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6966 — use an available awaitable API from async methods.
///
/// The sequence LINQ suggestions (`ToListAsync`, `FirstOrDefaultAsync`) are
/// gated on the receiver's resolved static type: a synchronous
/// `Enumerable.ToList()` over `IEnumerable<T>` has no awaitable replacement,
/// so suggesting one would not compile. Receivers that do not resolve keep
/// the historical report.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter_map(|invocation| {
            let callee = callee_name(invocation, source)?;
            let async_alternative = match callee {
                "Read" => "ReadAsync",
                "ReadAllLines" => "ReadAllLinesAsync",
                "ToList" => "ToListAsync",
                "FirstOrDefault" => "FirstOrDefaultAsync",
                _ => return None,
            };
            let inside_async = enclosing_callable(invocation).is_some_and(|callable| {
                crate::cst::modifiers_of(callable, source).contains(&"async")
            });
            if !inside_async {
                return None;
            }
            let sequence_linq = matches!(callee, "ToList" | "FirstOrDefault");
            (!sequence_linq || receiver_admits_async(root, invocation, source))
                .then_some((invocation, async_alternative))
        })
        .map(|(invocation, async_alternative)| {
            issue(
                language,
                "S6966",
                format!("Await {async_alternative} instead."),
                range_of(invocation, source),
            )
        })
        .collect()
}

/// Whether the invocation receiver's resolved type admits the async
/// alternative. Only a provably synchronous `IEnumerable` sequence suppresses
/// the suggestion; anything unresolved stays reportable.
fn receiver_admits_async(root: Node<'_>, invocation: Node<'_>, source: &str) -> bool {
    let Some(receiver) = invocation_receiver(invocation) else {
        return true;
    };
    match receiver.kind() {
        "identifier" | "member_access_expression" => {
            match resolved_identifier_type(receiver, source) {
                Some("var") => var_initializer_admits(root, receiver, source),
                Some(type_text) => !is_sync_enumerable_type(type_text),
                None => true,
            }
        }
        "invocation_expression" => callee_name(receiver, source).is_none_or(|callee| {
            let returns = same_file_return_types(root, callee, source);
            !returns.is_empty() && returns.iter().all(|text| !is_sync_enumerable_type(text))
        }),
        _ => true,
    }
}

/// Resolves a `var` local initialized directly from a call: the nearest
/// same-callable preceding declarator of that name must declare `var` and
/// initialize from an invocation, whose same-file return types decide.
fn var_initializer_admits(root: Node<'_>, receiver: Node<'_>, source: &str) -> bool {
    let wanted = canonical_identifier(node_text(receiver, source));
    let callable = enclosing_callable(receiver);
    let initializer = collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.start_byte() < receiver.start_byte())
        .filter(|declarator| enclosing_callable(*declarator) == callable)
        .filter(|declarator| {
            declarator
                .child_by_field_name("name")
                .is_some_and(|name| canonical_identifier(node_text(name, source)) == wanted)
        })
        .max_by_key(tree_sitter::Node::start_byte)
        .and_then(|declarator| {
            let declaration = declarator.parent()?;
            let declared = declaration.child_by_field_name("type")?;
            (node_text(declared, source).trim() == "var").then_some(())?;
            let mut declarator_cursor = declarator.walk();
            // The grammar inlines the initializer after the declarator's
            // name: the second named child is the `=` value, when present.
            let initializer = declarator
                .children(&mut declarator_cursor)
                .filter(tree_sitter::Node::is_named)
                .nth(1)?;
            (initializer.kind() == "invocation_expression").then_some(initializer)
        });
    let Some(initializer) = initializer else {
        return true;
    };
    let Some(callee) = callee_name(initializer, source) else {
        return true;
    };
    let returns = same_file_return_types(root, callee, source);
    !returns.is_empty() && returns.iter().all(|text| !is_sync_enumerable_type(text))
}

/// Return-type spellings of every same-file method or local function with the
/// callee's name. Overloads with differing returns keep the suggestion
/// reportable unless every one is a synchronous `IEnumerable`.
fn same_file_return_types<'t>(root: Node<'t>, callee: &str, source: &'t str) -> Vec<&'t str> {
    collect_kinds(root, &["method_declaration", "local_function_statement"])
        .into_iter()
        .filter_map(|callable| {
            let name = callable.child_by_field_name("name")?;
            (canonical_identifier(node_text(name, source)) == callee).then_some(())?;
            callable
                .child_by_field_name("returns")
                .or_else(|| callable.child_by_field_name("type"))
                .map(|returns| node_text(returns, source))
        })
        .collect()
}

/// Whether a resolved type spelling is the synchronous `IEnumerable` sequence
/// (any qualification, type arguments, or nullability annotation).
fn is_sync_enumerable_type(type_text: &str) -> bool {
    crate::cst::simple_name(type_text.trim().trim_end_matches('?')) == "IEnumerable"
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6966_isolated_to_nearest_local_function_async_context() {
        let async_local = analyze_default(
            "class C\n{\n    void Outer(List<int> items)\n    {\n        async Task Local()\n        {\n            items.ToList();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&async_local, "csharpsquid:S6966");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[0].range.start.column, 12);
        assert_eq!(flagged[0].message, "Await ToListAsync instead.");

        let sync_local = analyze_default(
            "class C\n{\n    async Task Outer(List<int> items)\n    {\n        void Local()\n        {\n            items.ToList();\n        }\n    }\n}\n",
        );
        assert!(with_key(&sync_local, "csharpsquid:S6966").is_empty());
    }
    #[test]
    fn s6966_sync_enumerable_receivers_are_not_offered_to_list_async() {
        let report = analyze_default(
            "using System.Collections.Generic;\nusing System.Linq;\nusing System.Threading.Tasks;\nclass Materializer\n{\n    async Task<int> MaterializeAsync(IEnumerable<int> results)\n    {\n        return results.ToList();\n    }\n}\n",
        );
        assert!(
            with_key(&report, "csharpsquid:S6966").is_empty(),
            "synchronous Enumerable.ToList() over IEnumerable<T> has no ToListAsync to suggest"
        );
    }

    #[test]
    fn s6966_qualified_sync_enumerable_receivers_stay_clean() {
        let report = analyze_default(
            "class Qualified\n{\n    async System.Threading.Tasks.Task<int> DrainAsync(System.Collections.Generic.IEnumerable<int> results)\n    {\n        return results.ToList();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6966").is_empty());
    }

    #[test]
    fn s6966_var_from_sync_enumerable_method_stays_clean() {
        let report = analyze_default(
            "using System.Collections.Generic;\nusing System.Threading.Tasks;\nclass Provider\n{\n    IEnumerable<int> Page() => new int[0];\n    async Task<int> DrainAsync()\n    {\n        var results = Page();\n        return results.ToList();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6966").is_empty());
    }

    #[test]
    fn s6966_unresolved_receivers_remain_reportable() {
        let report = analyze_default(
            "using System.Collections.Generic;\nusing System.Linq;\nusing System.Threading.Tasks;\nclass Keeper\n{\n    async Task<int> KeepAsync()\n    {\n        var items = new List<int>();\n        return items.ToList();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6966");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 9);
    }
}
