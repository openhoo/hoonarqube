use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, first_named_child, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6612 — `ConcurrentDictionary` factories must be delegates or
/// every caller pays the evaluation cost.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const FACTORY_METHODS: [&str; 2] = ["GetOrAdd", "AddOrUpdate"];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            FACTORY_METHODS.contains(&callee_name(*invocation, source).unwrap_or(""))
        })
        .filter(|invocation| {
            invocation_arguments(*invocation)
                .iter()
                .skip(1)
                .any(|argument| {
                    first_named_child(*argument)
                        .is_none_or(|value| value.kind() != "lambda_expression")
                })
        })
        .map(|invocation| {
            issue(
                language,
                "S6612",
                "Pass a delegate to this 'ConcurrentDictionary' method.",
                range_of(invocation, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6612_flags_eager_add_or_update_factories() {
        let report = analyze_default(
            "class C\n{\n    int Bump(System.Collections.Concurrent.ConcurrentDictionary<int, int> map)\n    {\n        return map.AddOrUpdate(1, Compute(), (key, old) => old + 1);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6612").len(), 1);
    }

    #[test]
    fn s6612_all_lambda_factories_stay_unflagged() {
        let report = analyze_default(
            "class C\n{\n    int Bump(System.Collections.Concurrent.ConcurrentDictionary<int, int> map)\n    {\n        return map.AddOrUpdate(1, key => 1, (key, old) => old + 1);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6612").is_empty());
    }
}
