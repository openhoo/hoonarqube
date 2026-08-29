use super::support::collect_kinds_in_callable;
use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, range_of};
use crate::rules::dataflow::callable_blocks;
use crate::rules::expressions::{callee_name, invocation_function, invocation_receiver};
use hoonarqube_ir::Issue;
use std::collections::HashMap;
use tree_sitter::Node;

/// csharpsquid:S4583 — every delegate `BeginInvoke` needs a matching
/// `EndInvoke` on the same receiver or the async machinery leaks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let mut unpaired: HashMap<&str, Vec<Node<'_>>> = HashMap::new();
        for call in collect_kinds_in_callable(body, &["invocation_expression"]) {
            if is_error_tainted(call) {
                continue;
            }
            let Some(receiver) = invocation_receiver(call) else {
                continue;
            };
            let receiver = node_text(receiver, source);
            match callee_name(call, source) {
                Some("BeginInvoke") => unpaired.entry(receiver).or_default().push(call),
                Some("EndInvoke") => {
                    if let Some(begins) = unpaired.get_mut(receiver) {
                        begins.pop();
                    }
                }
                _ => {}
            }
        }
        let mut begins: Vec<Node<'_>> = unpaired.into_values().flatten().collect();
        begins.sort_unstable_by_key(tree_sitter::Node::start_byte);
        for begin in begins {
            let anchor = invocation_function(begin)
                .and_then(|function| {
                    collect_kinds_in_callable(function, &["identifier"])
                        .into_iter()
                        .last()
                })
                .unwrap_or(begin);
            issues.push(issue(
                language,
                "S4583",
                "Pair this \"BeginInvoke\" with an \"EndInvoke\".",
                range_of(anchor, source),
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4583_does_not_pair_with_an_earlier_endinvoke() {
        let report = analyze_default(
            "class C\n{\n    void M(Delegate work, IAsyncResult result)\n    {\n        work.EndInvoke(result);\n        work.BeginInvoke(null, null);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4583").len(), 1);
    }

    #[test]
    fn s4583_requires_one_endinvoke_per_begininvoke() {
        let report = analyze_default(
            "class C\n{\n    void M(Delegate work)\n    {\n        var first = work.BeginInvoke(null, null);\n        var second = work.BeginInvoke(null, null);\n        work.EndInvoke(second);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4583").len(), 1);
    }

    #[test]
    fn s4583_does_not_pair_across_local_functions() {
        let report = analyze_default(
            "class C\n{\n    void M(Delegate work, IAsyncResult result)\n    {\n        work.BeginInvoke(null, null);\n        void Local()\n        {\n            work.EndInvoke(result);\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4583").len(), 1);
    }
}
