use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::expressions::{invocation_targets, is_test_attributed};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2925 — sleeping in tests slows suites and hides races.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !is_test_attributed(method, source) {
            continue;
        }
        for invocation in collect_kinds(method, &["invocation_expression"]) {
            if invocation_targets(invocation, source, Some("Thread"), &["Sleep"]) {
                issues.push(issue(
                    language,
                    "S2925",
                    "Do not use 'Thread.Sleep()' in a test.",
                    range_of(invocation, source),
                ));
            }
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2925_flags_sleep_in_test_attributed_methods() {
        let fact = analyze_default(
            "class Tests\n{\n    [Fact]\n    void T()\n    {\n        Thread.Sleep(100);\n    }\n}\n",
        );
        assert_eq!(with_key(&fact, "csharpsquid:S2925").len(), 1);

        let test_method = analyze_default(
            "class Tests\n{\n    [TestMethod]\n    void T()\n    {\n        Thread.Sleep(50);\n    }\n}\n",
        );
        assert_eq!(with_key(&test_method, "csharpsquid:S2925").len(), 1);
    }

    #[test]
    fn s2925_spares_plain_methods_and_delay_calls() {
        let production = analyze_default(
            "class Worker\n{\n    void Wait()\n    {\n        Thread.Sleep(100);\n    }\n}\n",
        );
        assert!(with_key(&production, "csharpsquid:S2925").is_empty());

        let async_wait = analyze_default(
            "class Tests\n{\n    [Fact]\n    void T()\n    {\n        Task.Delay(100).Wait();\n    }\n}\n",
        );
        assert!(with_key(&async_wait, "csharpsquid:S2925").is_empty());
    }

    #[test]
    fn s2925_counts_each_sleep_in_a_test() {
        let report = analyze_default(
            "class Tests\n{\n    [Theory]\n    void T()\n    {\n        Thread.Sleep(1);\n        Thread.Sleep(2);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2925").len(), 2);
    }
}
