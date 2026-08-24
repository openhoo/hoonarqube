use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of, simple_name};
use crate::rules::expressions::is_test_attributed;
use crate::rules::modifiers::has_modifier;
use crate::rules::security::return_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3433 — runners only invoke public `void`/`Task` test
/// methods.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !is_test_attributed(method, source) {
            continue;
        }
        if !has_modifier(&modifiers_of(method, source), "public") {
            issues.push(issue(
                language,
                "S3433",
                "Make this test method public.",
                range_of(method),
            ));
        }
        let returns = simple_name(return_type_text(method, source));
        if !TEST_RETURN_TYPES.contains(&returns) {
            issues.push(issue(
                language,
                "S3433",
                "Test methods must not return values.",
                range_of(method),
            ));
        }
    }
    issues
}

/// Return shapes valid for test methods.
const TEST_RETURN_TYPES: [&str; 3] = ["void", "Task", "ValueTask"];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3433_flags_missing_public_and_value_returns_together() {
        let report = analyze_default(
            "class T\n{\n    [Fact]\n    int Compute() { return 1; }\n\n    [Test]\n    internal Task Load() { return Task.CompletedTask; }\n\n    [TestMethod]\n    public ValueTask Save() { return ValueTask.CompletedTask; }\n\n    public int Plain() { return 2; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3433");
        assert_eq!(flagged.len(), 3);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 3);
        assert_eq!(flagged[2].range.start.line, 6);
    }

    #[test]
    fn s3433_allows_generic_task_return_shapes() {
        let report = analyze_default(
            "class T\n{\n    [Fact]\n    public Task<int> Fetch()\n    {\n        return Task.FromResult(1);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3433").is_empty());
    }
}
