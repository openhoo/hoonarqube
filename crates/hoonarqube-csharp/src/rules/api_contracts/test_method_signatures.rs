use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::security::return_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3433 — runners only invoke public `void`/`Task` test
/// methods.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let attributes = attributes_of(method, source);
        if !attributes
            .iter()
            .any(|attribute| TEST_METHOD_ATTRIBUTE_NAMES.contains(attribute))
        {
            continue;
        }
        let xunit = attributes
            .iter()
            .any(|attribute| matches!(*attribute, "Fact" | "Theory"));
        let modifiers = modifiers_of(method, source);
        let mut faults = Vec::new();
        if !xunit && !has_modifier(&modifiers, "public") {
            faults.push("'public'");
        }
        if method.child_by_field_name("type_parameters").is_some()
            && !attributes
                .iter()
                .any(|attribute| matches!(*attribute, "Theory" | "TestCase" | "TestCaseSource"))
        {
            faults.push("non-generic");
        }
        if has_modifier(&modifiers, "async") && return_type_text(method, source) == "void" && !xunit
        {
            faults.push("non-'async' or return 'Task'");
        }
        if !faults.is_empty() {
            let name = method.child_by_field_name("name").unwrap_or(method);
            issues.push(issue(
                language,
                "S3433",
                format!("Make this test method {}.", faults.join(" and ")),
                range_of(name, source),
            ));
        }
    }
    issues
}

const TEST_METHOD_ATTRIBUTE_NAMES: [&str; 7] = [
    "Test",
    "Fact",
    "Theory",
    "TestCase",
    "TestCaseSource",
    "TestMethod",
    "DataTestMethod",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3433_flags_non_public_nunit_test_methods() {
        let report = analyze_default(
            "class T\n{\n    [Fact]\n    int Compute() { return 1; }\n\n    [Test]\n    internal Task Load() { return Task.CompletedTask; }\n\n    [TestMethod]\n    public ValueTask Save() { return ValueTask.CompletedTask; }\n\n    public int Plain() { return 2; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3433");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[0].message, "Make this test method 'public'.");
    }

    #[test]
    fn s3433_allows_generic_task_return_shapes() {
        let report = analyze_default(
            "class T\n{\n    [Fact]\n    public Task<int> Fetch()\n    {\n        return Task.FromResult(1);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3433").is_empty());
    }

    #[test]
    fn s3433_ignores_non_public_lifecycle_hooks() {
        let report = analyze_default(
            "class T\n{\n    [SetUp]\n    internal void Prepare() { }\n\n    [TestCleanup]\n    private void Clean() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3433").is_empty());
    }

    #[test]
    fn s3433_checks_data_driven_test_methods() {
        let report = analyze_default(
            "class T\n{\n    [TestCaseSource(nameof(Cases))]\n    internal void NUnitCase(int value) { }\n\n    [DataTestMethod]\n    internal void MsTestCase(int value) { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3433");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 4);
        assert_eq!(flagged[1].range.start.line, 7);
    }
}
