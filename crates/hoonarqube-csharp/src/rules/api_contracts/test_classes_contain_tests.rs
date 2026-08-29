use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2187 — annotated-but-empty test classes rot quietly.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| !is_error_tainted(*class_node))
        .filter(|class_node| {
            attributes_of(*class_node, source)
                .iter()
                .any(|name| TEST_CLASS_ATTRIBUTE_NAMES.contains(name))
        })
        .filter(|class_node| {
            member_declarations_of_kind(*class_node, "method_declaration")
                .iter()
                .all(|method| !is_test_method(*method, source))
        })
        .map(|class_node| {
            let name = class_node.child_by_field_name("name").unwrap_or(class_node);
            issue(
                language,
                "S2187",
                "Add some tests to this class.",
                range_of(name, source),
            )
        })
        .collect()
}

/// Attributes marking a type as a test container.
const TEST_CLASS_ATTRIBUTE_NAMES: [&str; 2] = ["TestClass", "TestFixture"];

fn is_test_method(method: Node<'_>, source: &str) -> bool {
    const TEST_METHOD_ATTRIBUTE_NAMES: [&str; 7] = [
        "Test",
        "Fact",
        "Theory",
        "TestCase",
        "TestCaseSource",
        "TestMethod",
        "DataTestMethod",
    ];
    attributes_of(method, source)
        .iter()
        .any(|name| TEST_METHOD_ATTRIBUTE_NAMES.contains(name))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2187_flags_nunit_fixtures_and_nested_containers() {
        let report = analyze_default(
            "[TestFixture]\nclass EmptyFixture { }\n\nclass Holder\n{\n    [TestClass]\n    class InnerEmpty { }\n\n    [TestFixture]\n    class InnerReal\n    {\n        [Test]\n        public void Works() { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2187");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 2);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s2187_does_not_count_lifecycle_hooks_as_tests() {
        let report = analyze_default(
            "[TestFixture]\nclass HooksOnly\n{\n    [SetUp]\n    void Prepare() { }\n\n    [TearDown]\n    void Clean() { }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2187").len(), 1);
    }

    #[test]
    fn s2187_recognizes_data_driven_test_methods() {
        let report = analyze_default(
            "[TestFixture]\nclass NUnitData\n{\n    [TestCaseSource(nameof(Cases))]\n    void Works(int value) { }\n}\n\n[TestClass]\nclass MsTestData\n{\n    [DataTestMethod]\n    void Works(int value) { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2187").is_empty());
    }
}
