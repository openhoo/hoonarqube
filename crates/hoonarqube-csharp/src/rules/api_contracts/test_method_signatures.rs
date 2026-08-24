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
