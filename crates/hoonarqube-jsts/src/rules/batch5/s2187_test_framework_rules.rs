// Rule module s2187_test_framework_rules (generated).
use crate::JstsLanguage;
use crate::support::{IssueSink, LineIndex, span_issue};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

/// All Batch5 test-framework rules in one traversal (test files only).
pub(crate) fn check_test_framework_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = TestFrameworkCollector {
        source,
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        test_calls_found: false,
    };
    collector.visit_program(program);
    let mut issues = collector.sink.issues;
    if !collector.test_calls_found {
        issues.push(span_issue(
            index,
            format!("{}:S2187", language.prefix()),
            "Add at least one test to this file.",
            program.span(),
        ));
    }
    issues
}

/// Test-framework collector; only constructed for test files.
pub(crate) struct TestFrameworkCollector<'s, 'index> {
    pub(crate) source: &'s str,
    pub(crate) sink: IssueSink<'index>,
    pub(crate) test_calls_found: bool,
}
