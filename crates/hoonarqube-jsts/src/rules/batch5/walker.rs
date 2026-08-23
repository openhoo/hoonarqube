// Family walker for 'batch5' (generated).
use super::s2187_test_framework_rules::check_test_framework_rules;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex};
use crate::{
    JstsLanguage, MiscCollector, SecurityHotspotCollector, TsTypeCollector,
    check_default_export_name, check_self_imports,
};
use hoonarqube_ir::Issue;
use oxc_ast_visit::Visit;
use std::path::Path;

// --- Batch5: TypeScript-only AST rules, security hotspots, test-framework
// --- rules, and misc Tier A ---

/// Entry point for all Batch5 rules; fans out into the per-section checks.
pub(crate) fn check_batch5_rules<'a>(
    path: &'a Path,
    program: &'a oxc_ast::ast::Program<'a>,
    source: &'a str,
    index: &'a LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_ts_type_rules(program, source, index, language));
    issues.extend(check_security_hotspot_rules(
        program, source, index, language,
    ));
    if is_test_file(path) {
        issues.extend(check_test_framework_rules(program, source, index, language));
    }
    issues.extend(check_misc_rules(path, program, index, language));
    issues
}

/// All Batch5 TypeScript-only type-system rules in one traversal.
pub(crate) fn check_ts_type_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = TsTypeCollector {
        source,
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        class_stack: Vec::new(),
        constructor_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// All Batch5 security-hotspot rules in one traversal.
pub(crate) fn check_security_hotspot_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = SecurityHotspotCollector {
        source,
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Whether `path` looks like a test file (`foo.test.js`, `foo.spec.ts`, or
/// anywhere under a `__tests__` directory).
pub(crate) fn is_test_file(path: &Path) -> bool {
    let stem_is_test =
        path.file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| match stem.rsplit_once('.') {
                Some((_, extension)) => {
                    matches!(extension.to_ascii_lowercase().as_str(), "test" | "spec")
                }
                None => false,
            });
    let in_tests_dir = path
        .components()
        .any(|component| component.as_os_str() == "__tests__");
    stem_is_test || in_tests_dir
}

/// All Batch5 misc Tier-A rules in one pass.
pub(crate) fn check_misc_rules(
    path: &Path,
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = MiscCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        function_depth: 0,
    };
    collector.visit_program(program);
    let mut issues = collector.sink.issues;
    issues.extend(check_default_export_name(program, path, index, language));
    issues.extend(check_self_imports(program, path, index, language));
    issues
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_batch5_rules(ctx.path, ctx.program, ctx.source, ctx.index, ctx.language)
}
