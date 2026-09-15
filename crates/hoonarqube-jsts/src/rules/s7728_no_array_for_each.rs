// Rule module s7728_no_array_for_each (generated).
//
// `javascript:S7728` + `typescript:S7728` — decoration of
// eslint-plugin-unicorn `no-array-for-each` (v65.0.1, wrapped by SonarJS
// S7728): every `.forEach(...)` method call is reported — optional member
// (`a?.forEach`), optional call (`a.forEach?.(...)`), and member chains or
// call results alike — except when the receiver's dotted path matches the
// reference ignore list (`React.Children`, `Children`, `R`, `pIteration`,
// `Effect`, from unicorn) or the receiver resolves to the
// `strict-callbag-basics` namespace import (irrelevant for the analyzer's
// per-file view and therefore not replicated). The reference rule is
// syntactic: it runs without type information, so `Object.keys(...).forEach`
// and non-array receivers are reported the same way.
//
// The finding is anchored on the `forEach` property with the reference
// message "Use `for…of` instead of `.forEach(…)`." and no auto-fix is
// offered (the unicorn fixer is a whole-statement rewrite the analyzer does
// not reproduce).
//
// SonarJS reports the rule with scope MAIN: test files (the pinned server's
// filename-based classification, shared with the analyzer's other rules)
// stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_ast_visit::{Visit, walk};
use oxc_span::GetSpan;

/// Receivers the reference rule ignores, matched as dotted paths.
const IGNORED_OBJECTS: [&str; 5] = ["React.Children", "Children", "R", "pIteration", "Effect"];

/// Entry point: `javascript:S7728` + `typescript:S7728` no-array-for-each
/// check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return Vec::new();
    }
    let mut collector = ForEachCollector {
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct ForEachCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for ForEachCollector<'_> {
    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name == "forEach"
            && !dotted_path(&member.object)
                .is_some_and(|path| IGNORED_OBJECTS.contains(&path.as_str()))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S7728",
                "Use `for…of` instead of `.forEach(…)`.",
                member.property.span(),
            );
        }
        walk::walk_call_expression(self, call);
    }
}

/// Dotted path of a plain identifier/member receiver, or `None` when any
/// segment is computed, optional, or not a plain member chain.
fn dotted_path(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::Identifier(identifier) => Some(identifier.name.to_string()),
        Expression::StaticMemberExpression(member) if !member.optional => {
            let mut path = dotted_path(&member.object)?;
            path.push('.');
            path.push_str(member.property.name.as_str());
            Some(path)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7728_flags_pinned_express_and_exceljs_sites() {
        // Pinned oracle: express@3ce6d0e lib/application.js:219 `fns.forEach`
        // and exceljs@5bed18b lib/doc/table.js:169 `table.columns.forEach`.
        let source = "\
fns.forEach(function (fn) { return fn; });
table.columns.forEach((column, i) => { keep(column, i); });
Object.keys(style).forEach(key => { keep(key); });
fs.readdirSync(dir).forEach(function(name){ keep(name); });
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7728"), 4);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7728")
            .expect("pinned express forEach must be reported");
        assert_eq!(issue.message, "Use `for…of` instead of `.forEach(…)`.");
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(issue.range.start.column, u32::try_from("fns.".len()).unwrap());
        assert_eq!(issue.range.end.column, issue.range.start.column + 7);
    }

    #[test]
    fn s7728_flags_optional_member_and_call_forms_like_reference() {
        let source = "\
a?.forEach(v => v);
a.forEach?.(v => v);
obj.deep.forEach(f);
new Foo().forEach(f);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7728"), 4);
    }

    #[test]
    fn s7728_ignores_reference_ignore_list_receivers() {
        let source = "\
React.Children.forEach(kids, f);
Children.forEach(kids, f);
R.forEach(f);
pIteration.forEach(list, f);
Effect.forEach(monad, f);
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7728"), 0);
    }

    #[test]
    fn s7728_stays_silent_for_non_member_calls_and_computed_access() {
        let source = "\
forEach(f);
map['forEach'](f);
const each = map.forEach;
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7728"), 0);
    }

    #[test]
    fn s7728_also_fires_for_typescript_files() {
        let source = "items.forEach((item) => keep(item));\n";
        let report = crate::analyze(
            PathBuf::from("lib/doc/table.ts"),
            source,
            crate::JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&report), "typescript:S7728"), 1);
    }

    #[test]
    fn s7728_stays_silent_in_test_files_like_reference_main_scope() {
        // The pinned server classifies `*.spec.js` as TEST and reports the
        // MAIN-scoped rule only on MAIN files.
        let source = "list.forEach(fn);\n";
        let test_report = crate::analyze(
            PathBuf::from("spec/utils/string-buf.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&test_report), "javascript:S7728"), 0);
        let main_report = crate::analyze(
            PathBuf::from("lib/doc/table.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S7728"), 1);
    }
}
