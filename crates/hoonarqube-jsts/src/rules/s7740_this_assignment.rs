// Rule module s7740_this_assignment (generated).
//
// `javascript:S7740` + `typescript:S7740` — eslint-plugin-unicorn
// `no-this-assignment` (v65.0.1, wrapped by SonarJS S7740): assigning
// `this` to a plain identifier is reported on the whole declarator or
// assignment with "Do not assign `this` to `X`." Both forms are covered:
// `var self = this` (VariableDeclarator with an identifier binding and a
// `this` initializer) and `self = this` (AssignmentExpression with an
// identifier target and a `this` right side). Destructuring declarators,
// member/pattern assignment targets, compound assignments (`x += this`
// still reports, matching the reference which ignores the operator), and
// non-`this` initializers behave exactly like the reference. No auto-fix
// is offered.
//
// SonarJS reports the rule with scope MAIN: test files (the pinned
// server's filename-based classification, shared with the analyzer's
// other rules) stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{AssignmentTarget, BindingPattern, Expression};
use oxc_span::GetSpan;

/// Entry point: `javascript:S7740` + `typescript:S7740`
/// no-this-assignment check over the parsed program.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return sink.issues;
    }
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        match node.kind() {
            AstKind::VariableDeclarator(declarator) => {
                let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
                    continue;
                };
                let Some(init) = declarator.init.as_ref() else {
                    continue;
                };
                if !matches!(unparenthesized(init), Expression::ThisExpression(_)) {
                    continue;
                }
                // The reference reports `valueNode.parent`: the whole
                // declarator (`self = this` without the `var` keyword).
                emit(&mut sink, identifier.name.as_str(), declarator.span());
            }
            AstKind::AssignmentExpression(assignment) => {
                let AssignmentTarget::AssignmentTargetIdentifier(identifier) = &assignment.left
                else {
                    continue;
                };
                if !matches!(
                    unparenthesized(&assignment.right),
                    Expression::ThisExpression(_)
                ) {
                    continue;
                }
                emit(&mut sink, identifier.name.as_str(), assignment.span());
            }
            _ => {}
        }
    }
    sink.issues
}

fn emit(sink: &mut IssueSink<'_>, name: &str, span: oxc_span::Span) {
    sink.emit_span(
        RuleScope::Both,
        "S7740",
        &format!("Do not assign `this` to `{name}`."),
        span,
    );
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7740_flags_pinned_express_sites() {
        // Pinned oracle: express@3ce6d0e lib/response.js:376 (`var res =
        // this`), lib/response.js:899 (`var self = this`), lib/view.js:146
        // (`var cntx = this`), examples/view-constructor/github-view.js:37.
        let source = "\
var done = callback;
var req = this.req;
var res = this;
var self = this;
var cntx = this;
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7740"), 3);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7740")
            .expect("pinned express `var res = this` must be reported");
        assert_eq!(issue.message, "Do not assign `this` to `res`.");
        // Report span: the declarator `res = this` (no `var ` prefix).
        assert_eq!(issue.range.start.line, 3);
        assert_eq!(
            issue.range.start.column,
            u32::try_from("var ".len()).unwrap()
        );
    }

    #[test]
    fn s7740_flags_plain_assignment() {
        let source = "\
var self;
self = this;
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7740"), 1);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7740")
            .expect("`self = this` must be reported");
        assert_eq!(issue.message, "Do not assign `this` to `self`.");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.start.column, 0);
    }

    #[test]
    fn s7740_member_targets_destructuring_and_non_this_stay_silent() {
        let source = "\
var self = this.req;
var other = value;
this.self = this;
obj.self = this;
var { self } = this;
var [first] = this;
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7740"), 0);
    }

    #[test]
    fn s7740_typescript_uses_typescript_key() {
        let source = "var self = this;\n";
        let findings = ts_keys(source);
        assert_eq!(count_key(&findings, "typescript:S7740"), 1);
        assert_eq!(count_key(&findings, "javascript:S7740"), 0);
    }

    #[test]
    fn s7740_test_files_stay_silent() {
        // Scope MAIN: the pinned server classifies spec files as tests.
        let source = "var self = this;\n";
        assert_eq!(count_key(&test_file_keys(source), "javascript:S7740"), 0);
    }
}
