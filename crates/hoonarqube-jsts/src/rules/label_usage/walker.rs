// Family walker for 'label_usage' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{LabeledStatement, Statement, SwitchCase};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_labeled_statement, walk_switch_case};
use oxc_span::GetSpan;

pub(crate) fn check_label_usage(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = LabelUsageCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        switch_case_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1219` and `S1439` in one traversal.
pub(crate) struct LabelUsageCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// > 0 while walking inside a switch clause (`S1219`).
    pub(crate) switch_case_depth: u32,
}

impl<'a> Visit<'a> for LabelUsageCollector<'_> {
    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        self.switch_case_depth += 1;
        walk_switch_case(self, it);
        self.switch_case_depth -= 1;
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        if self.switch_case_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1219",
                "Remove this unnecessary label.",
                it.label.span(),
            );
        }
        if !label_target_is_loop_or_switch(&it.body) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1439",
                "Only loops and switch statements should be labeled.",
                it.label.span(),
            );
        }
        walk_labeled_statement(self, it);
    }
}

/// Whether the labeled statement body is a loop or a switch (`S1439`
/// tolerance set).
pub(crate) fn label_target_is_loop_or_switch(statement: &Statement<'_>) -> bool {
    matches!(
        statement,
        Statement::WhileStatement(_)
            | Statement::DoWhileStatement(_)
            | Statement::ForStatement(_)
            | Statement::ForInStatement(_)
            | Statement::ForOfStatement(_)
            | Statement::SwitchStatement(_)
    )
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_label_usage(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn labels_on_switch_cases_and_non_loops_are_flagged() {
        assert_eq!(
            count_key(
                &js_keys("switch (x) {\n  case 1:\n    outer: break;\n}\n"),
                "javascript:S1219"
            ),
            1
        );

        assert_eq!(
            count_key(
                &js_keys("outer: for (;;) {\n  break outer;\n}\n"),
                "javascript:S1439"
            ),
            0
        );

        assert_eq!(
            count_key(&js_keys("outer: {\n  f();\n}\n"), "javascript:S1439"),
            1
        );
    }

    #[test]
    fn s1219_flags_labels_nested_in_switch_cases_only() {
        // A label inside a nested block within a case still counts.
        assert_eq!(
            count_key(
                &js_keys("switch (x) {\n  case 1:\n    {\n      inner: break;\n    }\n}\n"),
                "javascript:S1219"
            ),
            1
        );
        // Outside a switch, labels are not flagged by `S1219`.
        assert_eq!(
            count_key(
                &js_keys("outer: for (;;) {\n  break outer;\n}\n"),
                "javascript:S1219"
            ),
            0
        );
    }

    #[test]
    fn s1439_flags_nested_labels_and_non_loop_targets() {
        // Both labels of a nested pair target non-loops.
        assert_eq!(
            count_key(&js_keys("a: b: {\n  f();\n}\n"), "javascript:S1439"),
            2
        );
        // A labeled function declaration is a non-loop target.
        assert_eq!(
            count_key(&js_keys("label: function g() {}\n"), "javascript:S1439"),
            1
        );
        // Every tolerated target kind stays clean.
        assert_eq!(
            count_key(
                &js_keys("p: while (a) {}\nq: do {} while (b);\nr: switch (c) {}\n"),
                "javascript:S1439"
            ),
            0
        );
    }
}
