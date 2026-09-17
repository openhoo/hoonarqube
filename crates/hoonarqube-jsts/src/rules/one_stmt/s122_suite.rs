// Rule module s122_suite (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BlockStatement, Declaration, ExpressionStatement, FunctionBody, Program, StaticBlock,
    SwitchCase, WithStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_block_statement, walk_break_statement, walk_continue_statement, walk_debugger_statement,
    walk_declaration, walk_do_while_statement, walk_export_all_declaration,
    walk_export_default_declaration, walk_export_named_declaration, walk_expression,
    walk_expression_statement, walk_for_in_statement, walk_for_of_statement, walk_for_statement,
    walk_function_body, walk_import_declaration, walk_labeled_statement, walk_return_statement,
    walk_statement, walk_static_block, walk_switch_case, walk_switch_statement,
    walk_throw_statement, walk_try_statement, walk_while_statement, walk_with_statement,
};
use oxc_parser::{Kind, Token};
use oxc_span::{GetSpan, Span};

/// `S122` pins the upstream `max-statements-per-line` rule with its default
/// maximum of one: every counted statement sharing its start line with the
/// previous counted statement beyond the first raises one issue per line,
/// reported on the first extra statement with the pinned Sonar way message.
///
/// Counted statements are the `ESLint` rule's statement list (blocks, `if`
/// branches that are direct children of the `if`, and `switch` case bodies
/// are not counted themselves); a statement whose parent is a bare
/// `if`/loop/`labeled` body is not counted unless it is the `else` branch.
pub(crate) fn check_suite(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut collector = S122Collector {
        index: ctx.index,
        language: ctx.language,
        tokens: ctx.tokens,
        issues: Vec::new(),
        last_statement_line: 0,
        count: 0,
        first_extra: None,
        parents: Vec::new(),
        alternate_span: None,
    };
    collector.visit_program(ctx.program);
    collector.flush();
    collector.issues
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Parent {
    /// A bare-statement parent: `if`, loops, `labeled`, and `export`
    /// declarations allow a single non-block child.
    SingleChild,
    /// An `if` parent; the `else` branch still counts.
    If,
    /// Any other statement container (blocks, function bodies, cases).
    Container,
}

struct S122Collector<'a, 'index> {
    index: &'index LineIndex<'index>,
    language: JstsLanguage,
    tokens: &'a [Token],
    issues: Vec<Issue>,
    last_statement_line: u32,
    count: u32,
    first_extra: Option<Span>,
    parents: Vec<Parent>,
    alternate_span: Option<Span>,
}

impl S122Collector<'_, '_> {
    fn enter_statement(&mut self, span: Span) {
        let skipped = match self.parents.last() {
            Some(Parent::If) => self.alternate_span != Some(span),
            Some(Parent::SingleChild) => true,
            _ => false,
        };
        if skipped {
            return;
        }
        let line = self.index.pos(span.start).line;
        if line == self.last_statement_line {
            self.count += 1;
        } else {
            self.flush();
            self.count = 1;
            self.last_statement_line = line;
        }
        if self.count == 2 && self.first_extra.is_none() {
            self.first_extra = Some(span);
        }
    }

    fn leave_statement(&mut self, span: Span) {
        let end_line = self.actual_last_token_end_line(span);
        if end_line != self.last_statement_line {
            self.flush();
            self.count = 1;
            self.last_statement_line = end_line;
        }
    }

    /// The line holding the statement's last real token (a trailing
    /// semicolon is not the statement's last token).
    fn actual_last_token_end_line(&self, span: Span) -> u32 {
        let end = span.end as usize;
        let slice = &self.tokens[..self
            .tokens
            .partition_point(|token| (token.start() as usize) < end)];
        for token in slice.iter().rev() {
            if token.kind() != Kind::Semicolon {
                return self.index.pos(token.end()).line;
            }
        }
        self.index.pos(span.end).line
    }

    fn flush(&mut self) {
        if let Some(span) = self.first_extra.take() {
            self.issues.push(Issue {
                rule_key: format!("{}:S122", self.language.prefix()),
                message: format!(
                    "This line has {} statements. Maximum allowed is 1.",
                    self.count
                ),
                range: self.index.range(span),
                fix: None,
                flows: Vec::new(),
                alternatives: Vec::new(),
            });
        }
    }
}

impl<'a> Visit<'a> for S122Collector<'a, 'a> {
    fn visit_program(&mut self, it: &Program<'a>) {
        for statement in &it.body {
            walk_statement(self, statement);
        }
        self.flush();
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        self.enter_statement(it.span());
        walk_expression_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_break_statement(&mut self, it: &oxc_ast::ast::BreakStatement<'a>) {
        self.enter_statement(it.span());
        walk_break_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_continue_statement(&mut self, it: &oxc_ast::ast::ContinueStatement<'a>) {
        self.enter_statement(it.span());
        walk_continue_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_debugger_statement(&mut self, it: &oxc_ast::ast::DebuggerStatement) {
        self.enter_statement(it.span());
        walk_debugger_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_return_statement(&mut self, it: &oxc_ast::ast::ReturnStatement<'a>) {
        self.enter_statement(it.span());
        walk_return_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_throw_statement(&mut self, it: &oxc_ast::ast::ThrowStatement<'a>) {
        self.enter_statement(it.span());
        walk_throw_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_import_declaration(&mut self, it: &oxc_ast::ast::ImportDeclaration<'a>) {
        self.enter_statement(it.span());
        walk_import_declaration(self, it);
        self.leave_statement(it.span());
    }

    fn visit_export_all_declaration(&mut self, it: &oxc_ast::ast::ExportAllDeclaration<'a>) {
        self.enter_statement(it.span());
        walk_export_all_declaration(self, it);
        self.leave_statement(it.span());
    }

    fn visit_export_named_declaration(&mut self, it: &oxc_ast::ast::ExportNamedDeclaration<'a>) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_export_named_declaration(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_export_default_declaration(
        &mut self,
        it: &oxc_ast::ast::ExportDefaultDeclaration<'a>,
    ) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_export_default_declaration(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        match it {
            Declaration::VariableDeclaration(declaration) => {
                self.enter_statement(declaration.span());
                walk_declaration(self, it);
                self.leave_statement(declaration.span());
            }
            Declaration::FunctionDeclaration(function) => {
                self.enter_statement(function.span());
                walk_declaration(self, it);
                self.leave_statement(function.span());
            }
            Declaration::ClassDeclaration(class) => {
                self.enter_statement(class.span());
                walk_declaration(self, it);
                self.leave_statement(class.span());
            }
            _ => walk_declaration(self, it),
        }
    }

    fn visit_if_statement(&mut self, it: &oxc_ast::ast::IfStatement<'a>) {
        self.enter_statement(it.span());
        walk_expression(self, &it.test);
        self.parents.push(Parent::If);
        walk_statement(self, &it.consequent);
        if let Some(alternate) = &it.alternate {
            let saved = self.alternate_span;
            self.alternate_span = Some(alternate.span());
            walk_statement(self, alternate);
            self.alternate_span = saved;
        }
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_for_statement(&mut self, it: &oxc_ast::ast::ForStatement<'a>) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_for_statement(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_for_in_statement(&mut self, it: &oxc_ast::ast::ForInStatement<'a>) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_for_in_statement(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_for_of_statement(&mut self, it: &oxc_ast::ast::ForOfStatement<'a>) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_for_of_statement(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_while_statement(&mut self, it: &oxc_ast::ast::WhileStatement<'a>) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_while_statement(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_do_while_statement(&mut self, it: &oxc_ast::ast::DoWhileStatement<'a>) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_do_while_statement(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_labeled_statement(&mut self, it: &oxc_ast::ast::LabeledStatement<'a>) {
        self.enter_statement(it.span());
        self.parents.push(Parent::SingleChild);
        walk_labeled_statement(self, it);
        self.parents.pop();
        self.leave_statement(it.span());
    }

    fn visit_switch_statement(&mut self, it: &oxc_ast::ast::SwitchStatement<'a>) {
        self.enter_statement(it.span());
        walk_switch_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_try_statement(&mut self, it: &oxc_ast::ast::TryStatement<'a>) {
        self.enter_statement(it.span());
        walk_try_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_with_statement(&mut self, it: &WithStatement<'a>) {
        self.enter_statement(it.span());
        walk_with_statement(self, it);
        self.leave_statement(it.span());
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.parents.push(Parent::Container);
        walk_block_statement(self, it);
        self.parents.pop();
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        self.parents.push(Parent::Container);
        walk_function_body(self, it);
        self.parents.pop();
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.parents.push(Parent::Container);
        walk_static_block(self, it);
        self.parents.pop();
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        self.parents.push(Parent::Container);
        walk_switch_case(self, it);
        self.parents.pop();
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn same_line_statement_pairs_are_reported_once() {
        let findings = js_keys("let a = 1; let b = 2;\n");
        assert_eq!(count_key(&findings, "javascript:S122"), 1);
        assert_eq!(
            js("let a = 1; let b = 2;\n")
                .issues
                .iter()
                .find(|issue| issue.rule_key == "javascript:S122")
                .map(|issue| issue.message.as_str()),
            Some("This line has 2 statements. Maximum allowed is 1.")
        );

        let separate = js_keys("let a = 1;\nlet b = 2;\n");
        assert_eq!(count_key(&separate, "javascript:S122"), 0);
    }
    #[test]
    fn three_and_four_statement_lines_report_the_line_total() {
        let three = js("let a = 1; let b = 2; let c = 3;\n");
        assert_eq!(count_key(&report_keys(&three), "javascript:S122"), 1);
        assert_eq!(
            three
                .issues
                .iter()
                .find(|issue| issue.rule_key == "javascript:S122")
                .map(|issue| issue.message.as_str()),
            Some("This line has 3 statements. Maximum allowed is 1.")
        );

        let calls = js("f(); g(); h(); i();\n");
        assert_eq!(count_key(&report_keys(&calls), "javascript:S122"), 1);
        assert_eq!(
            calls
                .issues
                .iter()
                .find(|issue| issue.rule_key == "javascript:S122")
                .map(|issue| issue.message.as_str()),
            Some("This line has 4 statements. Maximum allowed is 1.")
        );
    }

    #[test]
    fn function_body_pairs_on_one_line_are_counted() {
        // #392: verbatim express lib/utils.js reduction — the outer
        // `return` and the nested function body's `return` share a line.
        let findings = js_keys("function make() {\n  return function(){ return true };\n}\n");
        assert_eq!(count_key(&findings, "javascript:S122"), 1);

        // Empty one-line function bodies stay clean.
        let empty = js_keys("function emptyFn() {}\n");
        assert_eq!(count_key(&empty, "javascript:S122"), 0);
    }

    #[test]
    fn control_statement_children_follow_the_pinned_rules() {
        let source = "\
if (ok) { step(); }
while (ok) { step(); }
if (ok) step(); else stop();
for (;;) { break; }
if (a) { if (b) { step(); } }
";
        let report = js(source);
        let mut sites: Vec<(u32, &str)> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S122"))
            .map(|issue| (issue.range.start.line, issue.message.as_str()))
            .collect();
        sites.sort_unstable();
        assert_eq!(
            sites,
            vec![
                (1, "This line has 2 statements. Maximum allowed is 1."),
                (2, "This line has 2 statements. Maximum allowed is 1."),
                (3, "This line has 2 statements. Maximum allowed is 1."),
                (4, "This line has 2 statements. Maximum allowed is 1."),
                (5, "This line has 3 statements. Maximum allowed is 1."),
            ]
        );
    }
}
