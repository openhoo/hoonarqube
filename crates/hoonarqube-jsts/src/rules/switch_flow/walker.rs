// Family walker for 'switch_flow' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    Expression, IfStatement, LogicalOperator, Statement, SwitchCase, SwitchStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_switch_case, walk_switch_statement};
use oxc_span::GetSpan;

pub(crate) fn check_switch_flow(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = SwitchFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        in_else_if_chain: false,
        case_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Switch-statement and if-chain flow rules in one traversal: `S126`
/// (chain without final `else`), `S128` (case fall-through), `S131`
/// (missing `default`), `S4524` (default not last), `S3616` (sequence or
/// logical-OR case test), `S1479` (too many cases), `S1301` (switch
/// convertible to `if`), and `S1821` (switch nested inside a case).
pub(crate) struct SwitchFlowCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Set while visiting the `alternate` of an enclosing `if`; detects
    /// chains whose last link lacks a final `else` (`S126`).
    pub(crate) in_else_if_chain: bool,
    /// Number of enclosing `SwitchCase` consequents (`S1821`).
    pub(crate) case_depth: u32,
}

impl<'a> Visit<'a> for SwitchFlowCollector<'_> {
    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if self.in_else_if_chain && it.alternate.is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S126",
                "Add a final \"else\" clause to this if/else-if chain.",
                it.span(),
            );
        }
        let saved_in_chain = self.in_else_if_chain;
        self.in_else_if_chain = false;
        self.visit_statement(&it.consequent);
        self.in_else_if_chain = matches!(&it.alternate, Some(Statement::IfStatement(_)));
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
        self.in_else_if_chain = saved_in_chain;
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        if self.case_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1821",
                "Extract this nested switch statement from its parent case.",
                it.span(),
            );
        }
        if it.cases.iter().all(|case| case.test.is_some()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S131",
                "Add a \"default\" case to this switch statement.",
                it.span(),
            );
        }
        let last_case_index = it.cases.len().saturating_sub(1);
        for (case_index, case) in it.cases.iter().enumerate() {
            if case.test.is_none() && case_index != last_case_index {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4524",
                    "Move this default case to the end of this switch statement.",
                    case.span(),
                );
            }
        }
        if it.cases.len() > MAX_SWITCH_CASES {
            self.sink.emit_span(
                RuleScope::Both,
                "S1479",
                &format!(
                    "Reduce the number of switch cases from {} to at most {}.",
                    it.cases.len(),
                    MAX_SWITCH_CASES
                ),
                it.span(),
            );
        }
        let tested_cases = it.cases.iter().filter(|case| case.test.is_some()).count();
        if (1..=MAX_TINY_SWITCH_CASES).contains(&tested_cases) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1301",
                "Replace this switch statement with an if statement.",
                it.span(),
            );
        }
        walk_switch_statement(self, it);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        if let Some(test) = &it.test
            && case_test_is_sequence_or_or(test)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3616",
                "Remove this sequence expression or logical OR from the case test.",
                test.span(),
            );
        }
        if let Some(last) = it.consequent.last()
            && !statement_ends_with_jump(last)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S128",
                "End this case with an unconditional break, return, throw, or continue statement.",
                it.span(),
            );
        }
        self.case_depth += 1;
        walk_switch_case(self, it);
        self.case_depth -= 1;
    }
}

/// `S1301`: switches with at most this many tested cases are flagged as
/// convertible to `if` (frozen catalog default).
pub(crate) const MAX_TINY_SWITCH_CASES: usize = 2;

// ===== Batch2b: statement-shape and control-flow walks =====
//
// Family A — switch/if-chain flow: `S126`, `S128`, `S131`, `S4524`,
// `S3616`, `S1479`, `S1301`, and `S1821`. Catalog parameters used by
// this section are kept as local constants mirroring the frozen
// catalog defaults.

/// `S1479`: switch statements carrying more cases than this are flagged
/// (frozen catalog default of the `maximum` parameter).
pub(crate) const MAX_SWITCH_CASES: usize = 30;

/// Whether a case test uses a sequence expression or a logical OR
/// (`S3616`).
pub(crate) fn case_test_is_sequence_or_or(test: &Expression<'_>) -> bool {
    match unparenthesized(test) {
        Expression::SequenceExpression(_) => true,
        Expression::LogicalExpression(logical) => logical.operator == LogicalOperator::Or,
        _ => false,
    }
}

/// Whether a statement terminates unconditionally for `S128`: a direct
/// jump, a block whose last statement jumps, or an `if/else` where both
/// branches jump.
pub(crate) fn statement_ends_with_jump(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::BreakStatement(_)
        | Statement::ContinueStatement(_)
        | Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(block) => block.body.last().is_some_and(statement_ends_with_jump),
        Statement::IfStatement(if_statement) => {
            statement_ends_with_jump(&if_statement.consequent)
                && if_statement
                    .alternate
                    .as_ref()
                    .is_some_and(statement_ends_with_jump)
        }
        _ => false,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_switch_flow(ctx.program, ctx.index, ctx.language)
}
