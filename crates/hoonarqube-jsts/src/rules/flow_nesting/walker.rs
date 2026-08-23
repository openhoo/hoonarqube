// Family walker for 'flow_nesting' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionExpression, BreakStatement, CatchClause, ContinueStatement, Declaration,
    DoWhileStatement, ExportDefaultDeclarationKind, Expression, ForInStatement, ForOfStatement,
    ForStatement, FormalParameters, IfStatement, MethodDefinition, ReturnStatement, StaticBlock,
    SwitchStatement, ThrowStatement, TryStatement, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_catch_clause, walk_declaration, walk_do_while_statement,
    walk_export_default_declaration_kind, walk_expression, walk_for_in_statement,
    walk_for_of_statement, walk_if_statement, walk_method_definition, walk_return_statement,
    walk_static_block, walk_switch_statement, walk_throw_statement, walk_while_statement,
};
use oxc_span::{GetSpan, Span};

pub(crate) fn check_flow_nesting_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ControlFlowNestingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        flow_depth: 0,
        finally_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S107`, `S134`, and `S1143` in one traversal. Tracks control-flow nesting
/// depth and `finally` membership, both reset at every function boundary.
pub(crate) struct ControlFlowNestingCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Number of control-flow constructs enclosing the current node (`S134`).
    pub(crate) flow_depth: u32,
    /// > 0 while walking inside a `finally` clause (`S1143`).
    pub(crate) finally_depth: u32,
}

impl ControlFlowNestingCollector<'_> {
    pub(crate) fn check_parameter_count(&mut self, params: &FormalParameters<'_>) {
        let count = params.items.len() + usize::from(params.rest.is_some());
        if count > MAX_FUNCTION_PARAMETERS {
            self.sink.emit_span(
                RuleScope::Both,
                "S107",
                &format!(
                    "This function has {count} parameters, which is greater \
                     than the {MAX_FUNCTION_PARAMETERS} authorized."
                ),
                params.span(),
            );
        }
    }

    /// Zeroes the per-function state; returns the saved values for
    /// [`Self::leave_function`].
    pub(crate) fn enter_function(&mut self) -> (u32, u32) {
        let saved = (self.flow_depth, self.finally_depth);
        self.flow_depth = 0;
        self.finally_depth = 0;
        saved
    }

    pub(crate) fn leave_function(&mut self, saved: (u32, u32)) {
        self.flow_depth = saved.0;
        self.finally_depth = saved.1;
    }

    /// `S134`: flags a construct entered while already `MAX` deep, i.e. one
    /// whose own nesting level exceeds `MAX_CONTROL_FLOW_NESTING`.
    pub(crate) fn check_nesting(&mut self, span: Span) {
        if self.flow_depth >= MAX_CONTROL_FLOW_NESTING {
            self.sink.emit_span(
                RuleScope::Both,
                "S134",
                &format!(
                    "Refactor this code to not nest more than \
                     {MAX_CONTROL_FLOW_NESTING} control flow statements."
                ),
                span,
            );
        }
    }

    pub(crate) fn check_finally_jump(&mut self, span: Span) {
        if self.finally_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1143",
                "Remove this jump statement from this finally block.",
                span,
            );
        }
    }

    /// Counts parameters and resets nesting around one whole function-like
    /// subtree.
    pub(crate) fn function_scope(
        &mut self,
        params: Option<&FormalParameters<'_>>,
        walk_children: impl FnOnce(&mut Self),
    ) {
        if let Some(params) = params {
            self.check_parameter_count(params);
        }
        let saved = self.enter_function();
        walk_children(self);
        self.leave_function(saved);
    }
}

impl<'a> Visit<'a> for ControlFlowNestingCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.function_scope(Some(&function.params), |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.function_scope(Some(&it.params), |collector| {
            walk_arrow_function_expression(collector, it);
        });
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.function_scope(Some(&it.value.params), |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.function_scope(None, |collector| {
            walk_static_block(collector, it);
        });
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            self.function_scope(Some(&function.params), |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        if let ExportDefaultDeclarationKind::FunctionDeclaration(function) = it {
            self.function_scope(Some(&function.params), |collector| {
                walk_export_default_declaration_kind(collector, it);
            });
        } else {
            walk_export_default_declaration_kind(self, it);
        }
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_if_statement(collector, it));
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.nested_flow(it.span(), |collector| {
            if let Some(init) = &it.init {
                collector.visit_for_statement_init(init);
            }
            if let Some(test) = &it.test {
                collector.visit_expression(test);
            }
            if let Some(update) = &it.update {
                collector.visit_expression(update);
            }
            collector.visit_statement(&it.body);
        });
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_for_in_statement(collector, it));
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_for_of_statement(collector, it));
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_while_statement(collector, it));
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.nested_flow(it.span(), |collector| {
            walk_do_while_statement(collector, it);
        });
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        self.nested_flow(it.span(), |collector| walk_switch_statement(collector, it));
    }

    fn visit_catch_clause(&mut self, it: &CatchClause<'_>) {
        self.nested_flow(it.span(), |collector| walk_catch_clause(collector, it));
    }

    /// `S1143` handling: the `try` header itself nests like other
    /// constructs, while the optional `finally` additionally enables jump
    /// detection for its subtree.
    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        self.check_nesting(it.span());
        self.flow_depth += 1;
        self.visit_block_statement(&it.block);
        if let Some(handler) = &it.handler {
            self.visit_catch_clause(handler);
        }
        self.flow_depth -= 1;
        if let Some(finalizer) = &it.finalizer {
            self.finally_depth += 1;
            self.visit_block_statement(finalizer);
            self.finally_depth -= 1;
        }
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        self.check_finally_jump(it.span());
        walk_return_statement(self, it);
    }

    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        self.check_finally_jump(it.span());
        walk_throw_statement(self, it);
    }

    fn visit_break_statement(&mut self, it: &BreakStatement<'a>) {
        self.check_finally_jump(it.span());
    }

    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        self.check_finally_jump(it.span());
    }
}

impl ControlFlowNestingCollector<'_> {
    pub(crate) fn nested_flow(&mut self, span: Span, walk_children: impl FnOnce(&mut Self)) {
        self.check_nesting(span);
        self.flow_depth += 1;
        walk_children(self);
        self.flow_depth -= 1;
    }
}

/// `S134`: control-flow statements nested deeper than this are flagged
/// (frozen catalog default of `maximumNestingLevel`).
pub(crate) const MAX_CONTROL_FLOW_NESTING: u32 = 3;

/// `S107`: functions carrying more parameters than this are flagged (frozen
/// catalog default of `maximumFunctionParameters`).
pub(crate) const MAX_FUNCTION_PARAMETERS: usize = 7;

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_flow_nesting_rules(ctx.program, ctx.index, ctx.language)
}
