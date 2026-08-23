// Family walker for 'function_contexts' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionExpression, BindingPattern, BlockStatement, Declaration, DoWhileStatement,
    Expression, ForInStatement, ForOfStatement, ForStatement, ForStatementLeft, FormalParameter,
    FormalParameters, MethodDefinition, StaticBlock, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_block_statement, walk_declaration, walk_expression,
    walk_method_definition, walk_static_block,
};
use oxc_span::{GetSpan, Span};

pub(crate) fn check_function_contexts(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = FunctionContextCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        block_depth: 0,
        loop_body_depth: 0,
        function_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1515` (functions created inside loop bodies), `S1530` (function
/// declarations placed in nested blocks), `S1788` (default parameter before
/// a regular one), and `S2004` (function nesting beyond
/// [`MAX_FUNCTION_NESTING`] levels) in one traversal.
pub(crate) struct FunctionContextCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Depth of `BlockStatement`s below the nearest function or program
    /// root (`S1530`); reset per function.
    pub(crate) block_depth: u32,
    /// > 0 while walking inside a loop *body* (`S1515`); reset per function.
    pub(crate) loop_body_depth: u32,
    /// Number of enclosing functions (`S2004`).
    pub(crate) function_depth: u32,
}

impl FunctionContextCollector<'_> {
    pub(crate) fn check_parameter_order(&mut self, params: &FormalParameters<'_>) {
        let mut defaulted = false;
        for item in &params.items {
            if param_has_default(item) {
                defaulted = true;
            } else if defaulted {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1788",
                    "Move this default parameter after the other parameters.",
                    item.span(),
                );
            }
        }
    }

    /// Walks the shared `for-in`/`for-of` header left side: either a target
    /// declaration or an assignment/expression target.
    pub(crate) fn visit_for_header_left(&mut self, left: &ForStatementLeft<'_>) {
        match left {
            ForStatementLeft::VariableDeclaration(declaration) => {
                self.visit_variable_declaration(declaration);
            }
            other => {
                if let Some(target) = other.as_assignment_target() {
                    self.visit_assignment_target(target);
                }
            }
        }
    }

    /// Shared entry for every function-like node: flags creation context
    /// (`S1515`, `S2004`), checks parameter order (`S1788`), then resets
    /// block/loop state for the subtree.
    pub(crate) fn enter_function(
        &mut self,
        span: Span,
        params: Option<&FormalParameters<'_>>,
        walk_children: impl FnOnce(&mut Self),
    ) {
        if self.function_depth >= MAX_FUNCTION_NESTING {
            self.sink.emit_span(
                RuleScope::Both,
                "S2004",
                &format!(
                    "Refactor this code to not nest functions more than \
                     {MAX_FUNCTION_NESTING} levels deep."
                ),
                span,
            );
        }
        if self.loop_body_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1515",
                "Functions should not be created within loops.",
                span,
            );
        }
        if let Some(params) = params {
            self.check_parameter_order(params);
        }

        let saved_block = self.block_depth;
        let saved_loop = self.loop_body_depth;
        let saved_function = self.function_depth;
        self.block_depth = 0;
        self.loop_body_depth = 0;
        self.function_depth += 1;
        walk_children(self);
        self.function_depth = saved_function;
        self.block_depth = saved_block;
        self.loop_body_depth = saved_loop;
    }
}

impl<'a> Visit<'a> for FunctionContextCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.enter_function(function.span(), Some(&function.params), |collector| {
                walk_expression(collector, it);
            });
        } else {
            walk_expression(self, it);
        }
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.enter_function(it.span(), Some(&it.params), |collector| {
            walk_arrow_function_expression(collector, it);
        });
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.enter_function(it.span(), Some(&it.value.params), |collector| {
            walk_method_definition(collector, it);
        });
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.enter_function(it.span(), None, |collector| {
            walk_static_block(collector, it);
        });
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            // Flag before entering: the *enclosing* block decides `S1530`.
            if self.block_depth > 0 {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1530",
                    "Function declarations should not be placed in blocks.",
                    function.span(),
                );
            }
            self.enter_function(function.span(), Some(&function.params), |collector| {
                walk_declaration(collector, it);
            });
        } else {
            walk_declaration(self, it);
        }
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.block_depth += 1;
        walk_block_statement(self, it);
        self.block_depth -= 1;
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            self.visit_for_statement_init(init);
        }
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &it.update {
            self.visit_expression(update);
        }
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.visit_for_header_left(&it.left);
        self.visit_expression(&it.right);
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.visit_for_header_left(&it.left);
        self.visit_expression(&it.right);
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.visit_expression(&it.test);
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.loop_body_depth += 1;
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
        self.visit_expression(&it.test);
    }
}

/// `S2004`: functions nested deeper than this many levels are flagged
/// (frozen catalog default of `max`).
pub(crate) const MAX_FUNCTION_NESTING: u32 = 4;

/// Whether the parameter carries a default value (`= expr`) or a
/// destructuring default at its top level.
pub(crate) fn param_has_default(item: &FormalParameter<'_>) -> bool {
    item.initializer.is_some() || matches!(item.pattern, BindingPattern::AssignmentPattern(_))
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_function_contexts(ctx.program, ctx.index, ctx.language)
}
