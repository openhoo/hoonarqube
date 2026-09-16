// Family walker for 'function_contexts' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::argument_expression;
use crate::support::{
    IssueSink, LineIndex, RuleScope, member_object, static_property_name, unparenthesized,
};
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

fn check_function_contexts(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    semantic: Option<&oxc_semantic::Semantic<'_>>,
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
        loop_spans: Vec::new(),
        s1515_exempt: std::collections::HashSet::new(),
        semantic,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1515` (functions created inside loop bodies), `S1530` (function
/// declarations placed in nested blocks), `S1788` (default parameter before
/// a regular one), and `S2004` (function nesting beyond
/// [`MAX_FUNCTION_NESTING`] levels) in one traversal.
struct FunctionContextCollector<'index, 'semantic> {
    sink: IssueSink<'index>,
    /// Depth of `BlockStatement`s below the nearest function or program
    /// root (`S1530`); reset per function.
    block_depth: u32,
    /// > 0 while walking inside a loop *body* (`S1515`); reset per function.
    loop_body_depth: u32,
    /// Number of enclosing functions (`S2004`).
    function_depth: u32,
    /// Spans of enclosing loop statements (`S1515` capture analysis).
    loop_spans: Vec<Span>,
    /// Function spans exempt from `S1515`: IIFEs and callbacks of the
    /// array-iteration family (`map`/`forEach`/…), matching `SonarJS`.
    s1515_exempt: std::collections::HashSet<(u32, u32)>,
    semantic: Option<&'index oxc_semantic::Semantic<'semantic>>,
}

impl FunctionContextCollector<'_, '_> {
    fn check_parameter_order(&mut self, params: &FormalParameters<'_>) {
        let mut first_default = None;
        for item in &params.items {
            if param_has_default(item) {
                first_default.get_or_insert(item.span());
                continue;
            }
            if let Some(span) = first_default.take() {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1788",
                    "Default parameters should be last.",
                    span,
                );
            }
        }
    }

    /// Walks the shared `for-in`/`for-of` header left side: either a target
    /// declaration or an assignment/expression target.
    fn visit_for_header_left(&mut self, left: &ForStatementLeft<'_>) {
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
    fn enter_function(
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
        if self.loop_body_depth > 0
            && !self.s1515_exempt.contains(&(span.start, span.end))
            && self.captures_mutated_outer(span)
        {
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

    /// `S1515` capture analysis: whether a function created inside the
    /// innermost enclosing loop references an outer binding whose value the
    /// loop mutates. Mirrors `SonarJS` `isSafe`: block-scoped (`let`/`const`)
    /// bindings are per-iteration and always safe; other kinds (`var`,
    /// function declarations, parameters, imports) are unsafe only when
    /// written inside the loop statement. Without semantic scope data the
    /// check stays conservative (flags, as before).
    fn captures_mutated_outer(&self, function_span: Span) -> bool {
        let Some(semantic) = self.semantic else {
            return true;
        };
        let Some(&loop_span) = self.loop_spans.last() else {
            return true;
        };
        let scoping = semantic.scoping();
        scoping.symbol_ids().any(|symbol| {
            let decl_span = scoping.symbol_span(symbol);
            if function_span.contains_inclusive(decl_span) {
                return false;
            }
            let captured = scoping
                .get_resolved_reference_ids(symbol)
                .iter()
                .map(|&id| scoping.get_reference(id))
                .any(|reference| {
                    function_span.contains_inclusive(semantic.reference_span(reference))
                });
            captured && !captured_symbol_is_safe(semantic, symbol, loop_span)
        })
    }
}

/// Whether a captured binding is safe for `S1515`: block-scoped
/// (`let`/`const`) bindings are per-iteration and always safe; every other
/// kind is unsafe only when written inside the loop span.
fn captured_symbol_is_safe(
    semantic: &oxc_semantic::Semantic<'_>,
    symbol: oxc_semantic::SymbolId,
    loop_span: Span,
) -> bool {
    use oxc_syntax::symbol::SymbolFlags;
    let scoping = semantic.scoping();
    if scoping
        .symbol_flags(symbol)
        .contains(SymbolFlags::BlockScopedVariable)
    {
        return true;
    }
    !scoping
        .get_resolved_reference_ids(symbol)
        .iter()
        .map(|&id| scoping.get_reference(id))
        .any(|reference| {
            reference.is_write() && loop_span.contains_inclusive(semantic.reference_span(reference))
        })
}

impl<'a> Visit<'a> for FunctionContextCollector<'_, '_> {
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
                    "Do not use function declarations within blocks.",
                    function.id.as_ref().map_or(function.span(), GetSpan::span),
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
        self.loop_spans.push(it.span());
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
        self.loop_spans.pop();
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.visit_for_header_left(&it.left);
        self.visit_expression(&it.right);
        self.loop_body_depth += 1;
        self.loop_spans.push(it.span());
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
        self.loop_spans.pop();
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.visit_for_header_left(&it.left);
        self.visit_expression(&it.right);
        self.loop_body_depth += 1;
        self.loop_spans.push(it.span());
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
        self.loop_spans.pop();
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.visit_expression(&it.test);
        self.loop_body_depth += 1;
        self.loop_spans.push(it.span());
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
        self.loop_spans.pop();
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.loop_body_depth += 1;
        self.loop_spans.push(it.span());
        self.visit_statement(&it.body);
        self.loop_body_depth -= 1;
        self.loop_spans.pop();
        self.visit_expression(&it.test);
    }

    fn visit_call_expression(&mut self, it: &oxc_ast::ast::CallExpression<'a>) {
        // `S1515` exemptions matching SonarJS: IIFEs run before the loop
        // completes, and the array-iteration callback family is invoked
        for expression in
            std::iter::once(&it.callee).chain(it.callee.as_member_expression().map(member_object))
        {
            if let Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_) =
                unparenthesized(expression)
            {
                let span = expression.span();
                self.s1515_exempt.insert((span.start, span.end));
            }
        }
        if let Some(member) = it.callee.as_member_expression()
            && static_property_name(member).is_some_and(|name| LOOP_SAFE_CALLBACKS.contains(&name))
        {
            for argument in &it.arguments {
                if let Some(expression) = argument_expression(argument)
                    && matches!(
                        unparenthesized(expression),
                        Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
                    )
                {
                    let span = expression.span();
                    self.s1515_exempt.insert((span.start, span.end));
                }
            }
        }
        oxc_ast_visit::walk::walk_call_expression(self, it);
    }
}

/// Callback names `SonarJS` `S1515` exempts inside loops (synchronous
/// per-iteration invocation).
const LOOP_SAFE_CALLBACKS: [&str; 12] = [
    "replace",
    "forEach",
    "filter",
    "map",
    "find",
    "findIndex",
    "every",
    "some",
    "reduce",
    "reduceRight",
    "sort",
    "each",
];

/// `S2004`: functions nested deeper than this many levels are flagged
/// (frozen catalog default of `max`).
const MAX_FUNCTION_NESTING: u32 = 4;

/// Whether the parameter carries a default value (`= expr`) or a
/// destructuring default at its top level.
fn param_has_default(item: &FormalParameter<'_>) -> bool {
    item.initializer.is_some() || matches!(item.pattern, BindingPattern::AssignmentPattern(_))
}
pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_function_contexts(ctx.program, ctx.index, ctx.language, ctx.semantic)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn functions_in_loops_blocks_and_depths_are_flagged() {
        // S1515: a closure created inside a loop body that captures a
        // `var` binding the loop mutates.
        let in_loop = js_keys("for (var i = 0; i < 10; i++) {\n  setTimeout(() => i);\n}\n");
        assert_eq!(count_key(&in_loop, "javascript:S1515"), 1);

        let in_header = js_keys("for (const f of makers) {\n  f();\n}\n");
        assert_eq!(count_key(&in_header, "javascript:S1515"), 0);

        // S1530: function declaration nested in a block; top level is fine.
        let in_block = js_keys("{\n  function inner() {}\n}\n");
        assert_eq!(count_key(&in_block, "javascript:S1530"), 1);
        let top_level = js_keys("function outer() {}\n");
        assert_eq!(count_key(&top_level, "javascript:S1530"), 0);

        // S2004: five levels of nesting exceed the maximum of four.
        let deep_keys = js_keys(
            "function a() {\n  const b = () => {\n    const c = () => {\n      const d = () => {\n        const e = () => {};\n      };\n    };\n  };\n}\n",
        );
        assert_eq!(count_key(&deep_keys, "javascript:S2004"), 1);
        assert_eq!(count_key(&deep_keys, "javascript:S1515"), 0);

        // Four levels are exactly at the allowed maximum.
        assert_eq!(
            count_key(
                &js_keys(
                    "function a() {\n  const b = () => {\n    const c = () => {\n      const d = () => {};\n    };\n  };\n}\n"
                ),
                "javascript:S2004"
            ),
            0
        );
    }

    #[test]
    fn default_parameters_must_come_last() {
        let ordered = js_keys("function f(a, b = 1, c = 2) { return a; }\n");
        assert_eq!(count_key(&ordered, "javascript:S1788"), 0);

        let unordered = js_keys("function f(a = 1, b) { return b; }\n");
        assert_eq!(count_key(&unordered, "javascript:S1788"), 1);
    }

    #[test]
    fn s1515_and_s1530_flag_function_declarations_in_loop_blocks() {
        let keys = js_keys(
            "var a = true;\nwhile (a) {\n  a = tick();\n  function inner() { return a; }\n}\n",
        );
        assert_eq!(count_key(&keys, "javascript:S1515"), 1);
        assert_eq!(count_key(&keys, "javascript:S1530"), 1);

        // A declaration two blocks deep is still flagged once.
        assert_eq!(
            count_key(
                &js_keys("{\n  if (a) {\n    function deep() {}\n  }\n}\n"),
                "javascript:S1530"
            ),
            1
        );
    }

    #[test]
    fn s1515_ignores_callbacks_capturing_only_safe_bindings() {
        // #538: arrows inside loops capturing only their own parameter and
        // `const` locals are safe (SonarJS `isSafe`).
        let safe = ts_keys(
            "const declarations = [1, 2, 3];\nfor (const name of [\"a\", \"b\"]) {\n  const indent = \"  \";\n  const out = declarations.map(declaration => `${indent}${declaration}`);\n  console.log(name, out);\n}\n",
        );
        assert_eq!(count_key(&safe, "typescript:S1515"), 0);

        // Block-scoped bindings are per-iteration in SonarJS `isSafe` —
        // safe to capture even when the loop writes them.
        let per_iteration = js_keys("for (let i = 0; i < 3; i++) {\n  funs[i] = () => i;\n}\n");
        assert_eq!(count_key(&per_iteration, "javascript:S1515"), 0);
        let mutated_let = js_keys(
            "let count = 0;\nfor (const v of items) {\n  count += 1;\n  funs.push(() => count);\n}\n",
        );
        assert_eq!(count_key(&mutated_let, "javascript:S1515"), 0);

        // A `var` binding written inside the loop is unsafe to capture.
        let mutated_var = js_keys(
            "var count = 0;\nfor (const v of items) {\n  count += 1;\n  funs.push(() => count);\n}\n",
        );
        assert_eq!(count_key(&mutated_var, "javascript:S1515"), 1);
    }

    #[test]
    fn s1788_flags_every_parameter_after_the_first_default() {
        assert_eq!(
            count_key(
                &js_keys("function f(a = 1, b, c = 2, d) { return a; }\n"),
                "javascript:S1788"
            ),
            2
        );
    }

    #[test]
    fn s2004_flags_each_function_beyond_four_nesting_levels() {
        assert_eq!(
            count_key(
                &js_keys(
                    "function a() {\n  const b = () => {\n    const c = () => {\n      const d = () => {\n        const e = () => {\n          const g = () => {};\n        };\n      };\n    };\n  };\n}\n"
                ),
                "javascript:S2004"
            ),
            2
        );
    }

    #[test]
    fn empty_function_like_nodes_stay_unflagged() {
        let keys = js_keys(
            "function f() {}\nconst g = () => {};\nconst h = function () {};\nclass A {\n  m() {}\n  static {}\n}\n",
        );
        assert_eq!(count_key(&keys, "javascript:S1515"), 0);
        assert_eq!(count_key(&keys, "javascript:S1530"), 0);
        assert_eq!(count_key(&keys, "javascript:S1788"), 0);
        assert_eq!(count_key(&keys, "javascript:S2004"), 0);
    }
}
