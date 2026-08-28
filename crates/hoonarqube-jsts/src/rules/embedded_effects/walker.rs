// Family walker for 'embedded_effects' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope, assignment_target_name};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{Expression, ExpressionStatement, ForStatement, UnaryOperator, UpdateOperator};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_expression, walk_expression_statement};
use oxc_span::GetSpan;

fn check_embedded_effects(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EmbeddedEffectCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        expr_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S881` (standalone `++`/`--`), `S1121` (standalone assignments), and
/// `S905` (pointless expression statements) in one traversal.
///
/// Updates and assignments are only tolerated as the direct root expression
/// of an `ExpressionStatement` or in a `for` header init/update slot; the
/// `expr_depth` counter distinguishes those roots from deeper embedding.
struct EmbeddedEffectCollector<'source, 'index> {
    sink: IssueSink<'index>,
    source: &'source str,
    /// Distance of the current expression below its statement root: `1` for
    /// the root itself, increasing per nesting level, `0` outside
    /// statement-root contexts (initializers, conditions, arguments, ...).
    expr_depth: u32,
}

impl<'a> Visit<'a> for EmbeddedEffectCollector<'_, '_> {
    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        if is_pointless_expression(&it.expression) {
            self.sink.emit_span(
                RuleScope::Both,
                "S905",
                "Expected an assignment or function call and instead saw an expression.",
                it.span(),
            );
        }
        let saved = self.expr_depth;
        self.expr_depth = 1;
        walk_expression_statement(self, it);
        self.expr_depth = saved;
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        if let Some(init) = &it.init {
            // Only the expression form of the init slot is an embedded
            // statement root; `for (let i = ...)` declarations walk with
            // their own (non-root) initializer context.
            if init.as_expression().is_some() {
                let saved = self.expr_depth;
                self.expr_depth = 1;
                self.visit_for_statement_init(init);
                self.expr_depth = saved;
            } else {
                self.visit_for_statement_init(init);
            }
        }
        if let Some(test) = &it.test {
            self.visit_expression(test);
        }
        if let Some(update) = &it.update {
            let saved = self.expr_depth;
            self.expr_depth = 1;
            self.visit_expression(update);
            self.expr_depth = saved;
        }
        self.visit_statement(&it.body);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        match it {
            Expression::UpdateExpression(update) => {
                if self.expr_depth != 1 {
                    let operation = match update.operator {
                        UpdateOperator::Increment => "increment",
                        UpdateOperator::Decrement => "decrement",
                    };
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S881",
                        &format!("Extract this {operation} operation into a dedicated statement."),
                        update.span(),
                    );
                }
            }
            Expression::AssignmentExpression(assign) if self.expr_depth != 1 => {
                let target = assignment_target_name(&assign.left).unwrap_or("value");
                let between_start = assign.left.span().end;
                let between_end = assign.right.span().start;
                let operator_span = self
                    .source
                    .get(between_start as usize..between_end as usize)
                    .and_then(|text| {
                        let start = text.find(|character: char| !character.is_whitespace())?;
                        let operator = text[start..].trim_end();
                        let absolute = between_start + u32::try_from(start).ok()?;
                        Some(oxc_span::Span::new(
                            absolute,
                            absolute + u32::try_from(operator.len()).ok()?,
                        ))
                    })
                    .unwrap_or_else(|| assign.left.span());
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1121",
                    &format!("Extract the assignment of \"{target}\" from this expression."),
                    operator_span,
                );
            }
            _ => {}
        }
        if self.expr_depth > 0 {
            self.expr_depth += 1;
            walk_expression(self, it);
            self.expr_depth -= 1;
        } else {
            walk_expression(self, it);
        }
    }
}

/// Whether an expression statement provably has no effect: literals,
/// identifiers, templates without substitutions, and pure operators over
/// such operands. Calls, assignments, `delete`, tagged templates, and any
/// unrecognized shape are treated as effectful.
fn is_pointless_expression(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::Identifier(_)
        | Expression::ThisExpression(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::ParenthesizedExpression(parens) => is_pointless_expression(&parens.expression),
        Expression::UnaryExpression(unary) => {
            unary.operator != UnaryOperator::Delete && is_pointless_expression(&unary.argument)
        }
        Expression::BinaryExpression(binary) => {
            is_pointless_expression(&binary.left) && is_pointless_expression(&binary.right)
        }
        Expression::LogicalExpression(logical) => {
            is_pointless_expression(&logical.left) && is_pointless_expression(&logical.right)
        }
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .iter()
            .all(|expression| is_pointless_expression(expression)),
        _ => false,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_embedded_effects(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn embedded_updates_and_assignments_require_statement_roots() {
        let source = "\
let i = 0;
i++;
for (i = 0; i < 3; i++) {
  foo(i++);
}
let j = i++;
foo(k = 1);
if (k = 1) {}
m = n = 1;
";
        let report = js(source);
        let embedded: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| {
                matches!(
                    issue.rule_key.as_str(),
                    "javascript:S881" | "javascript:S1121"
                )
            })
            .map(|issue| {
                (
                    issue.rule_key.clone(),
                    (
                        issue.range.start.line,
                        issue.range.start.column,
                        issue.range.end.line,
                        issue.range.end.column,
                    ),
                )
            })
            .collect();
        // Standalone `i++`, the assignment in the `for` header, and the
        // statement-root assignment are clean; everything embedded deeper
        // than a statement root is flagged once per construct.
        let hit = |rule: &str, line: u32, start: u32, end: u32| {
            (rule.to_string(), (line, start, line, end))
        };
        assert_eq!(
            embedded,
            vec![
                hit("javascript:S881", 4, 6, 9),
                hit("javascript:S881", 6, 8, 11),
                hit("javascript:S1121", 7, 6, 7),
                hit("javascript:S1121", 8, 6, 7),
                hit("javascript:S1121", 9, 6, 7),
            ]
        );
    }

    #[test]
    fn s905_flags_pointless_expression_statements() {
        assert_eq!(
            count_key(
                &js_keys("foo;\n42;\n1 + 2;\nvoid 0;\n`done`;\n"),
                "javascript:S905"
            ),
            5
        );
    }

    #[test]
    fn s905_allows_effectful_expression_statements() {
        assert_eq!(
            count_key(
                &js_keys("foo();\n`x${y}`;\ndelete obj.p;\nlet q = 1;\ntag`x`;\n"),
                "javascript:S905"
            ),
            0
        );
    }

    #[test]
    fn s881_flags_updates_inside_sequence_statement_roots() {
        // The sequence expression is the statement root; both updates sit
        // one level deeper and are embedded.
        assert_eq!(count_key(&js_keys("i++, j++;\n"), "javascript:S881"), 2);
    }
}
