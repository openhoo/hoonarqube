// Family walker for 'arrow_body_consistency' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionBody, ArrowFunctionExpression, Expression, FunctionBody, Statement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_arrow_function_expression;
use oxc_span::GetSpan;

fn check_arrow_body_consistency(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ArrowStyleCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S3524`: a block-bodied arrow whose only statement is
/// `return <expression>;` on a single line can drop its braces. A bare
/// `return {}` stays unflagged because the concise form would parse as a
/// block, and expression bodies are never flagged.
fn arrow_body_is_removable_return(body: &FunctionBody<'_>, index: &LineIndex) -> bool {
    if !body.directives.is_empty() || body.statements.len() != 1 {
        return false;
    }
    let Statement::ReturnStatement(return_statement) = &body.statements[0] else {
        return false;
    };
    let Some(argument) = return_statement.argument.as_ref() else {
        return false;
    };
    if matches!(argument, Expression::ObjectExpression(_)) {
        return false;
    }
    let span = argument.span();
    index.pos(span.start).line == index.pos(span.end).line
}

struct ArrowStyleCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for ArrowStyleCollector<'_> {
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if let ArrowFunctionBody::FunctionBody(body) = &it.body
            && arrow_body_is_removable_return(body, self.sink.index)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3524",
                "Remove curly braces and \"return\" from this arrow function body.",
                it.body.span(),
            );
        }
        walk_arrow_function_expression(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_arrow_body_consistency(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s3524_flags_single_return_block_body() {
        let findings = js_keys("const a = () => {\n  return 1;\n};\n");
        assert_eq!(count_key(&findings, "javascript:S3524"), 1);
    }

    #[test]
    fn s3524_ignores_unconvertible_block_bodies() {
        // Multi-statement bodies, single non-return statements, bare
        // `return;`, and `return {}` can never become expression bodies.
        let findings = js_keys(
            "const multi = () => {\n  const x = 1;\n  return x;\n};\n\
             const side_effect = () => {\n  call();\n};\n\
             const bare = () => {\n  return;\n};\n\
             const object = () => {\n  return {};\n};\n",
        );
        assert_eq!(count_key(&findings, "javascript:S3524"), 0);
    }

    #[test]
    fn s3524_never_flags_expression_bodies() {
        // Expression-bodied arrows stay silent even when block-bodied
        // arrows dominate the file.
        let findings = js_keys(
            "const a = () => {\n  return 1;\n};\nconst b = () => {\n  return 2;\n};\nconst c = () => 3;\n",
        );
        assert_eq!(count_key(&findings, "javascript:S3524"), 2);
    }

    #[test]
    fn s3524_ignores_multiline_return_expressions() {
        let findings = js_keys(
            "const a = () => {\n  return (\n    longCall(\n      argument\n    )\n  );\n};\n",
        );
        assert_eq!(count_key(&findings, "javascript:S3524"), 0);
    }

    #[test]
    fn s3524_flags_nested_convertible_arrows() {
        let findings = js_keys("const outer = () => () => {\n  return 1;\n};\n");
        assert_eq!(count_key(&findings, "javascript:S3524"), 1);
    }
}
