// Family walker for 'arrow_body_consistency' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope, ScannedComment, source_slice};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionBody, ArrowFunctionExpression, BindingPattern, Expression, FunctionBody, Statement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_arrow_function_expression;
use oxc_span::GetSpan;

fn check_arrow_body_consistency(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    comments: &[ScannedComment],
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ArrowStyleCollector {
        source,
        comments,
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// The body-style part of `S3524`: a block-bodied arrow whose only statement is
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

/// Only a plain identifier can omit arrow parameter parentheses. TypeScript
/// annotations, optional parameters and generic arrows require their syntax,
/// as do defaults, destructuring, rest and multiple parameters.
fn arrow_parameter_parentheses_are_removable(
    arrow: &ArrowFunctionExpression<'_>,
    source: &str,
    comments: &[ScannedComment],
) -> bool {
    if arrow.params.items.len() != 1
        || arrow.params.rest.is_some()
        || arrow.type_parameters.is_some()
        || arrow.return_type.is_some()
    {
        return false;
    }
    let parameter = &arrow.params.items[0];
    if !matches!(parameter.pattern, BindingPattern::BindingIdentifier(_))
        || parameter.initializer.is_some()
        || parameter.type_annotation.is_some()
        || parameter.optional
    {
        return false;
    }
    // JavaScript can put a JSDoc type annotation inside the parentheses.
    // Keep that parameter annotation, matching the retained Commander case.
    if comments.iter().any(|comment| {
        arrow.params.span.start <= comment.token.start
            && comment.token.end <= arrow.params.span.end
            && source_slice(source, comment.token).starts_with("/**")
            && source_slice(source, comment.body)
                .split_whitespace()
                .any(|word| word == "@type")
    }) {
        return false;
    }
    let parameters = source_slice(source, arrow.params.span);
    parameters.starts_with('(') && parameters.ends_with(')')
}

struct ArrowStyleCollector<'index> {
    source: &'index str,
    comments: &'index [ScannedComment],
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for ArrowStyleCollector<'_> {
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        if arrow_parameter_parentheses_are_removable(it, self.source, self.comments) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3524",
                "Remove parentheses around the parameter of this arrow function.",
                it.params.items[0].pattern.span(),
            );
        }
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
    check_arrow_body_consistency(
        ctx.program,
        ctx.source,
        &ctx.comments,
        ctx.index,
        ctx.language,
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s3524_reports_single_identifier_parentheses_with_reference_range_and_message() {
        for report in [js("const f = (x) => x;\n"), ts("const f = (x) => x;\n")] {
            let findings: Vec<_> = report
                .issues
                .into_iter()
                .filter(|finding| finding.rule_key.ends_with(":S3524"))
                .collect();
            assert_eq!(findings.len(), 1);
            assert_eq!(
                findings[0].message,
                "Remove parentheses around the parameter of this arrow function."
            );
            assert_eq!(findings[0].range.start, pos(1, 11));
            assert_eq!(findings[0].range.end, pos(1, 12));
            assert!(findings[0].fix.is_none());
            assert!(findings[0].alternatives.is_empty());
        }
    }

    #[test]
    fn s3524_required_parameter_parentheses_and_bare_identifiers_are_clean() {
        let source = "const bare = x => x;\n\
                      const object = ({ x }) => x;\n\
                      const array = ([x]) => x;\n\
                      const fallback = (x = 1) => x;\n\
                      const rest = (...xs) => xs;\n\
                      const multiple = (x, y) => x + y;\n\
                      const empty = () => 1;\n";
        for report in [js(source), ts(source)] {
            assert_eq!(
                report
                    .issues
                    .iter()
                    .filter(|issue| issue.rule_key.ends_with(":S3524"))
                    .count(),
                0
            );
        }
    }

    #[test]
    fn s3524_typescript_annotations_and_generic_arrows_keep_parentheses() {
        let report = ts("const typed = (x: number) => x;\n\
             const optional = (x?) => x;\n\
             const returnTyped = (x): number => x;\n\
             const generic = <T>(x) => x;\n");
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.rule_key == "typescript:S3524")
                .count(),
            0
        );
    }

    #[test]
    fn s3524_parameter_and_body_consistency_are_independent() {
        let report = js("const f = (x) => { return x; };\n");
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|finding| finding.rule_key == "javascript:S3524")
            .collect();
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().any(|finding| finding.message
            == "Remove parentheses around the parameter of this arrow function."));
        assert!(findings.iter().any(|finding| finding.message
            == "Remove curly braces and \"return\" from this arrow function body."));
    }

    #[test]
    fn s3524_parenthesized_async_identifier_is_reported() {
        let report = js("const f = async (x) => x;\n");
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|finding| finding.rule_key == "javascript:S3524")
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].range.start, pos(1, 17));
        assert_eq!(findings[0].range.end, pos(1, 18));
    }

    #[test]
    fn s3524_jsdoc_typed_parameter_parentheses_are_clean() {
        let findings =
            js_keys("const f = (/** @type {HelpTextEventContext} */ context) => context;\n");
        assert_eq!(count_key(&findings, "javascript:S3524"), 0);
    }

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
