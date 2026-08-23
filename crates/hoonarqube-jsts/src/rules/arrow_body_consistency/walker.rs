// Family walker for 'arrow_body_consistency' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{ArrowFunctionBody, ArrowFunctionExpression};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_arrow_function_expression;
use oxc_span::{GetSpan, Span};

pub(crate) fn check_arrow_body_consistency(
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
        arrows: Vec::new(),
    };
    collector.visit_program(program);
    let block_bodies = collector.arrows.iter().filter(|(_, block)| *block).count();
    let expression_bodies = collector.arrows.len() - block_bodies;
    // Flag whichever style is the minority; on ties flag expression bodies.
    let minority_is_block = block_bodies < expression_bodies;
    let tie = block_bodies == expression_bodies;
    let flagged_arrows: Vec<Span> = collector
        .arrows
        .iter()
        .filter(|(span, uses_block_body)| {
            let _ = span;
            *uses_block_body == minority_is_block || (tie && !*uses_block_body)
        })
        .map(|(span, _)| *span)
        .collect();
    for span in flagged_arrows {
        collector.sink.emit_span(
            RuleScope::Both,
            "S3524",
            "Use a consistent arrow function body style in this file.",
            span,
        );
    }
    collector.sink.issues
}

/// `S3524`: arrow functions mixing concise-expression and block bodies
/// within one file; each arrow of the minority style is flagged (ties favor
/// block bodies).
pub(crate) struct ArrowStyleCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) arrows: Vec<(Span, bool)>,
}

impl<'a> Visit<'a> for ArrowStyleCollector<'_> {
    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let uses_block_body = matches!(it.body, ArrowFunctionBody::FunctionBody(_));
        self.arrows.push((it.span(), uses_block_body));
        walk_arrow_function_expression(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_arrow_body_consistency(ctx.program, ctx.index, ctx.language)
}
