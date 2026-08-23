// Family walker for 'exception_handling' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, ScannedComment, binding_identifier_name, identifier_name,
    scan_comments,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    CatchClause, Declaration, Expression, MethodDefinition, MethodDefinitionKind, ReturnStatement,
    Statement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_catch_clause, walk_declaration, walk_expression, walk_method_definition,
};
use oxc_span::{GetSpan, Span};

pub(crate) fn check_exception_handling(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ExceptionHandlingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        comments: scan_comments(source),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S2486`, `S2737`, and `S2432` in one traversal.
pub(crate) struct ExceptionHandlingCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) comments: Vec<ScannedComment>,
}

impl<'a> Visit<'a> for ExceptionHandlingCollector<'a> {
    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        // `S2737`: exactly one statement rethrowing the caught binding.
        if it.body.body.len() == 1
            && let Statement::ThrowStatement(thrown) = &it.body.body[0]
        {
            let caught = it
                .param
                .as_ref()
                .and_then(|param| binding_identifier_name(&param.pattern));
            if caught.is_some() && identifier_name(&thrown.argument) == caught {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2737",
                    "This catch clause does nothing but rethrow the caught exception.",
                    thrown.span(),
                );
            }
        }
        // `S2486`: an empty catch is flagged unless it carries a comment
        // explaining why the exception is ignored.
        if it.body.body.is_empty() {
            let inner = Span::new(it.body.span.start + 1, it.body.span.end.saturating_sub(1));
            if !span_contains_comment(&self.comments, inner) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2486",
                    "Handle this exception or remove this empty catch clause.",
                    it.body.span(),
                );
            }
        }
        walk_catch_clause(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        // `S2432`: setters returning a value.
        if it.kind == MethodDefinitionKind::Set {
            let mut scanner = ReturnValueScanner::default();
            if let Some(body) = &it.value.body {
                scanner.visit_function_body(body);
            }
            if scanner.found {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S2432",
                    "Setters should not return values.",
                    it.key.span(),
                );
            }
        }
        walk_method_definition(self, it);
    }
}

/// Finds `return <value>` statements outside nested functions; used to skip
/// function subtrees while scanning setter bodies.
#[derive(Default)]
pub(crate) struct ReturnValueScanner {
    pub(crate) found: bool,
}

impl<'a> Visit<'a> for ReturnValueScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if it.argument.is_some() {
            self.found = true;
        }
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }
}

/// Whether any scanned comment lies inside `span` (overlap counts).
pub(crate) fn span_contains_comment(comments: &[ScannedComment], span: Span) -> bool {
    comments
        .iter()
        .any(|comment| comment.token.start < span.end && span.start < comment.token.end)
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_exception_handling(ctx.program, ctx.source, ctx.index, ctx.language)
}
