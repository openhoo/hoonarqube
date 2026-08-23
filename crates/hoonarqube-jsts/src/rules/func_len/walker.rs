// Family walker for 'func_len' (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{ArrowFunctionExpression, Declaration, ExportDefaultDeclarationKind, Expression, MethodDefinition};
use oxc_ast_visit::{Visit};
use oxc_ast_visit::walk::{walk_arrow_function_expression, walk_declaration, walk_export_default_declaration_kind, walk_expression, walk_method_definition};
use oxc_span::{GetSpan, Span};
use crate::{JstsLanguage};
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::{IssueSink, LineIndex, RuleScope};


pub(crate) fn check_function_lengths(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
) -> Vec<Issue> {
    let mut collector = FunctionLengthCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        maximum_function_lines: rules.maximum_function_lines,
    };
    collector.visit_program(program);
    collector.sink.issues
}


/// `S138`: functions whose span covers more than `max` physical lines
/// (`end_line - start_line`, blank/comment trimming approximate per the
/// classification artifact).
pub(crate) struct FunctionLengthCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) maximum_function_lines: u32,
}


impl FunctionLengthCollector<'_> {
    pub(crate) fn check_length(&mut self, span: Span) {
        let start_line = self.sink.index.pos(span.start).line;
        let end_line = self.sink.index.pos(span.end).line;
        let length = end_line - start_line;
        if length > self.maximum_function_lines {
            self.sink.emit_pos(
                RuleScope::Both,
                "S138",
                &format!(
                    "This function has {} lines, which is greater than the {} authorized. \
                     Split it into smaller pieces.",
                    length, self.maximum_function_lines
                ),
                (start_line, 0),
                (start_line, 0),
            );
        }
    }
}


impl<'a> Visit<'a> for FunctionLengthCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.check_length(function.span());
        }
        walk_expression(self, it);
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            self.check_length(function.span());
        }
        walk_declaration(self, it);
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        if let ExportDefaultDeclarationKind::FunctionDeclaration(function) = it {
            self.check_length(function.span());
        }
        walk_export_default_declaration_kind(self, it);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.check_length(it.span());
        walk_arrow_function_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.check_length(it.span());
        walk_method_definition(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_function_lengths(
        ctx.program,
        ctx.index,
        ctx.language,
        ctx.rules,
    )
}
