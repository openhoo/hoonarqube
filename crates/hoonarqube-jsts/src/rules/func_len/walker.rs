// Family walker for 'func_len' (generated).
use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionExpression, Declaration, ExportDefaultDeclarationKind, Expression,
    MethodDefinition,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_declaration, walk_export_default_declaration_kind,
    walk_expression, walk_method_definition,
};
use oxc_span::{GetSpan, Span};

fn check_function_lengths(
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
struct FunctionLengthCollector<'index> {
    sink: IssueSink<'index>,
    maximum_function_lines: u32,
}

impl FunctionLengthCollector<'_> {
    fn check_length(&mut self, span: Span, anchor: Span) {
        let start_line = self.sink.index.pos(span.start).line;
        let end_line = self.sink.index.pos(span.end).line;
        let length = end_line - start_line + 1;
        if length > self.maximum_function_lines {
            let anchor_start = self.sink.index.pos(anchor.start);
            let anchor_end = self.sink.index.pos(anchor.end);
            self.sink.emit_pos(
                RuleScope::Both,
                "S138",
                &format!(
                    "This function has {} lines, which is greater than the {} lines authorized. \
                     Split it into smaller functions.",
                    length, self.maximum_function_lines
                ),
                (anchor_start.line, anchor_start.column),
                (anchor_end.line, anchor_end.column),
            );
        }
    }
}

impl<'a> Visit<'a> for FunctionLengthCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            self.check_length(
                function.span(),
                function
                    .id
                    .as_ref()
                    .map_or_else(|| function.span(), GetSpan::span),
            );
        }
        walk_expression(self, it);
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            self.check_length(
                function.span(),
                function
                    .id
                    .as_ref()
                    .map_or_else(|| function.span(), GetSpan::span),
            );
        }
        walk_declaration(self, it);
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        if let ExportDefaultDeclarationKind::FunctionDeclaration(function) = it {
            self.check_length(
                function.span(),
                function
                    .id
                    .as_ref()
                    .map_or_else(|| function.span(), GetSpan::span),
            );
        }
        walk_export_default_declaration_kind(self, it);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.check_length(it.span(), it.span());
        walk_arrow_function_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        self.check_length(it.span(), it.key.span());
        walk_method_definition(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_function_lengths(ctx.program, ctx.index, ctx.language, ctx.rules)
}
#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s138_flags_function_exceeding_configured_line_budget() {
        let rules = RuleOptions {
            maximum_function_lines: 2,
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules("function big() {\n  a();\n  b();\n  c();\n}\n", &rules);
        assert_eq!(count_key(&flagged, "javascript:S138"), 1);
        let line = flagged
            .iter()
            .find(|(key, _)| key == "javascript:S138")
            .map(|(_, line)| *line);
        assert_eq!(line, Some(1));
    }

    #[test]
    fn s138_allows_functions_at_exact_boundary_length() {
        let rules = RuleOptions {
            maximum_function_lines: 5,
            ..RuleOptions::default()
        };
        let at_limit = keys_with_rules("function big() {\n  a();\n  b();\n  c();\n}\n", &rules);
        assert_eq!(count_key(&at_limit, "javascript:S138"), 0);
    }

    #[test]
    fn s138_checks_arrows_and_methods_default_budget_passes_short_functions() {
        let rules = RuleOptions {
            maximum_function_lines: 1,
            ..RuleOptions::default()
        };
        let flagged = keys_with_rules(
            "const handler = () => {\n  step();\n  step();\n};\nclass K {\n  go() {\n    a();\n    b();\n  }\n}\n",
            &rules,
        );
        assert_eq!(count_key(&flagged, "javascript:S138"), 2);

        let tiny = js_keys("function tiny(value) {\n  return value;\n}\n");
        assert_eq!(count_key(&tiny, "javascript:S138"), 0);
    }
}
