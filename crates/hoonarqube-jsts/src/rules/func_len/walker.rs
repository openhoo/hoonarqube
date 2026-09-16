// Family walker for 'func_len' (generated).
use crate::JstsLanguage;
use crate::context::{AnalysisContext, RuleOptions};
use crate::support::{IssueSink, LineIndex, RuleScope, ScannedComment, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionExpression, CallExpression, Declaration, ExportDefaultDeclarationKind, Expression,
    MethodDefinition, ReturnStatement, VariableDeclarator,
};
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_call_expression, walk_declaration,
    walk_export_default_declaration_kind, walk_expression, walk_method_definition,
    walk_return_statement, walk_variable_declarator,
};
use oxc_span::{GetSpan, Span};
use std::collections::{BTreeMap, HashSet};

fn check_function_lengths(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    rules: &RuleOptions,
    comments: &[ScannedComment],
) -> Vec<Issue> {
    let mut collector = FunctionLengthCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        maximum_function_lines: rules.maximum_function_lines,
        comment_spans: comments.iter().map(|comment| comment.token).collect(),
        pending: BTreeMap::new(),
        frames: Vec::new(),
        iife_callees: HashSet::new(),
        arrow_names: BTreeMap::new(),
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// A function whose length check is deferred until its body has been
/// walked, so the React-component and IIFE exemptions are known.
struct PendingFunction {
    span: Span,
    anchor: Span,
    starts_with_capital: bool,
}

/// One in-progress function body on the walk stack.
struct FunctionFrame {
    returns_jsx: bool,
}

/// `S138`: functions whose body covers more than `max` lines of code
/// (blank lines and lines holding only comments do not count). IIFEs and
/// capitalized functions returning JSX (React components) are exempt,
/// matching the reference rule.
struct FunctionLengthCollector<'index> {
    sink: IssueSink<'index>,
    maximum_function_lines: u32,
    /// Sorted comment token spans for full-line comment detection.
    comment_spans: Vec<Span>,
    /// Deferred checks keyed by function span start.
    pending: BTreeMap<u32, PendingFunction>,
    /// Stack of in-progress function bodies (innermost last).
    frames: Vec<FunctionFrame>,
    /// Span starts of function expressions used as a call callee (IIFEs).
    iife_callees: HashSet<u32>,
    /// Capitalization of arrow functions bound by a variable declarator.
    arrow_names: BTreeMap<u32, bool>,
}

impl FunctionLengthCollector<'_> {
    /// Lines of code inside `span`: physical lines minus blank lines and
    /// lines whose only content is a comment.
    fn lines_of_code(&self, span: Span) -> u32 {
        let start_line = self.sink.index.pos(span.start).line;
        let end_line = self.sink.index.pos(span.end).line;
        u32::try_from(
            self.sink
                .index
                .lines()
                .skip(usize::try_from(start_line.saturating_sub(1)).unwrap_or(0))
                .take(usize::try_from(end_line - start_line + 1).unwrap_or(0))
                .filter(|(line_number, text)| {
                    !text.trim().is_empty() && !self.is_full_line_comment(*line_number, text)
                })
                .count(),
        )
        .unwrap_or(u32::MAX)
    }

    /// Whether `text` on `line_number` is entirely covered by a comment.
    fn is_full_line_comment(&self, line_number: u32, text: &str) -> bool {
        let line_start = self
            .sink
            .index
            .line_starts
            .get(usize::try_from(line_number - 1).unwrap_or(0))
            .copied()
            .unwrap_or(0);
        let leading = text.len() - text.trim_start().len();
        let trailing = text.len() - text.trim_end().len();
        let content_start = line_start + u32::try_from(leading).unwrap_or(0);
        let content_end = line_start + u32::try_from(text.len() - trailing).unwrap_or(0);
        // Comments are sorted by start; only the latest comment starting
        // at or before the content can cover it.
        let candidate = self
            .comment_spans
            .partition_point(|comment| comment.start <= content_start)
            .checked_sub(1)
            .map(|index| self.comment_spans[index]);
        candidate.is_some_and(|comment| comment.end >= content_end)
    }

    /// Emits the deferred check for `span` once the body was walked.
    fn finish_function(&mut self, span_start: u32, returns_jsx: bool) {
        let Some(pending) = self.pending.remove(&span_start) else {
            return;
        };
        if self.iife_callees.contains(&span_start) {
            return;
        }
        if pending.starts_with_capital && returns_jsx {
            return;
        }
        let length = self.lines_of_code(pending.span);
        if length > self.maximum_function_lines {
            let anchor_start = self.sink.index.pos(pending.anchor.start);
            let anchor_end = self.sink.index.pos(pending.anchor.end);
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

    fn defer(&mut self, span: Span, anchor: Span, starts_with_capital: bool) {
        self.pending.insert(
            span.start,
            PendingFunction {
                span,
                anchor,
                starts_with_capital,
            },
        );
    }
}

impl<'a> Visit<'a> for FunctionLengthCollector<'_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        if matches!(
            kind,
            AstKind::Function(_) | AstKind::ArrowFunctionExpression(_)
        ) {
            self.frames.push(FunctionFrame { returns_jsx: false });
        }
    }

    fn leave_node(&mut self, kind: AstKind<'a>) {
        let span_start = match kind {
            AstKind::Function(function) => Some(function.span.start),
            AstKind::ArrowFunctionExpression(arrow) => Some(arrow.span.start),
            _ => None,
        };
        let Some(span_start) = span_start else {
            return;
        };
        if let Some(frame) = self.frames.pop() {
            self.finish_function(span_start, frame.returns_jsx);
        }
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let Some(frame) = self.frames.last_mut()
            && let Some(argument) = &it.argument
            && matches!(
                unparenthesized(argument),
                Expression::JSXElement(_) | Expression::JSXFragment(_)
            )
        {
            frame.returns_jsx = true;
        }
        walk_return_statement(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::FunctionExpression(function) = unparenthesized(&it.callee) {
            self.iife_callees.insert(function.span.start);
        }
        walk_call_expression(self, it);
    }

    fn visit_variable_declarator(&mut self, it: &VariableDeclarator<'a>) {
        if let Some(init) = &it.init
            && let Expression::ArrowFunctionExpression(arrow) = unparenthesized(init)
        {
            let capital = it
                .id
                .get_identifier_name()
                .is_some_and(|name| name.chars().next().is_some_and(char::is_uppercase));
            self.arrow_names.insert(arrow.span.start, capital);
        }
        walk_variable_declarator(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if let Expression::FunctionExpression(function) = it {
            let capital = function
                .id
                .as_ref()
                .and_then(|id| id.name.chars().next())
                .is_some_and(char::is_uppercase);
            self.defer(
                function.span(),
                function
                    .id
                    .as_ref()
                    .map_or_else(|| function.span(), GetSpan::span),
                capital,
            );
        }
        walk_expression(self, it);
    }

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if let Declaration::FunctionDeclaration(function) = it {
            let capital = function
                .id
                .as_ref()
                .and_then(|id| id.name.chars().next())
                .is_some_and(char::is_uppercase);
            self.defer(
                function.span(),
                function
                    .id
                    .as_ref()
                    .map_or_else(|| function.span(), GetSpan::span),
                capital,
            );
        }
        walk_declaration(self, it);
    }

    fn visit_export_default_declaration_kind(&mut self, it: &ExportDefaultDeclarationKind<'a>) {
        if let ExportDefaultDeclarationKind::FunctionDeclaration(function) = it {
            let capital = function
                .id
                .as_ref()
                .and_then(|id| id.name.chars().next())
                .is_some_and(char::is_uppercase);
            self.defer(
                function.span(),
                function
                    .id
                    .as_ref()
                    .map_or_else(|| function.span(), GetSpan::span),
                capital,
            );
        }
        walk_export_default_declaration_kind(self, it);
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let capital = self
            .arrow_names
            .get(&it.span.start)
            .copied()
            .unwrap_or(false);
        self.defer(it.span(), it.span(), capital);
        walk_arrow_function_expression(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        // The reference sees the method's FunctionExpression: measure and
        // key the deferral by the inner function span (the `leave_node`
        // key), anchored on the method name.
        self.defer(it.value.span(), it.key.span(), false);
        walk_method_definition(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_function_lengths(
        ctx.program,
        ctx.index,
        ctx.language,
        ctx.rules,
        &ctx.comments,
    )
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

    #[test]
    fn s138_counts_code_lines_only_and_exempts_iifes() {
        // Regression of #505: the reference counts lines of code — blank
        // lines and lines holding only comments do not count, but the
        // signature and closing-brace lines do — and never reports IIFEs.
        let rules = RuleOptions {
            maximum_function_lines: 3,
            ..RuleOptions::default()
        };
        let padded = keys_with_rules(
            "function big() {\n  a();\n\n  // explanatory comment\n}\n",
            &rules,
        );
        assert_eq!(count_key(&padded, "javascript:S138"), 0);

        // A multi-line comment still exempts the lines it covers.
        let blocked = keys_with_rules(
            "function big() {\n  a();\n  /* block\n     comment */\n}\n",
            &rules,
        );
        assert_eq!(count_key(&blocked, "javascript:S138"), 0);

        let iife = keys_with_rules(
            "(function () {\n  a();\n  b();\n  c();\n  d();\n})();\n",
            &rules,
        );
        assert_eq!(count_key(&iife, "javascript:S138"), 0);

        // A dense function over the same budget still flags.
        let dense = keys_with_rules(
            "function big() {\n  a();\n  b();\n  c();\n  d();\n}\n",
            &rules,
        );
        assert_eq!(count_key(&dense, "javascript:S138"), 1);
    }

    #[test]
    fn s138_exempts_capitalized_functions_returning_jsx() {
        let rules = RuleOptions {
            maximum_function_lines: 2,
            ..RuleOptions::default()
        };
        let component = keys_with_rules(
            "function Panel() {\n  const a = 1;\n  const b = 2;\n  const c = 3;\n  return <div>{a}{b}{c}</div>;\n}\n",
            &rules,
        );
        assert_eq!(count_key(&component, "javascript:S138"), 0);

        // Lowercase functions returning JSX are ordinary functions.
        let helper = keys_with_rules(
            "function panel() {\n  const a = 1;\n  const b = 2;\n  const c = 3;\n  return <div>{a}</div>;\n}\n",
            &rules,
        );
        assert_eq!(count_key(&helper, "javascript:S138"), 1);
    }
}
