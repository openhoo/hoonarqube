// Family walker for 'regex_family' (generated).
use super::s5856_constant_regex_site::check_constant_regex_site;
use super::s6328_replacement_groups::check_replacement_groups;
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::pattern_parser::{
    constructor_regex_site, literal_string_value, parse_regex_pattern, regex_flags_text,
    regex_literal_argument, regex_site_from_literal,
};
use crate::rules::expression::walker::call_property;
use crate::support::{
    IssueSink, LineIndex, RuleScope, callee_name, constructor_name, member_object, unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    CallExpression, DoWhileStatement, Expression, ForInStatement, ForOfStatement, ForStatement,
    MemberExpression, NewExpression, RegExpFlags, WhileStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_call_expression, walk_do_while_statement, walk_expression, walk_for_in_statement,
    walk_for_of_statement, walk_for_statement, walk_new_expression, walk_while_statement,
};
use oxc_span::{GetSpan, Span};

/// All Batch3 regex-family checks in one traversal: the shared pattern
/// walker over `S5856`, `S2639`, `S6323`, `S6331`, `S5869`, `S6397`,
/// `S6353`, `S6326`, `S6324`, `S5842`, `S6019`, `S6035`, `S5850`, `S5867`,
/// `S5868`, `S5843`, and `S5852`, plus context rules `S6325`, `S6328`, and
/// `S6351`.
pub(crate) fn check_regex_family(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = RegexFamilyCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        loop_depth: 0,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Drives [`check_constant_regex_site`] over every constant regex and adds
/// the context-sensitive rules: `S6325` (constructor preference), `S6328`
/// (replacement groups), and `S6351` (stateful global regexes in loops).
pub(crate) struct RegexFamilyCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) loop_depth: u32,
}

impl RegexFamilyCollector<'_> {
    /// `S6325`: a fully constant `RegExp` constructor call prefers literal
    /// notation (upstream `prefer-regex-literals` primary message).
    pub(crate) fn check_constructor(
        &mut self,
        arguments: &[oxc_ast::ast::Argument<'_>],
        span: Span,
    ) {
        let Some(site) = constructor_regex_site(arguments) else {
            return;
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S6325",
            "Use a regular expression literal instead of the 'RegExp' constructor.",
            span,
        );
        check_constant_regex_site(&mut self.sink, &site);
    }

    /// `S6328`: `.replace(/…/, "…")` pairs cross-check replacement group
    /// references against the pattern's captures.
    pub(crate) fn check_replacement_pair(&mut self, call: &CallExpression<'_>) {
        let Some(regex) = regex_literal_argument(call.arguments.first()) else {
            return;
        };
        let Some(replacement) = call.arguments.get(1) else {
            return;
        };
        let Some(text) = literal_string_value(replacement) else {
            return;
        };
        let flags = regex_flags_text(regex.regex.flags);
        let unicode_mode = flags.contains('u') || flags.contains('v');
        if let Ok(parsed) = parse_regex_pattern(regex.regex.pattern.text.as_str(), unicode_mode) {
            check_replacement_groups(&mut self.sink, replacement.span(), &text, &parsed);
        }
    }

    /// `S6351` subset: a `/g` regex literal feeding `.test()` or `.exec()`
    /// inside a loop carries hidden `lastIndex` state.
    pub(crate) fn check_stateful_global_regex(
        &mut self,
        object_member: &MemberExpression<'_>,
        span: Span,
    ) {
        if self.loop_depth == 0 {
            return;
        }
        let Expression::RegExpLiteral(literal) = unparenthesized(member_object(object_member))
        else {
            return;
        };
        if literal.regex.flags.contains(RegExpFlags::G) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6351",
                "Extract this regular expression to avoid infinite loop.",
                span,
            );
        }
    }
}

impl Visit<'_> for RegexFamilyCollector<'_> {
    fn visit_expression(&mut self, it: &Expression<'_>) {
        if let Expression::RegExpLiteral(literal) = it {
            let site = regex_site_from_literal(literal);
            check_constant_regex_site(&mut self.sink, &site);
        }
        walk_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'_>) {
        if constructor_name(it) == Some("RegExp") {
            self.check_constructor(&it.arguments, it.span());
        }
        walk_new_expression(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'_>) {
        if callee_name(it) == Some("RegExp") {
            self.check_constructor(&it.arguments, it.span());
        }
        if let Some((property, member)) = call_property(it) {
            match property {
                "replace" | "replaceAll" => self.check_replacement_pair(it),
                "test" | "exec" => self.check_stateful_global_regex(member, it.span()),
                _ => {}
            }
        }
        walk_call_expression(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'_>) {
        self.loop_depth += 1;
        walk_for_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'_>) {
        self.loop_depth += 1;
        walk_for_in_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'_>) {
        self.loop_depth += 1;
        walk_for_of_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'_>) {
        self.loop_depth += 1;
        walk_while_statement(self, it);
        self.loop_depth -= 1;
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'_>) {
        self.loop_depth += 1;
        walk_do_while_statement(self, it);
        self.loop_depth -= 1;
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_regex_family(ctx.program, ctx.index, ctx.language)
}
