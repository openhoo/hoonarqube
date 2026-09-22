// Family walker for 'regex_family' (generated).
use super::s5856_constant_regex_site::check_constant_regex_site;
use super::s6328_replacement_groups::check_replacement_groups;
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::engine::pattern_parser::{
    constructor_regex_site, literal_string_value, parse_regex_pattern, regex_flags_text,
    regex_literal_argument, regex_site_from_literal,
};
use crate::rules::shared::call_property;
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
fn check_regex_family(
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
    dedupe_identical_issues(&mut collector.sink.issues);
    collector.sink.issues
}

/// Drops byte-identical findings — same rule, message, and range — while
/// keeping the first occurrence. One regex source range yields at most
/// one finding per rule (#787); genuinely distinct findings at different
/// ranges or with different messages are preserved.
fn dedupe_identical_issues(issues: &mut Vec<Issue>) {
    let mut seen = std::collections::HashSet::new();
    issues.retain(|issue| {
        seen.insert((
            issue.rule_key.clone(),
            issue.message.clone(),
            issue.range.start.line,
            issue.range.start.column,
            issue.range.end.line,
            issue.range.end.column,
        ))
    });
}

/// Drives [`check_constant_regex_site`] over every constant regex and adds
/// the context-sensitive rules: `S6325` (constructor preference), `S6328`
/// (replacement groups), and `S6351` (stateful global regexes in loops).
struct RegexFamilyCollector<'index> {
    sink: IssueSink<'index>,
    loop_depth: u32,
}

impl RegexFamilyCollector<'_> {
    /// `S6325`: a fully constant `RegExp` constructor call prefers literal
    /// notation (upstream `prefer-regex-literals` primary message).
    fn check_constructor(&mut self, arguments: &[oxc_ast::ast::Argument<'_>], span: Span) {
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
    fn check_replacement_pair(&mut self, call: &CallExpression<'_>) {
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
    fn check_stateful_global_regex(&mut self, object_member: &MemberExpression<'_>, span: Span) {
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn constant_regexp_constructor_prefers_literal() {
        let flagged = js_keys("const re = new RegExp('ab+c');\nRegExp('\\\\d+', 'g');\n");
        assert_eq!(count_key(&flagged, "javascript:S6325"), 2);

        // A substitution-free template literal also counts as constant.
        let template = js_keys("const re = new RegExp(`ab+c`);\n");
        assert_eq!(count_key(&template, "javascript:S6325"), 1);

        let dynamic = js_keys("const re = new RegExp(userPattern);\n");
        assert_eq!(count_key(&dynamic, "javascript:S6325"), 0);

        let literal_form = js_keys("const re = /ab+c/;\n");
        assert_eq!(count_key(&literal_form, "javascript:S6325"), 0);

        let dynamic_flags = js_keys("const re = new RegExp('ab+c', flags);\n");
        assert_eq!(count_key(&dynamic_flags, "javascript:S6325"), 0);

        let invalid_flags = js_keys("const re = new RegExp('ab+c', 'gg');\n");
        assert_eq!(count_key(&invalid_flags, "javascript:S5856"), 1);
    }

    #[test]
    fn wholly_empty_groups_are_flagged() {
        let capturing = js_keys("const re = /()/;\n");
        assert_eq!(count_key(&capturing, "javascript:S6331"), 1);
        // A wholly empty group is not reported as an empty alternative.
        assert_eq!(count_key(&capturing, "javascript:S6323"), 0);

        let non_capturing = js_keys("const re = /(?:)/;\n");
        assert_eq!(count_key(&non_capturing, "javascript:S6331"), 1);

        let clean = js_keys("const re = /(a)/;\n");
        assert_eq!(count_key(&clean, "javascript:S6331"), 0);
    }

    #[test]
    fn duplicate_class_members_are_flagged() {
        let duplicated = js_keys("const re = /[aa]/;\n");
        assert_eq!(count_key(&duplicated, "javascript:S5869"), 1);
        // Duplicate-only classes additionally receive the concise rewrite.
        assert_eq!(count_key(&duplicated, "javascript:S6353"), 1);

        // Both duplicates anchor at the first member's span, so the two
        // findings are byte-identical and collapse to one (#787).
        let twice = js_keys("const re = /[aaa]/;\n");
        assert_eq!(count_key(&twice, "javascript:S5869"), 1);

        let clean = js_keys("const re = /[ab]/;\n");
        assert_eq!(count_key(&clean, "javascript:S5869"), 0);
    }

    #[test]
    fn space_runs_in_patterns_are_flagged() {
        let double = js_keys("const re = /a  b/;\n");
        assert_eq!(count_key(&double, "javascript:S6326"), 1);

        let triple = js_keys("const re = /a   b/;\n");
        assert_eq!(count_key(&triple, "javascript:S6326"), 1);

        let clean = js_keys("const re = /a b/;\n");
        assert_eq!(count_key(&clean, "javascript:S6326"), 0);
    }

    #[test]
    fn empty_string_repetition_is_flagged() {
        // Bounded repetition over a group that can match empty still loops.
        let bounded = js_keys("const re = /x(a*){2}y/;\n");
        assert_eq!(count_key(&bounded, "javascript:S5842"), 1);

        // `(a*)+` trips both this rule and exponential backtracking.
        let unbounded = js_keys("const re = /(a*)+b/;\n");
        assert_eq!(count_key(&unbounded, "javascript:S5842"), 1);
        assert_eq!(count_key(&unbounded, "javascript:S5852"), 1);

        let clean = js_keys("const re = /(a+){2}/;\n");
        assert_eq!(count_key(&clean, "javascript:S5842"), 0);
    }

    #[test]
    fn single_char_alternations_become_classes() {
        let top_level = js_keys("const re = /a|b|c/;\n");
        assert_eq!(count_key(&top_level, "javascript:S6035"), 1);

        // Alternations nested inside groups are flagged at the group span.
        let nested = js_keys("const re = /x(a|b)y/;\n");
        assert_eq!(count_key(&nested, "javascript:S6035"), 1);

        let clean = js_keys("const re = /(ab)|c/;\n");
        assert_eq!(count_key(&clean, "javascript:S6035"), 0);
    }

    #[test]
    fn nested_unbounded_quantifiers_risk_backtracking() {
        let classic = js_keys("const re = /(a+)+$/;\n");
        assert_eq!(count_key(&classic, "javascript:S5852"), 1);
        // `(a+)` cannot match empty, so S5842 stays silent here.
        assert_eq!(count_key(&classic, "javascript:S5842"), 0);

        // Empty-matchable bodies are reported regardless of the outer
        // quantifier minimum.
        let zero_min = js_keys("const re = /(a*)*b/;\n");
        assert_eq!(count_key(&zero_min, "javascript:S5852"), 1);
        assert_eq!(count_key(&zero_min, "javascript:S5842"), 1);

        let flat = js_keys("const re = /a+b+c/;\n");
        assert_eq!(count_key(&flat, "javascript:S5852"), 0);
    }

    #[test]
    fn stateful_global_regexes_inside_loops_are_flagged() {
        let while_loop =
            js_keys("while (more) {\n  if (/\\d+/g.test(input)) {\n    more = false;\n  }\n}\n");
        assert_eq!(count_key(&while_loop, "javascript:S6351"), 1);

        let for_of_loop =
            js_keys("for (const part of parts) {\n  const m = /[a-z]+/g.exec(part);\n}\n");
        assert_eq!(count_key(&for_of_loop, "javascript:S6351"), 1);

        let outside_loop = js_keys("const found = /\\d+/g.test(input);\n");
        assert_eq!(count_key(&outside_loop, "javascript:S6351"), 0);

        let not_global = js_keys("while (more) {\n  found = /\\d+/.test(input);\n}\n");
        assert_eq!(count_key(&not_global, "javascript:S6351"), 0);
    }

    /// #787: two nested unbounded quantifiers in one literal produced two
    /// byte-identical `S5852` findings at the same source range.
    #[test]
    fn one_regex_range_yields_at_most_one_finding_per_rule() {
        let report = js(
            "export function isUnsafeSlug(value) {\n  return /^((a+)+)+$/.test(\n    value,\n  );\n}\n",
        );
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S5852")
            .collect();
        assert_eq!(findings.len(), 1);
        let finding = findings[0];
        assert_eq!(finding.range.start, pos(2, 9));
        assert_eq!(finding.range.end, pos(2, 21));
        assert_eq!(
            finding.message,
            "Make sure the regex used here, which is vulnerable to super-linear runtime due to backtracking, cannot lead to denial of service."
        );

        // Distinct vulnerable sites keep their own findings.
        let two_sites = js_keys("const a = /(x+)+/;\nconst b = /(y+)+/;\n");
        assert_eq!(count_key(&two_sites, "javascript:S5852"), 2);

        // The same guard covers other site-span rules: two Unicode
        // constructs in one literal still report once.
        let unicode = js_keys("const re = /\\p{L}\\p{N}/;\n");
        assert_eq!(count_key(&unicode, "javascript:S5867"), 1);
    }

    /// #792: the reference `S5843` scorer charges nesting-aware costs for
    /// quantifiers, lookarounds, and multi-branch disjunctions only; the
    /// slug regex scores 16 and stays under the budget of 20.
    #[test]
    fn regex_complexity_matches_reference_scoring() {
        // Nested optional groups, repeated separators, anchors, and
        // character classes: 16 <= 20, no finding.
        let slug =
            js_keys("const re = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:--[a-z0-9]+(?:-[a-z0-9]+)*)?$/;\n");
        assert_eq!(count_key(&slug, "javascript:S5843"), 0);

        // Anchors, literals, dots, and shorthand escapes are free.
        let free = js_keys("const re = /^\\w.\\d+$/;\n");
        assert_eq!(count_key(&free, "javascript:S5843"), 0);

        // SonarJS unit-test anchors: `/(?:a|b|c)*/` scores 4 and
        // `|/?[a-z]` scores 4 (disjunction 1 + quantifier 2 + class 1).
        let nested_alternation = js_keys("const re = /(?:a|b|c)*/;\n");
        assert_eq!(count_key(&nested_alternation, "javascript:S5843"), 0);
        let leading_branch = js_keys("const re = /|\\/?[a-z]/;\n");
        assert_eq!(count_key(&leading_branch, "javascript:S5843"), 0);

        // Boundary: 20 stays clean, 21 reports.
        let at_budget = js_keys("const re = /(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u)/;\n");
        assert_eq!(count_key(&at_budget, "javascript:S5843"), 0);
        let over_budget =
            js_keys("const re = /(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v)/;\n");
        assert_eq!(count_key(&over_budget, "javascript:S5843"), 1);

        // TypeScript shares the same scoring for equivalent syntax.
        let slug_ts =
            ts_keys("const re = /^[a-z0-9]+(?:-[a-z0-9]+)*(?:--[a-z0-9]+(?:-[a-z0-9]+)*)?$/;\n");
        assert_eq!(count_key(&slug_ts, "typescript:S5843"), 0);
        let over_ts = ts_keys("const re = /(?:a|b|c|d|e|f|g|h|i|j|k|l|m|n|o|p|q|r|s|t|u|v)/;\n");
        assert_eq!(count_key(&over_ts, "typescript:S5843"), 1);
    }
}
