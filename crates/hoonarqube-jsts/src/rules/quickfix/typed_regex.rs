use super::{Candidate, candidate, issue_offsets};
use crate::context::AnalysisContext;
use crate::engine::pattern_parser::has_unicode_surrogate_pair_in_class;
use crate::rules::shared::argument_expression;
use crate::support::{
    binding_identifier_name, expression_root_name, identifier_name, statement_as_expression,
    unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Argument, BinaryOperator, CallExpression, Expression, NewExpression, PropertyDefinition,
    RegExpFlags, TSIntersectionType, TSPropertySignature, TSType, TSUnionType,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_call_expression, walk_expression, walk_new_expression, walk_property_definition,
    walk_ts_intersection_type, walk_ts_property_signature, walk_ts_union_type,
};
use oxc_parser::{Kind, Token};
use oxc_semantic::Semantic;
use oxc_span::GetSpan;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Rule {
    S4621,
    S4623,
    S4634,
    S4782,
    S5868,
    S6326,
    S6426,
    S6439,
    S6594,
}
#[derive(Clone, Copy)]
struct IssueRef {
    index: usize,
    rule: Rule,
    start: usize,
    end: usize,
}

struct Collector<'a, 'ctx> {
    ctx: &'ctx AnalysisContext<'a>,
    semantic: &'ctx Semantic<'a>,
    issues: Vec<IssueRef>,
    used: Vec<bool>,
    out: Vec<(usize, Candidate)>,
}

pub(super) fn collect<'a>(
    ctx: &AnalysisContext<'a>,
    semantic: &Semantic<'a>,
    issues: &[Issue],
) -> Vec<(usize, Candidate)> {
    let issue_refs = issues
        .iter()
        .enumerate()
        .filter_map(|(index, issue)| {
            let rule = match issue.rule_key.rsplit(':').next()? {
                "S4621" => Rule::S4621,
                "S4623" => Rule::S4623,
                "S4634" => Rule::S4634,
                "S4782" => Rule::S4782,
                "S5868" => Rule::S5868,
                "S6326" => Rule::S6326,
                "S6426" => Rule::S6426,
                "S6439" => Rule::S6439,
                "S6594" => Rule::S6594,
                _ => return None,
            };
            let (start, end) = issue_offsets(ctx, issue)?;
            Some(IssueRef {
                index,
                rule,
                start,
                end,
            })
        })
        .collect::<Vec<_>>();
    if issue_refs.is_empty() {
        return Vec::new();
    }
    let used = vec![false; issue_refs.len()];
    let mut collector = Collector {
        ctx,
        semantic,
        issues: issue_refs,
        used,
        out: Vec::new(),
    };
    collector.visit_program(ctx.program);
    collector.out
}

impl Collector<'_, '_> {
    fn source(&self) -> &str {
        self.ctx.source
    }

    fn token_after(&self, offset: usize, limit: usize) -> Option<&Token> {
        self.ctx.tokens.iter().find(|token| {
            token.start() as usize >= offset
                && token.end() as usize <= limit
                && token.kind() != Kind::Skip
        })
    }

    fn token_before(&self, offset: usize) -> Option<&Token> {
        self.ctx
            .tokens
            .iter()
            .rev()
            .find(|token| token.end() as usize <= offset && token.kind() != Kind::Skip)
    }

    fn find_issue(&self, rule: Rule, start: usize, end: usize, enclosing: bool) -> Option<usize> {
        self.issues.iter().enumerate().find_map(|(slot, issue)| {
            if self.used[slot] || issue.rule != rule {
                return None;
            }
            let matches = if enclosing {
                issue.start >= start && issue.end <= end
            } else {
                issue.start == start && issue.end == end
            };
            matches.then_some(slot)
        })
    }

    fn take_issue(&mut self, slot: usize) -> IssueRef {
        self.used[slot] = true;
        self.issues[slot]
    }

    fn emit(&mut self, issue: IssueRef, value: Candidate) {
        self.out.push((issue.index, value));
    }

    fn emit_all_in(&mut self, rule: Rule, start: usize, end: usize) -> Vec<IssueRef> {
        let mut found = Vec::new();
        for slot in 0..self.issues.len() {
            let issue = self.issues[slot];
            if !self.used[slot] && issue.rule == rule && issue.start >= start && issue.end <= end {
                self.used[slot] = true;
                found.push(issue);
            }
        }
        found
    }

    fn check_constituents(&mut self, types: &[TSType<'_>], composite_end: usize) {
        for (index, current) in types.iter().enumerate().skip(1) {
            let span = current.span();
            let Some(slot) =
                self.find_issue(Rule::S4621, span.start as usize, span.end as usize, true)
            else {
                continue;
            };
            let issue = self.take_issue(slot);
            let previous_end =
                self.extend_closing(types[index - 1].span().end as usize, composite_end);
            let current_end = self.extend_closing(span.end as usize, composite_end);
            if previous_end < current_end {
                self.emit(
                    issue,
                    candidate(
                        "s4621-remove-duplicate-type",
                        "Remove duplicate types",
                        [(previous_end, current_end, String::new())],
                    ),
                );
            }
        }
    }

    fn extend_closing(&self, mut end: usize, limit: usize) -> usize {
        while let Some(token) = self.token_after(end, limit) {
            if token.kind() != Kind::RParen {
                break;
            }
            end = token.end() as usize;
        }
        end
    }

    fn check_undefined_argument(&mut self, call: &CallExpression<'_>) {
        let Some(last) = call.arguments.last() else {
            return;
        };
        let last_span = last.span();
        let Some(slot) = self.find_issue(
            Rule::S4623,
            last_span.start as usize,
            last_span.end as usize,
            true,
        ) else {
            return;
        };
        let issue = self.take_issue(slot);
        if call.arguments.len() == 1 {
            let Some(open) =
                self.token_after(call.callee.span().end as usize, call.span().end as usize)
            else {
                return;
            };
            let Some(close) = self.token_before(call.span().end as usize) else {
                return;
            };
            if open.kind() != Kind::LParen || close.kind() != Kind::RParen {
                return;
            }
            self.emit(
                issue,
                candidate(
                    "s4623-remove-undefined-argument",
                    "Remove this redundant argument",
                    [(open.end() as usize, close.start() as usize, String::new())],
                ),
            );
        } else if let Some(previous) = call.arguments.get(call.arguments.len() - 2) {
            self.emit(
                issue,
                candidate(
                    "s4623-remove-undefined-argument",
                    "Remove this redundant argument",
                    [(
                        previous.span().end as usize,
                        last_span.end as usize,
                        String::new(),
                    )],
                ),
            );
        }
    }

    fn check_promise(&mut self, expression: &NewExpression<'_>) {
        let Some(slot) = self.find_issue(
            Rule::S4634,
            expression.callee.span().start as usize,
            expression.callee.span().end as usize,
            true,
        ) else {
            return;
        };
        if expression.arguments.len() != 1 {
            return;
        }
        let Some(executor) = expression.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Some((first, second, body)) = executor_parts(executor) else {
            return;
        };
        let Expression::CallExpression(call) = unparenthesized(body) else {
            return;
        };
        if call.arguments.len() != 1 {
            return;
        }
        let Some(callee) = identifier_name(unparenthesized(&call.callee)) else {
            return;
        };
        let action = if first == Some(callee) {
            Some("resolve")
        } else if second == Some(callee) {
            Some("reject")
        } else {
            None
        };
        let Some(action) = action else {
            return;
        };
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let argument_text =
            self.source()[argument.span().start as usize..argument.span().end as usize].to_owned();
        let issue = self.take_issue(slot);
        self.emit(
            issue,
            candidate(
                "s4634-use-promise-action",
                "Replace with Promise action",
                [(
                    expression.span().start as usize,
                    expression.span().end as usize,
                    format!("Promise.{action}({argument_text})"),
                )],
            ),
        );
    }

    fn check_optional_property(
        &mut self,
        optional: bool,
        annotation: Option<&TSType>,
        key_end: usize,
        property_end: usize,
    ) {
        if !optional {
            return;
        }
        let Some(annotation) = annotation else {
            return;
        };
        let Some(slot) = self.find_issue(Rule::S4782, key_end, property_end, true) else {
            return;
        };
        let issue = self.take_issue(slot);
        let union = unwrap_type(annotation);
        let TSType::TSUnionType(union) = union else {
            return;
        };
        let Some(undefined_index) = union
            .types
            .iter()
            .position(|member| matches!(unwrap_type(member), TSType::TSUndefinedKeyword(_)))
        else {
            return;
        };
        let optional_candidate = candidate(
            "s4782-remove-optional-marker",
            "Remove \"?\" operator",
            [(issue.start, issue.end, String::new())],
        );
        self.emit(issue, optional_candidate);
        self.emit_undefined_type_candidates(issue, union, undefined_index, property_end);
    }

    fn emit_undefined_type_candidates(
        &mut self,
        issue: IssueRef,
        union: &TSUnionType<'_>,
        undefined_index: usize,
        property_end: usize,
    ) {
        let Some(undefined) = union.types.get(undefined_index) else {
            return;
        };
        if union.types.len() == 2 {
            let other = if undefined_index == 0 {
                &union.types[1]
            } else {
                &union.types[0]
            };
            let Some(other_text) = self
                .source()
                .get(other.span().start as usize..other.span().end as usize)
            else {
                return;
            };
            let mut edits = vec![(
                union.span.start as usize,
                union.span.end as usize,
                other_text.to_owned(),
            )];
            let before = self.token_before(union.span.start as usize);
            let after = self.token_after(union.span.end as usize, property_end);
            if before.is_some_and(|token| token.kind() == Kind::LParen)
                && after.is_some_and(|token| token.kind() == Kind::RParen)
            {
                edits.push((
                    before.unwrap().start() as usize,
                    before.unwrap().end() as usize,
                    String::new(),
                ));
                edits.push((
                    after.unwrap().start() as usize,
                    after.unwrap().end() as usize,
                    String::new(),
                ));
            }
            self.out.push((
                issue.index,
                candidate(
                    "s4782-remove-undefined-type",
                    "Remove \"undefined\" type annotation",
                    edits,
                ),
            ));
        } else if undefined_index == 0 {
            if let Some(next) = union.types.get(1) {
                self.out.push((
                    issue.index,
                    candidate(
                        "s4782-remove-undefined-type",
                        "Remove \"undefined\" type annotation",
                        [(
                            undefined.span().start as usize,
                            next.span().start as usize,
                            String::new(),
                        )],
                    ),
                ));
            }
        } else {
            let previous = &union.types[undefined_index - 1];
            self.out.push((
                issue.index,
                candidate(
                    "s4782-remove-undefined-type",
                    "Remove \"undefined\" type annotation",
                    [(
                        previous.span().end as usize,
                        undefined.span().end as usize,
                        String::new(),
                    )],
                ),
            ));
        }
    }

    fn check_focused_test(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
            return;
        };
        if member.property.name != "only" {
            return;
        }
        if !is_exclusive_test_root(&member.object) {
            return;
        }
        let property = &member.property;
        let Some(slot) = self.find_issue(
            Rule::S6426,
            property.span.start as usize,
            property.span.end as usize,
            true,
        ) else {
            return;
        };
        let issue = self.take_issue(slot);
        let Some(dot) = self.token_before(property.span.start as usize) else {
            return;
        };
        if dot.kind() != Kind::Dot {
            return;
        }
        self.emit(
            issue,
            candidate(
                "s6426-remove-only",
                "Remove \".only()\"",
                [(
                    dot.start() as usize,
                    property.span.end as usize,
                    String::new(),
                )],
            ),
        );
    }

    fn check_s6439_literal(&mut self, expression: &Expression<'_>) {
        let expression = unparenthesized(expression);
        let span = expression.span();
        if !matches!(
            expression,
            Expression::NumericLiteral(_)
                | Expression::StringLiteral(_)
                | Expression::BigIntLiteral(_)
        ) {
            return;
        }
        let Some(slot) =
            self.find_issue(Rule::S6439, span.start as usize, span.end as usize, false)
        else {
            return;
        };
        let issue = self.take_issue(slot);
        let text = self
            .source()
            .get(span.start as usize..span.end as usize)
            .unwrap_or_default();
        let mut edits = Vec::new();
        if let (Some(previous), Some(next)) = (
            self.token_before(span.start as usize),
            self.token_after(span.end as usize, self.source().len()),
        ) && previous.kind() == Kind::LParen
            && next.kind() == Kind::RParen
        {
            edits.push((
                previous.start() as usize,
                previous.end() as usize,
                String::new(),
            ));
            edits.push((next.start() as usize, next.end() as usize, String::new()));
        }
        edits.push((
            span.start as usize,
            span.end as usize,
            format!("!!({text})"),
        ));
        self.emit(
            issue,
            candidate(
                "s6439-convert-to-boolean",
                "Convert the conditional to a boolean",
                edits,
            ),
        );
    }

    fn check_s6594(&mut self, call: &CallExpression<'_>) {
        if call.arguments.len() != 1 {
            return;
        }
        let Expression::StaticMemberExpression(member) = unparenthesized(&call.callee) else {
            return;
        };
        if member.property.name != "match"
            || !receiver_is_known_string(&member.object, self.semantic)
        {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::RegExpLiteral(regex) = unparenthesized(argument) else {
            return;
        };
        if regex.regex.flags.contains(RegExpFlags::G) {
            return;
        }
        let property = &member.property;
        let Some(slot) = self.find_issue(
            Rule::S6594,
            property.span.start as usize,
            property.span.end as usize,
            true,
        ) else {
            return;
        };
        let issue = self.take_issue(slot);
        let Some(object_text) = self
            .source()
            .get(member.object.span().start as usize..member.object.span().end as usize)
        else {
            return;
        };
        let Some(regex_text) = self
            .source()
            .get(argument.span().start as usize..argument.span().end as usize)
        else {
            return;
        };
        self.emit(
            issue,
            candidate(
                "s6594-use-regexp-exec",
                "Replace with \"RegExp.exec()\"",
                [(
                    call.span().start as usize,
                    call.span().end as usize,
                    format!("RegExp({regex_text}).exec({object_text})"),
                )],
            ),
        );
    }

    fn check_constructor_regex(&mut self, callee: &Expression<'_>, arguments: &[Argument<'_>]) {
        if identifier_name(unparenthesized(callee)) != Some("RegExp") {
            return;
        }
        let Some(pattern_argument) = arguments.first() else {
            return;
        };
        let Some(mapping) = map_string_argument(self.source(), pattern_argument) else {
            return;
        };
        let pattern_start = pattern_argument.span().start as usize;
        let pattern_end = pattern_argument.span().end as usize;
        let runs = space_runs(&mapping);
        for (issue_index, issue) in self
            .emit_all_in(Rule::S6326, pattern_start, pattern_end)
            .into_iter()
            .enumerate()
        {
            let run = runs
                .iter()
                .find(|run| {
                    let Some(start) = mapping.chars.get(run.start).map(|(_, start, _)| *start)
                    else {
                        return false;
                    };
                    let Some(end) = mapping
                        .chars
                        .get(run.end.saturating_sub(1))
                        .map(|(_, _, end)| *end)
                    else {
                        return false;
                    };
                    issue.start >= start && issue.end <= end
                })
                .or_else(|| runs.get(issue_index));
            let Some(run) = run else {
                continue;
            };
            let Some(start) = mapping.chars.get(run.start).map(|(_, start, _)| *start) else {
                continue;
            };
            let Some(end) = mapping
                .chars
                .get(run.end.saturating_sub(1))
                .map(|(_, _, end)| *end)
            else {
                continue;
            };
            self.emit(
                issue,
                candidate(
                    "s6326-use-space-quantifier",
                    "Use a regex space quantifier",
                    [(start, end, format!(" {{{}}}", run.end - run.start))],
                ),
            );
        }

        let flags = arguments
            .get(1)
            .and_then(|argument| map_string_argument(self.source(), argument));
        for issue in self.emit_all_in(Rule::S5868, pattern_start, pattern_end) {
            if flags
                .as_ref()
                .is_some_and(|value| value.decoded.chars().any(|ch| matches!(ch, 'u' | 'v')))
                || !has_unicode_surrogate_pair_in_class(&mapping.decoded)
                || !unicode_pattern_is_valid(&mapping.decoded)
            {
                continue;
            }
            let edit = if let Some(flags_argument) = arguments.get(1) {
                let Some(flags_mapping) = flags.as_ref() else {
                    continue;
                };
                if flags_mapping
                    .decoded
                    .chars()
                    .any(|ch| matches!(ch, 'u' | 'v'))
                {
                    continue;
                }
                let end = flags_argument.span().end as usize;
                if end <= flags_argument.span().start as usize + 1 {
                    continue;
                }
                (end - 1, end - 1, "u".to_owned())
            } else {
                (pattern_end, pattern_end, ", \"u\"".to_owned())
            };
            self.emit(
                issue,
                candidate(
                    "s5868-add-unicode-flag",
                    "Add unicode 'u' flag to regex",
                    [edit],
                ),
            );
        }
    }

    fn check_regex_issue(&mut self, expression: &Expression<'_>) {
        let (span, flags, pattern_start, pattern_end, pattern) = match expression {
            Expression::RegExpLiteral(regex) => (
                regex.span,
                regex.regex.flags,
                regex.span.start as usize + 1,
                regex.span.end as usize - 1,
                regex.regex.pattern.text.as_str(),
            ),
            _ => return,
        };
        let pattern_end = pattern_end.max(pattern_start);
        let s6326_slots = self.emit_all_in(Rule::S6326, pattern_start, pattern_end);
        for issue in s6326_slots {
            let Some(text) = self
                .ctx
                .source
                .get(issue.start..issue.end)
                .map(str::to_owned)
            else {
                continue;
            };
            if text.chars().all(|ch| ch == ' ') && text.len() >= 2 {
                self.emit(
                    issue,
                    candidate(
                        "s6326-use-space-quantifier",
                        "Use a regex space quantifier",
                        [(issue.start, issue.end, format!(" {{{}}}", text.len()))],
                    ),
                );
            }
        }
        for issue in self.emit_all_in(Rule::S5868, span.start as usize, span.end as usize) {
            if flags.contains(RegExpFlags::U)
                || flags.contains(RegExpFlags::V)
                || !has_unicode_surrogate_pair_in_class(pattern)
                || !unicode_pattern_is_valid(pattern)
            {
                continue;
            }
            self.emit(
                issue,
                candidate(
                    "s5868-add-unicode-flag",
                    "Add unicode 'u' flag to regex",
                    [(span.end as usize, span.end as usize, "u".to_owned())],
                ),
            );
        }
    }
}

impl<'a> Visit<'a> for Collector<'_, 'a> {
    fn visit_ts_union_type(&mut self, it: &TSUnionType<'a>) {
        self.check_constituents(&it.types, it.span.end as usize);
        walk_ts_union_type(self, it);
    }

    fn visit_ts_intersection_type(&mut self, it: &TSIntersectionType<'a>) {
        self.check_constituents(&it.types, it.span.end as usize);
        walk_ts_intersection_type(self, it);
    }

    fn visit_ts_property_signature(&mut self, it: &TSPropertySignature<'a>) {
        let annotation = it
            .type_annotation
            .as_ref()
            .map(|value| &value.type_annotation);
        self.check_optional_property(
            it.optional,
            annotation,
            it.key.span().end as usize,
            it.span.end as usize,
        );
        walk_ts_property_signature(self, it);
    }

    fn visit_property_definition(&mut self, it: &PropertyDefinition<'a>) {
        let annotation = it
            .type_annotation
            .as_ref()
            .map(|value| &value.type_annotation);
        self.check_optional_property(
            it.optional,
            annotation,
            it.key.span().end as usize,
            it.span.end as usize,
        );
        walk_property_definition(self, it);
    }

    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_undefined_argument(it);
        self.check_focused_test(it);
        self.check_s6594(it);
        self.check_constructor_regex(&it.callee, &it.arguments);
        walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        self.check_promise(it);
        self.check_constructor_regex(&it.callee, &it.arguments);
        walk_new_expression(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        self.check_s6439_literal(it);
        self.check_regex_issue(it);
        walk_expression(self, it);
    }
}
struct StringMapping {
    decoded: String,
    chars: Vec<(char, usize, usize)>,
}

struct SpaceRun {
    start: usize,
    end: usize,
}

fn map_string_argument(source: &str, argument: &Argument<'_>) -> Option<StringMapping> {
    let (inner_start, raw_inner) = string_literal_inner(source, argument)?;
    map_string_inner(raw_inner, inner_start)
}

fn string_literal_inner<'a>(source: &'a str, argument: &Argument<'_>) -> Option<(usize, &'a str)> {
    let expression = argument.as_expression()?;
    let span = expression.span();
    let start = span.start as usize;
    let end = span.end as usize;
    let raw = source.get(start..end)?;
    let quote = raw.as_bytes().first().copied()?;
    if !matches!(quote, b'\'' | b'"' | b'`') || raw.as_bytes().last().copied() != Some(quote) {
        return None;
    }
    let inner_start = start + 1;
    let inner_end = end.checked_sub(1)?;
    Some((inner_start, source.get(inner_start..inner_end)?))
}

fn map_string_inner(raw_inner: &str, inner_start: usize) -> Option<StringMapping> {
    let mut decoded = String::new();
    let mut chars = Vec::new();
    let bytes = raw_inner.as_bytes();
    let mut pending_surrogate: Option<(u16, usize, usize)> = None;
    let mut offset = 0;
    while offset < bytes.len() {
        map_string_character(
            raw_inner,
            inner_start,
            bytes,
            &mut offset,
            &mut pending_surrogate,
            &mut decoded,
            &mut chars,
        )?;
    }
    flush_pending_surrogate(&mut pending_surrogate, &mut decoded, &mut chars);
    Some(StringMapping { decoded, chars })
}

fn map_string_character(
    raw_inner: &str,
    inner_start: usize,
    bytes: &[u8],
    offset: &mut usize,
    pending_surrogate: &mut Option<(u16, usize, usize)>,
    decoded: &mut String,
    chars: &mut Vec<(char, usize, usize)>,
) -> Option<()> {
    let source_start = inner_start + *offset;
    if bytes[*offset] != b'\\' {
        let character = raw_inner[*offset..].chars().next()?;
        let next = *offset + character.len_utf8();
        flush_pending_surrogate(pending_surrogate, decoded, chars);
        push_mapped_character(decoded, chars, character, source_start, inner_start + next);
        *offset = next;
        return Some(());
    }

    *offset += 1;
    let escaped = *bytes.get(*offset)?;
    *offset += 1;
    let escape = decode_escape(raw_inner, bytes, offset, escaped)?;
    apply_decoded_escape(
        escape,
        source_start,
        inner_start + *offset,
        pending_surrogate,
        decoded,
        chars,
    )
}

fn apply_decoded_escape(
    escape: DecodedEscape,
    source_start: usize,
    source_end: usize,
    pending_surrogate: &mut Option<(u16, usize, usize)>,
    decoded: &mut String,
    chars: &mut Vec<(char, usize, usize)>,
) -> Option<()> {
    match escape {
        DecodedEscape::Continuation => {}
        DecodedEscape::Character(character) => {
            flush_pending_surrogate(pending_surrogate, decoded, chars);
            push_mapped_character(decoded, chars, character, source_start, source_end);
        }
        DecodedEscape::Utf16CodeUnit(unit) => map_utf16_code_unit(
            unit,
            source_start,
            source_end,
            pending_surrogate,
            decoded,
            chars,
        )?,
    }
    Some(())
}

fn map_utf16_code_unit(
    unit: u16,
    source_start: usize,
    source_end: usize,
    pending_surrogate: &mut Option<(u16, usize, usize)>,
    decoded: &mut String,
    chars: &mut Vec<(char, usize, usize)>,
) -> Option<()> {
    if let Some((high, pending_start, pending_end)) = pending_surrogate.take() {
        if (0xDC00..=0xDFFF).contains(&unit) {
            let scalar = 0x1_0000 + ((u32::from(high) - 0xD800) << 10) + (u32::from(unit) - 0xDC00);
            let character = char::from_u32(scalar)?;
            push_mapped_character(decoded, chars, character, pending_start, source_end);
            return Some(());
        }
        push_mapped_character(decoded, chars, '\u{FFFD}', pending_start, pending_end);
    }
    if (0xD800..=0xDBFF).contains(&unit) {
        *pending_surrogate = Some((unit, source_start, source_end));
    } else {
        push_mapped_character(decoded, chars, '\u{FFFD}', source_start, source_end);
    }
    Some(())
}

fn push_mapped_character(
    decoded: &mut String,
    chars: &mut Vec<(char, usize, usize)>,
    character: char,
    start: usize,
    end: usize,
) {
    decoded.push(character);
    chars.push((character, start, end));
}

fn flush_pending_surrogate(
    pending: &mut Option<(u16, usize, usize)>,
    decoded: &mut String,
    chars: &mut Vec<(char, usize, usize)>,
) {
    if let Some((_, start, end)) = pending.take() {
        push_mapped_character(decoded, chars, '\u{FFFD}', start, end);
    }
}

#[derive(Clone, Copy)]
enum DecodedEscape {
    Character(char),
    Utf16CodeUnit(u16),
    Continuation,
}

fn decode_escape(
    raw_inner: &str,
    bytes: &[u8],
    offset: &mut usize,
    escaped: u8,
) -> Option<DecodedEscape> {
    let character = match escaped {
        b'n' => '\n',
        b'r' => '\r',
        b't' => '\t',
        b'b' => '\u{0008}',
        b'f' => '\u{000c}',
        b'v' => '\u{000b}',
        b'0' => '\0',
        b'x' => {
            let digits = raw_inner.get(*offset..*offset + 2)?;
            let value = u8::from_str_radix(digits, 16).ok()?;
            *offset += 2;
            char::from(value)
        }
        b'u' => {
            if bytes.get(*offset) == Some(&b'{') {
                *offset += 1;
                let digits_start = *offset;
                while bytes.get(*offset).is_some_and(u8::is_ascii_hexdigit) {
                    *offset += 1;
                }
                let digits = raw_inner.get(digits_start..*offset)?;
                if bytes.get(*offset) != Some(&b'}') {
                    return None;
                }
                *offset += 1;
                let value = u32::from_str_radix(digits, 16).ok()?;
                return Some(DecodedEscape::Character(char::from_u32(value)?));
            }
            let digits = raw_inner.get(*offset..*offset + 4)?;
            *offset += 4;
            let value = u16::from_str_radix(digits, 16).ok()?;
            return Some(if (0xD800..=0xDFFF).contains(&value) {
                DecodedEscape::Utf16CodeUnit(value)
            } else {
                DecodedEscape::Character(char::from_u32(u32::from(value))?)
            });
        }
        b'\n' | b'\r' => {
            if escaped == b'\r' && bytes.get(*offset) == Some(&b'\n') {
                *offset += 1;
            }
            return Some(DecodedEscape::Continuation);
        }
        other => other as char,
    };
    Some(DecodedEscape::Character(character))
}

fn space_runs(mapping: &StringMapping) -> Vec<SpaceRun> {
    let mut runs = Vec::new();
    let mut in_class = false;
    let mut escaped = false;
    let mut start = None;
    for (index, (character, _, _)) in mapping.chars.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if *character == '\\' {
            escaped = true;
            finish_space_run(&mut runs, &mut start, index);
            continue;
        }
        if *character == '[' {
            in_class = true;
        } else if *character == ']' {
            in_class = false;
        }
        if !in_class && *character == ' ' {
            start.get_or_insert(index);
        } else {
            finish_space_run(&mut runs, &mut start, index);
        }
    }
    finish_space_run(&mut runs, &mut start, mapping.chars.len());
    runs
}

fn finish_space_run(runs: &mut Vec<SpaceRun>, start: &mut Option<usize>, end: usize) {
    if let Some(begin) = start.take()
        && end.saturating_sub(begin) >= 2
    {
        runs.push(SpaceRun { start: begin, end });
    }
}

fn unwrap_type<'a>(mut ty: &'a TSType<'a>) -> &'a TSType<'a> {
    while let TSType::TSParenthesizedType(parenthesized) = ty {
        ty = &parenthesized.type_annotation;
    }
    ty
}

fn executor_parts<'a>(
    executor: &'a Expression<'a>,
) -> Option<(Option<&'a str>, Option<&'a str>, &'a Expression<'a>)> {
    match unparenthesized(executor) {
        Expression::ArrowFunctionExpression(arrow) => {
            let first = arrow
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern));
            let second = arrow
                .params
                .items
                .get(1)
                .and_then(|item| binding_identifier_name(&item.pattern));
            let body = match arrow.body.as_function_body() {
                Some(body) if body.statements.len() == 1 => {
                    statement_as_expression(&body.statements[0])?
                }
                Some(_) => return None,
                None => arrow.body.to_expression(),
            };
            Some((first, second, body))
        }
        Expression::FunctionExpression(function) => {
            let first = function
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern));
            let second = function
                .params
                .items
                .get(1)
                .and_then(|item| binding_identifier_name(&item.pattern));
            let body = function.body.as_deref()?;
            if body.statements.len() != 1 {
                return None;
            }
            Some((first, second, statement_as_expression(&body.statements[0])?))
        }
        _ => None,
    }
}

fn is_exclusive_test_root(expression: &Expression<'_>) -> bool {
    match unparenthesized(expression) {
        Expression::Identifier(identifier) => matches!(
            identifier.name.as_str(),
            "context" | "describe" | "it" | "specify" | "test"
        ),
        _ => expression_root_name(unparenthesized(expression))
            .is_some_and(|name| matches!(name, "context" | "describe" | "it" | "specify" | "test")),
    }
}

fn receiver_is_known_string(expression: &Expression<'_>, semantic: &Semantic<'_>) -> bool {
    receiver_is_known_string_inner(expression, semantic, &mut Vec::new())
}

fn receiver_is_known_string_inner(
    expression: &Expression<'_>,
    semantic: &Semantic<'_>,
    seen: &mut Vec<oxc_syntax::symbol::SymbolId>,
) -> bool {
    match unparenthesized(expression) {
        Expression::StringLiteral(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::BinaryExpression(binary) if binary.operator == BinaryOperator::Addition => {
            receiver_is_known_string_inner(&binary.left, semantic, seen)
                && receiver_is_known_string_inner(&binary.right, semantic, seen)
        }
        Expression::Identifier(identifier) => {
            let Some(reference_id) = identifier.reference_id.get() else {
                return false;
            };
            let Some(symbol_id) = semantic.scoping().get_reference(reference_id).symbol_id() else {
                return false;
            };
            if seen.contains(&symbol_id)
                || semantic.nodes().is_empty()
                || semantic.scoping().symbol_is_mutated(symbol_id)
            {
                return false;
            }
            seen.push(symbol_id);
            let result = match semantic.symbol_declaration(symbol_id).kind() {
                AstKind::VariableDeclarator(declarator) => declarator
                    .init
                    .as_ref()
                    .is_some_and(|init| receiver_is_known_string_inner(init, semantic, seen)),
                _ => false,
            };
            seen.pop();
            result
        }
        _ => false,
    }
}

fn unicode_pattern_is_valid(pattern: &str) -> bool {
    !pattern.is_empty() && crate::engine::pattern_parser::parse_regex_pattern(pattern, true).is_ok()
}
