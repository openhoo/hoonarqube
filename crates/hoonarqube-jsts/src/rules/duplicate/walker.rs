// Family walker for 'duplicate' (generated).
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use crate::{JstsLanguage, is_literal_expression};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    Expression, FunctionBody, IfStatement, ReturnStatement, Statement, SwitchStatement,
};
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::Visit;
use oxc_span::{ContentEq, GetSpan, Span};
use std::collections::BTreeSet;

pub(crate) fn check_duplicate_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = DuplicateCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        if_statements: Vec::new(),
        function_bodies: Vec::new(),
        return_groups: Vec::new(),
        current_return_group: None,
        group_stack: Vec::new(),
    };
    collector.visit_program(program);
    collector.check_if_chains();
    collector.check_similar_functions();
    collector.check_invariant_returns();
    collector.sink.issues
}

// ===== Batch2a: structural duplicate/identity checks (S1764 S1871 S3923 S1862 S4144 S3516) =====

/// `S1764` (identical binary operands), `S1871`/`S3923`/`S1862` (duplicated
/// branches and conditions), and `S3516` (invariant literal returns),
/// collected in one traversal; `S4144` (identical function bodies) is
/// resolved afterwards through span-free subtree equality (`ContentEq`).
pub(crate) struct DuplicateCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) if_statements: Vec<&'a IfStatement<'a>>,
    pub(crate) function_bodies: Vec<&'a FunctionBody<'a>>,
    pub(crate) return_groups: Vec<Vec<&'a ReturnStatement<'a>>>,
    pub(crate) current_return_group: Option<usize>,
    pub(crate) group_stack: Vec<Option<usize>>,
}

impl<'a> Visit<'a> for DuplicateCollector<'a, '_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            AstKind::IfStatement(statement) => self.if_statements.push(statement),
            AstKind::BinaryExpression(expression) => {
                if expression.left.content_eq(&expression.right) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S1764",
                        "Identical sub-expressions on both sides of this operator.",
                        expression.span,
                    );
                }
            }
            AstKind::ConditionalExpression(expression) => {
                if expression.consequent.content_eq(&expression.alternate) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3923",
                        "Either remove this branch or refactor the code to avoid duplication.",
                        expression.span,
                    );
                }
            }
            AstKind::SwitchStatement(statement) => self.check_switch_cases(statement),
            AstKind::FunctionBody(body) => {
                let group = self.return_groups.len();
                self.return_groups.push(Vec::new());
                self.function_bodies.push(body);
                self.group_stack.push(self.current_return_group);
                self.current_return_group = Some(group);
            }
            AstKind::ReturnStatement(statement) => {
                if let Some(group) = self.current_return_group {
                    self.return_groups[group].push(statement);
                }
            }
            _ => {}
        }
    }

    fn leave_node(&mut self, kind: AstKind<'a>) {
        if matches!(kind, AstKind::FunctionBody(_)) {
            self.current_return_group = self.group_stack.pop().flatten();
        }
    }
}

impl<'a> DuplicateCollector<'a, '_> {
    pub(crate) fn check_switch_cases(&mut self, it: &SwitchStatement<'a>) {
        let cases = &it.cases;
        if cases.len() < 2 {
            return;
        }
        // `S1862`: a case test duplicating an earlier one.
        for (position, case) in cases.iter().enumerate().skip(1) {
            let Some(test) = &case.test else {
                continue;
            };
            let duplicated = cases[..position].iter().any(|earlier| {
                earlier
                    .test
                    .as_ref()
                    .is_some_and(|previous| test.content_eq(previous))
            });
            if duplicated {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1862",
                    "This case duplicates an earlier case; merge the clauses.",
                    test.span(),
                );
            }
        }
        // `S1871`: consecutive cases with identical bodies (fallthrough
        // placeholders without statements do not count).
        for pair in cases.windows(2) {
            if let Some(first) = pair[1].consequent.first()
                && statements_equal(&pair[0].consequent, &pair[1].consequent)
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1871",
                    "This branch's code is identical to the previous branch's.",
                    first.span(),
                );
            }
        }
        // `S3923`: every case carrying the same non-empty body.
        let all_populated = cases.iter().all(|case| !case.consequent.is_empty());
        let all_identical = cases.first().is_some_and(|first| {
            cases
                .iter()
                .all(|case| statements_equal(&first.consequent, &case.consequent))
        });
        if all_populated && all_identical {
            self.sink.emit_span(
                RuleScope::Both,
                "S3923",
                "Either remove this branch or refactor the code to avoid duplication.",
                it.span,
            );
        }
    }

    /// Resolves the deferred if-chain rules once every `IfStatement` has
    /// been collected; chains are processed from their heads only so no
    /// link is reported twice.
    pub(crate) fn check_if_chains(&mut self) {
        let statements = std::mem::take(&mut self.if_statements);
        let chained_starts: BTreeSet<u32> = statements
            .iter()
            .filter_map(|statement| match statement.alternate.as_ref() {
                Some(Statement::IfStatement(next)) => Some(next.span.start),
                _ => None,
            })
            .collect();
        for head in statements {
            if !chained_starts.contains(&head.span.start) {
                self.check_single_chain(head);
            }
        }
    }
    pub(crate) fn check_single_chain(&mut self, head: &'a IfStatement<'a>) {
        // `S1871`: any link whose own branches are structurally equal.
        let mut current = head;
        loop {
            if let Some(alternate) = current.alternate.as_ref()
                && current.consequent.content_eq(alternate)
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1871",
                    "This branch's code is identical to the previous branch's.",
                    alternate.span(),
                );
            }
            match current.alternate.as_ref() {
                Some(Statement::IfStatement(next)) => current = next,
                _ => break,
            }
        }
        let mut tests: Vec<&Expression<'a>> = vec![&head.test];
        let mut branches: Vec<&Statement<'a>> = vec![&head.consequent];
        current = head;
        while let Some(alternate) = current.alternate.as_ref() {
            match alternate {
                Statement::IfStatement(next) => {
                    tests.push(&next.test);
                    branches.push(&next.consequent);
                    current = next;
                }
                other => {
                    branches.push(other);
                    break;
                }
            }
        }
        // `S1862`: repeated conditions within the same chain.
        for (position, test) in tests.iter().enumerate().skip(1) {
            if tests[..position]
                .iter()
                .any(|earlier| test.content_eq(earlier))
            {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1862",
                    "This condition duplicates an earlier condition in the same chain; \
                     merge the branches.",
                    test.span(),
                );
            }
        }
        // `S3923`: every branch carrying the same non-empty code.
        let all_identical = branches.windows(2).all(|pair| pair[0].content_eq(pair[1]));
        let all_populated = branches.iter().all(|branch| !is_empty_block(branch));
        if branches.len() >= 2 && all_identical && all_populated {
            self.sink.emit_span(
                RuleScope::Both,
                "S3923",
                "Either remove this branch or refactor the code to avoid duplication.",
                head.span,
            );
        }
    }

    /// `S4144`: function bodies identical to an earlier body in the same
    /// file; single-line bodies count as trivial and are skipped.
    pub(crate) fn check_similar_functions(&mut self) {
        let bodies = std::mem::take(&mut self.function_bodies);
        for (position, body) in bodies.iter().enumerate() {
            if !self.spans_multiple_lines(body.span) {
                continue;
            }
            let matches_earlier = bodies[..position]
                .iter()
                .any(|other| self.spans_multiple_lines(other.span) && other.content_eq(body));
            if matches_earlier {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4144",
                    "This function body is identical to another function's body; \
                     factor it out into a shared function.",
                    body.span,
                );
            }
        }
    }

    /// `S3516`: functions whose returns all yield the same literal.
    pub(crate) fn check_invariant_returns(&mut self) {
        let groups = std::mem::take(&mut self.return_groups);
        for returns in groups {
            let Some(second) = returns.get(1) else {
                continue;
            };
            let all_literals = returns.iter().all(|statement| {
                statement
                    .argument
                    .as_ref()
                    .is_some_and(is_literal_expression)
            });
            if !all_literals {
                continue;
            }
            let Some(baseline) = returns[0].argument.as_ref() else {
                continue;
            };
            let invariant = returns[1..].iter().all(|statement| {
                statement
                    .argument
                    .as_ref()
                    .is_some_and(|argument| argument.content_eq(baseline))
            });
            if invariant {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3516",
                    "All return statements of this function return the same value; \
                     simplify them.",
                    second.span(),
                );
            }
        }
    }

    pub(crate) fn spans_multiple_lines(&self, span: Span) -> bool {
        let start = self.sink.index.pos(span.start).line;
        let end = self.sink.index.pos(span.end).line;
        start != end
    }
}

/// Elementwise span-free equality of two statement lists.
pub(crate) fn statements_equal(left: &[Statement<'_>], right: &[Statement<'_>]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left_item, right_item)| left_item.content_eq(right_item))
}

pub(crate) fn is_empty_block(statement: &Statement<'_>) -> bool {
    matches!(statement, Statement::BlockStatement(block) if block.body.is_empty())
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_duplicate_rules(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn identical_binary_operands_flagged() {
        let report =
            js("if (a === a) {}\nif (b + c === b + c) {}\nif (x == y) {}\nlet t = p && p;\n");
        assert_eq!(count_key(&report_keys(&report), "javascript:S1764"), 2);
        let first: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1764")
            .collect();
        assert_eq!(
            first[0].range,
            hoonarqube_ir::Range {
                start: pos(1, 4),
                end: pos(1, 11),
            }
        );
    }

    #[test]
    fn identical_if_branches_and_switch_cases_flagged() {
        let report = js(
            "function f(cond) {\n  if (cond) { work(); cleanup(); } else { work(); cleanup(); }\n}\n",
        );
        // The identical if/else pair is reported by both rule keys.
        assert_eq!(count_key(&report_keys(&report), "javascript:S1871"), 1);
        assert_eq!(count_key(&report_keys(&report), "javascript:S3923"), 1);

        let switch = js(
            "function g(v) {\nswitch (v) { case 1: a(); break; case 2: a(); break; case 3: b(); break; }\n}\n",
        );
        assert_eq!(count_key(&report_keys(&switch), "javascript:S1871"), 1);

        // Fallthrough placeholders are not duplicated bodies.
        let fallthrough = js("switch (v) { case 1: case 2: a(); break; }\n");
        assert_eq!(count_key(&report_keys(&fallthrough), "javascript:S1871"), 0);
    }

    #[test]
    fn all_identical_branch_structures_flagged_once() {
        let ternary = js("const r = flag ? 1 : 1;\n");
        assert_eq!(count_key(&report_keys(&ternary), "javascript:S3923"), 1);

        let chain =
            js("function f(a, b) {\n  if (a) { x(); } else if (b) { x(); } else { x(); }\n}\n");
        assert_eq!(count_key(&report_keys(&chain), "javascript:S3923"), 1);
        // Only the last link's branches are identical.
        assert_eq!(count_key(&report_keys(&chain), "javascript:S1871"), 1);
    }

    #[test]
    fn duplicated_conditions_in_chains_and_switches_flagged() {
        let chain = js("function f(a) {\n  if (a === 1) { x(); } else if (a === 1) { y(); }\n}\n");
        assert_eq!(count_key(&report_keys(&chain), "javascript:S1862"), 1);

        let distinct =
            js("function f(a, b) {\n  if (a === 1) { x(); } else if (b === 1) { y(); }\n}\n");
        assert_eq!(count_key(&report_keys(&distinct), "javascript:S1862"), 0);

        let switch = js("switch (v) { case 1: r(); break; case 1: s(); break; }\n");
        assert_eq!(count_key(&report_keys(&switch), "javascript:S1862"), 1);
    }

    #[test]
    fn identical_function_bodies_flagged_but_trivial_ones_skipped() {
        let source = "\
function alpha() {
  setup();
  run();
}
function beta() {
  setup();
  run();
}
function gamma() {
  other();
}
";
        let report = js(source);
        assert_eq!(count_key(&report_keys(&report), "javascript:S4144"), 1);

        let trivial = js("function d1() { x(); }\nfunction d2() { x(); }\n");
        assert_eq!(count_key(&report_keys(&trivial), "javascript:S4144"), 0);
    }

    #[test]
    fn invariant_literal_returns_flagged_once_per_function() {
        let same = js("function f(n) {\n  if (n) { return 'same'; }\n  return 'same';\n}\n");
        assert_eq!(count_key(&report_keys(&same), "javascript:S3516"), 1);

        let differing = js("function f(n) {\n  if (n) { return 'a'; }\n  return 'b';\n}\n");
        assert_eq!(count_key(&report_keys(&differing), "javascript:S3516"), 0);

        // A bare `return` means the returns are not all literal values.
        let bare_mixed = js("function f(n) {\n  if (n) { return; }\n  return 'x';\n}\n");
        assert_eq!(count_key(&report_keys(&bare_mixed), "javascript:S3516"), 0);

        // Non-literal returns never count as invariant duplicates.
        let identifiers = js("function f(n, m) {\n  if (n) { return m; }\n  return m;\n}\n");
        assert_eq!(count_key(&report_keys(&identifiers), "javascript:S3516"), 0);
    }
}
