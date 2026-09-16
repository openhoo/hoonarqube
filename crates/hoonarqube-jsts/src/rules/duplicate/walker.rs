// Family walker for 'duplicate' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::is_literal_expression;
use crate::support::{IssueSink, LineIndex, RuleScope};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BinaryOperator, Expression, FunctionBody, IfStatement, ReturnStatement, Statement,
    SwitchStatement,
};
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::Visit;
use oxc_span::{ContentEq, GetSpan, Span};
use std::collections::{BTreeSet, HashMap};

fn check_duplicate_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = DuplicateCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        if_statements: Vec::new(),
        function_bodies: Vec::new(),
        s4144_parents: Vec::new(),
        return_groups: Vec::new(),
        return_group_anchors: Vec::new(),
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
struct DuplicateCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    if_statements: Vec<&'a IfStatement<'a>>,
    function_bodies: Vec<&'a FunctionBody<'a>>,
    /// Ancestor chain for `S4144` collection: a body participates only when
    /// a collectable shape (function declaration, declarator- or
    /// method-owned function/arrow) encloses it, mirroring the reference
    /// selector set.
    s4144_parents: Vec<bool>,
    return_groups: Vec<Vec<&'a ReturnStatement<'a>>>,
    return_group_anchors: Vec<Option<Span>>,
    current_return_group: Option<usize>,
    group_stack: Vec<Option<usize>>,
}

impl<'a> Visit<'a> for DuplicateCollector<'a, '_> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        match kind {
            AstKind::IfStatement(statement) => self.if_statements.push(statement),
            AstKind::BinaryExpression(expression) => {
                if expression.left.content_eq(&expression.right)
                    && has_relevant_operator(expression)
                    && !is_one_onto_one_shifting(expression)
                {
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
                        "This conditional operation returns the same value whether the condition is \"true\" or \"false\".",
                        expression.span,
                    );
                }
            }
            AstKind::SwitchStatement(statement) => self.check_switch_cases(statement),
            AstKind::VariableDeclarator(declarator) => {
                self.s4144_parents
                    .push(declarator.init.as_ref().is_some_and(|init| {
                        matches!(
                            init,
                            Expression::FunctionExpression(_)
                                | Expression::ArrowFunctionExpression(_)
                        )
                    }));
            }
            AstKind::MethodDefinition(method) => self.s4144_parents.push(
                matches!(
                    method.value.r#type,
                    oxc_ast::ast::FunctionType::FunctionExpression
                ) && method.value.body.is_some(),
            ),
            AstKind::Function(function) => self.s4144_parents.push(
                function.body.is_some()
                    && matches!(
                        function.r#type,
                        oxc_ast::ast::FunctionType::FunctionDeclaration
                    ),
            ),
            AstKind::ArrowFunctionExpression(_) => self.s4144_parents.push(false),
            AstKind::FunctionBody(body) => {
                let group = self.return_groups.len();
                self.return_groups.push(Vec::new());
                self.return_group_anchors
                    .push(function_name_before(self.source, body.span.start));
                // `S4144` collects only reference-shaped functions:
                // declarations plus declarator/method function values.
                if self.s4144_parents.iter().any(|&collectable| collectable) {
                    self.function_bodies.push(body);
                }
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
        if matches!(
            kind,
            AstKind::VariableDeclarator(_)
                | AstKind::MethodDefinition(_)
                | AstKind::Function(_)
                | AstKind::ArrowFunctionExpression(_)
        ) {
            self.s4144_parents.pop();
        }
    }
}

/// The reference `isOneOntoOneShifting` exemption: `1 << 1`-style bit-flag
/// definitions (a `<<` whose left operand is the literal `1`/`1n`) are an
/// idiom, not a defect.
fn is_one_onto_one_shifting(expression: &oxc_ast::ast::BinaryExpression<'_>) -> bool {
    use oxc_ast::ast::BinaryOperator;
    if expression.operator != BinaryOperator::ShiftLeft {
        return false;
    }
    match &expression.left {
        // `1.0` is exactly representable; the reference compares `value === 1`.
        Expression::NumericLiteral(literal) => literal.value.to_bits() == 1.0f64.to_bits(),
        Expression::BigIntLiteral(literal) => literal.value.as_str() == "1",
        _ => false,
    }
}

/// The reference `hasRelevantOperator` gate: `&&`, `||`, `/`, `-`, `<<`,
/// `>>`, `<`, `<=`, `>`, `>=` always count; the equality operators `==`,
/// `===`, `!=`, `!==` count only when the operands are not both plain
/// identifiers (identifier self-comparisons are a deliberate idiom).
fn has_relevant_operator(expression: &oxc_ast::ast::BinaryExpression<'_>) -> bool {
    use BinaryOperator::*;
    match expression.operator {
        Division | Subtraction | ShiftLeft | ShiftRight | LessThan | LessEqualThan
        | GreaterThan | GreaterEqualThan => true,
        Equality | StrictEquality | Inequality | StrictInequality => {
            !has_identifier_operands(expression)
        }
        _ => false,
    }
}

/// Both operands are plain identifiers — the reference's
/// `hasIdentifierOperands` exemption for equality self-checks.
fn has_identifier_operands(expression: &oxc_ast::ast::BinaryExpression<'_>) -> bool {
    matches!(expression.left, Expression::Identifier(_))
        && matches!(expression.right, Expression::Identifier(_))
}

impl<'a> DuplicateCollector<'a, '_> {
    fn check_switch_cases(&mut self, it: &SwitchStatement<'a>) {
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
                "This conditional operation returns the same value whether the condition is \"true\" or \"false\".",
                it.span,
            );
        }
    }

    /// Resolves the deferred if-chain rules once every `IfStatement` has
    /// been collected; chains are processed from their heads only so no
    /// link is reported twice.
    fn check_if_chains(&mut self) {
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
    fn check_single_chain(&mut self, head: &'a IfStatement<'a>) {
        // Branch bodies in source order: each chain link's consequent, then
        // the final else when present. Flattening across nested links is
        // what lets `S1871` compare an `else if` consequent with the head
        // branch instead of only a link with its own alternate.
        let mut tests: Vec<&Expression<'a>> = vec![&head.test];
        let mut branches: Vec<&Statement<'a>> = vec![&head.consequent];
        let mut current = head;
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
        // `S1871`: the second branch of every maximal run of identical
        // consecutive branches, so a fully identical chain still reports
        // once while separate duplicate runs each report one.
        let mut previous_identical = false;
        for pair in branches.windows(2) {
            let identical = pair[0].content_eq(pair[1]);
            if identical && !previous_identical {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1871",
                    "This branch's code is identical to the previous branch's.",
                    pair[1].span(),
                );
            }
            previous_identical = identical;
        }
        // `S1862`: repeated conditions within the same chain.
        for (position, test) in tests.iter().enumerate().skip(1) {
            if let Some(earlier) = tests[..position]
                .iter()
                .find(|earlier| test.content_eq(*earlier))
            {
                let line = self.sink.index.pos(earlier.span().start).line;
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1862",
                    &format!("This branch duplicates the one on line {line}"),
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
                "This conditional operation returns the same value whether the condition is \"true\" or \"false\".",
                head.span,
            );
        }
    }

    /// `S4144`: function bodies identical to an earlier body in the same
    /// file. Bodies spanning fewer than three content lines are exempt —
    /// the reference rule's `minLines` default — which keeps idiomatic
    /// short callbacks and accessors out of the report.
    fn check_similar_functions(&mut self) {
        let bodies = std::mem::take(&mut self.function_bodies);
        let candidates: Vec<&FunctionBody> = bodies
            .iter()
            .filter(|body| self.body_content_lines(body) >= 3)
            .copied()
            .collect();
        // Bucket by statement count: `ContentEq`-equal bodies always share
        // it, so comparing only same-bucket earlier entries preserves the
        // exact result set while collapsing the quadratic scan on files
        // with many small functions. Bucket indices stay ascending, so the
        // positional order of comparisons is unchanged.
        let mut buckets: HashMap<usize, Vec<usize>> = HashMap::new();
        for (index, body) in candidates.iter().enumerate() {
            buckets
                .entry(body.statements.len())
                .or_default()
                .push(index);
        }
        for (position, body) in candidates.iter().enumerate() {
            let matches_earlier = buckets[&body.statements.len()]
                .iter()
                .copied()
                .take_while(|&earlier| earlier < position)
                .any(|earlier| candidates[earlier].content_eq(body));
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
    fn check_invariant_returns(&mut self) {
        let groups = std::mem::take(&mut self.return_groups);
        let anchors = std::mem::take(&mut self.return_group_anchors);
        for (returns, anchor) in groups.into_iter().zip(anchors) {
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
                    "Refactor this function to not always return the same value.",
                    anchor.unwrap_or_else(|| second.span()),
                );
            }
        }
    }

    /// Content lines of a body (first statement start to last statement
    /// end, inclusive), mirroring the reference rule's brace-excluded
    /// token span (`S4144` threshold).
    fn body_content_lines(&self, body: &FunctionBody<'_>) -> usize {
        let Some(first) = body.statements.first() else {
            return 0;
        };
        let Some(last) = body.statements.last() else {
            return 0;
        };
        let first_line = self.sink.index.pos(first.span().start).line;
        let last_line = self.sink.index.pos(last.span().end).line;
        (last_line - first_line + 1) as usize
    }
}

fn function_name_before(source: &str, body_start: u32) -> Option<Span> {
    let prefix = source.get(..body_start as usize)?;
    let keyword = prefix.rfind("function ")?;
    let mut start = keyword + "function ".len();
    while prefix
        .as_bytes()
        .get(start)
        .is_some_and(u8::is_ascii_whitespace)
    {
        start += 1;
    }
    let mut end = start;
    while prefix
        .as_bytes()
        .get(end)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'$')
    {
        end += 1;
    }
    (end > start).then(|| {
        Span::new(
            u32::try_from(start).unwrap_or_default(),
            u32::try_from(end).unwrap_or_default(),
        )
    })
}

/// Elementwise span-free equality of two statement lists.
fn statements_equal(left: &[Statement<'_>], right: &[Statement<'_>]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left_item, right_item)| left_item.content_eq(right_item))
}

fn is_empty_block(statement: &Statement<'_>) -> bool {
    matches!(statement, Statement::BlockStatement(block) if block.body.is_empty())
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_duplicate_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn identical_binary_operands_flagged() {
        // `a === a` is an identifier self-check (silent per the reference's
        // `hasIdentifierOperands`); `b + c === b + c` flags because the
        // operands are not plain identifiers.
        let report =
            js("if (a === a) {}\nif (b + c === b + c) {}\nif (x == y) {}\nlet t = p && p;\n");
        assert_eq!(count_key(&report_keys(&report), "javascript:S1764"), 1);
        let first: Vec<_> = report
            .issues
            .iter()
            .filter(|found| found.rule_key == "javascript:S1764")
            .collect();
        assert_eq!(
            first[0].range,
            hoonarqube_ir::Range {
                start: pos(2, 4),
                end: pos(2, 19),
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
    fn identical_function_bodies_flagged_but_short_ones_exempt() {
        // Issue #379: bodies below three content lines are exempt, so both
        // functions here stay silent even though they are identical.
        let short_pair = js(
            "function alpha() {\n  setup();\n  run();\n}\nfunction beta() {\n  setup();\n  run();\n}\n",
        );
        assert_eq!(count_key(&report_keys(&short_pair), "javascript:S4144"), 0);

        // Three content lines reach the reference threshold and flag the
        // later duplicate once.
        let source = "\
function alpha() {
  setup();
  run();
  verify();
}
function beta() {
  setup();
  run();
  verify();
}
function gamma() {
  setup();
  stop();
}
";
        let report = js(source);
        assert_eq!(count_key(&report_keys(&report), "javascript:S4144"), 1);

        let trivial = js("function d1() { x(); }\nfunction d2() { x(); }\n");
        assert_eq!(count_key(&report_keys(&trivial), "javascript:S4144"), 0);
    }

    #[test]
    fn s4144_collects_only_reference_shaped_functions() {
        // Identical call-argument callbacks are not collected by the
        // reference selector set and stay silent.
        let listeners = js(
            "el.addEventListener('x', function () {\n  a();\n  b();\n  c();\n});\nel.addEventListener('y', function () {\n  a();\n  b();\n  c();\n});\n",
        );
        assert_eq!(count_key(&report_keys(&listeners), "javascript:S4144"), 0);

        // Method-owned function values are collected and flagged.
        let methods = js(
            "class C {\n  one() {\n    a();\n    b();\n    c();\n  }\n  two() {\n    a();\n    b();\n    c();\n  }\n}\n",
        );
        assert_eq!(count_key(&report_keys(&methods), "javascript:S4144"), 1);

        // Declarator-owned arrows are collected and flagged.
        let arrows = js(
            "const one = () => {\n  a();\n  b();\n  c();\n};\nconst two = () => {\n  a();\n  b();\n  c();\n};\n",
        );
        assert_eq!(count_key(&report_keys(&arrows), "javascript:S4144"), 1);
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
    #[test]
    fn s1764_distinct_operands_stay_clean_and_nesting_still_flags() {
        let distinct = js_keys("if (a === b) {}\nlet sum = c + d;\n");
        assert_eq!(count_key(&distinct, "javascript:S1764"), 0);

        // Identifier-vs-identifier equality self-checks are a deliberate
        // idiom in the reference (`hasIdentifierOperands`) and stay silent;
        // member-expression self-checks still flag.
        let nested = js_keys("function g() {\n  if (p.text === p.text) {\n    mark();\n  }\n}\n");
        assert_eq!(count_key(&nested, "javascript:S1764"), 1);
    }

    #[test]
    fn s1764_exempts_one_onto_one_shift_bit_flag_idiom() {
        // Regression of #539: the reference `isOneOntoOneShifting` exempts
        // `1 << 1`-style bit-flag definitions; member-expression
        // self-inequality checks like `field.type !== field.type` stay
        // flagged (the reference reports them).
        let idioms = js_keys(
            "const Flags = {\n  None: 0,\n  Instantiated: 1 << 0,\n  SyntheticProperty: 1 << 1,\n  SyntheticMethod: 1 << 2,\n};\nconst big = 1n << 1n;\n",
        );
        assert_eq!(count_key(&idioms, "javascript:S1764"), 0);

        let flagged = js_keys(
            "if (field.type !== field.type) { throw new Error('cache mismatch'); }\nif (a - a) {}\n",
        );
        assert_eq!(count_key(&flagged, "javascript:S1764"), 2);

        // Identifier self-comparisons and non-relevant operators stay silent.
        let silent = js_keys("if (a === a) {}\nif (a !== a) {}\nif (a + a) {}\n");
        assert_eq!(count_key(&silent, "javascript:S1764"), 0);
    }

    #[test]
    fn s3923_differing_branch_values_stay_clean() {
        let ternary = js_keys("const r = flag ? 1 : 2;\n");
        assert_eq!(count_key(&ternary, "javascript:S3923"), 0);

        let branches = js_keys(
            "function f(cond) {\n  if (cond) {\n    work();\n  } else {\n    cleanup();\n  }\n}\n",
        );
        assert_eq!(count_key(&branches, "javascript:S3923"), 0);
    }

    #[test]
    fn duplicate_compliant_fixture_emits_none_of_the_family_keys() {
        let source = "\
function one(a) {
  return a + 1;
}

function two(b) {
  return b * 2;
}

function pick(flag) {
  if (flag) {
    return 'yes';
  }
  return 'no';
}

const other = flag ? 'left' : 'right';
switch (side) {
  case 1:
    r();
    break;
  case 2:
    s();
    break;
}
";
        let flagged = js_keys(source);
        for key in ["S1764", "S1862", "S1871", "S3516", "S3923", "S4144"] {
            assert_eq!(
                count_key(&flagged, &format!("javascript:{key}")),
                0,
                "unexpected {key}"
            );
        }
    }
    #[test]
    fn s1871_flags_identical_nested_else_if_chain_branches_with_clean_controls() {
        // Issue #196: the else-if consequent equals the head consequent,
        // but per-link comparison only ever sees a link with its own
        // alternate.
        let nested = ts("declare const value: number;\n\
             function choose(): number {\n\
             if (value === 1) {\n\
             return 2;\n\
             } else if (value === 2) {\n\
             return 2;\n\
             } else {\n\
             return 3;\n\
             }\n\
             }\n\
             export { choose };\n");
        let flagged: Vec<_> = nested
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S1871")
            .collect();
        assert_eq!(flagged.len(), 1);
        // The second branch is reported, identical to the head branch.
        assert_eq!(
            flagged[0].range,
            hoonarqube_ir::Range {
                start: pos(5, 24),
                end: pos(7, 1),
            }
        );

        // The Markdown-it shape: two identical branches, no final else.
        let no_else = ts_keys(
            "declare const nextToken: { type: string; hidden: boolean; nesting: number; tag: string };\n\
             declare const token: { tag: string };\n\
             let needLf = true;\n\
             if (nextToken.type === 'inline' || nextToken.hidden) {\n\
             needLf = false;\n\
             } else if (nextToken.nesting === -1 && nextToken.tag === token.tag) {\n\
             needLf = false;\n\
             }\n",
        );
        assert_eq!(count_key(&no_else, "typescript:S1871"), 1);

        // Genuinely distinct branch bodies across the chain stay clean.
        let distinct = ts_keys(
            "function pick(value: number): number {\n\
             if (value === 1) {\n\
             return 2;\n\
             } else if (value === 2) {\n\
             return 4;\n\
             } else {\n\
             return 6;\n\
             }\n\
             }\n",
        );
        assert_eq!(count_key(&distinct, "typescript:S1871"), 0);
    }
}
