// Family walker for 'embedded_effects' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, assignment_target_name, property_key_name, unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BinaryOperator, Expression, ExpressionStatement, ForStatement, MethodDefinition,
    MethodDefinitionKind, ObjectProperty, PropertyKind, UnaryOperator, UpdateOperator,
};
use oxc_ast::ast_kind::AstKind;
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_expression, walk_expression_statement, walk_method_definition, walk_object_property,
};
use oxc_span::{GetSpan, Span};
use std::collections::HashSet;

fn check_embedded_effects(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let accessors = collect_accessor_names(program);
    let mut collector = EmbeddedEffectCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        ancestors: Vec::new(),
        accessors,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Property names declared by any `get`/`set` accessor in the file: a
/// member read of such a name may run user code, so `S905` leaves those
/// statements alone.
fn collect_accessor_names(program: &oxc_ast::ast::Program<'_>) -> HashSet<String> {
    struct AccessorNames(HashSet<String>);

    impl<'a> Visit<'a> for AccessorNames {
        fn visit_object_property(&mut self, it: &ObjectProperty<'a>) {
            if it.kind != PropertyKind::Init
                && let Some(name) = property_key_name(&it.key)
            {
                self.0.insert(name.to_string());
            }
            walk_object_property(self, it);
        }

        fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
            if matches!(
                it.kind,
                MethodDefinitionKind::Get | MethodDefinitionKind::Set
            ) && let Some(name) = property_key_name(&it.key)
            {
                self.0.insert(name.to_string());
            }
            walk_method_definition(self, it);
        }
    }

    let mut collector = AccessorNames(HashSet::new());
    collector.visit_program(program);
    collector.0
}

/// `S881` (standalone `++`/`--`), `S1121` (standalone assignments), and
/// `S905` (pointless expression statements) in one traversal.
///
/// Updates and assignments are only tolerated in the positions upstream
/// exempts: as an `ExpressionStatement` root, in `for` header init/update
/// slots, or under the parent shapes `S1121` accepts (assignment chains,
/// relational operands, sequence members, declarator initializers, arrow
/// bodies, logical right sides, and `while`/`do-while` tests). The
/// `ancestors` stack supplies each expression's parent node kind;
/// `ParenthesizedExpression` links are transparent like upstream's AST.
struct EmbeddedEffectCollector<'source, 'index, 'a> {
    sink: IssueSink<'index>,
    source: &'source str,
    /// Innermost-last stack of enclosing `AstKind` nodes, maintained by
    /// `enter_node`/`leave_node`.
    ancestors: Vec<AstKind<'a>>,
    /// Accessor names declared anywhere in this file (`get`/`set`); reads
    /// of these names may invoke user code.
    accessors: HashSet<String>,
}

impl EmbeddedEffectCollector<'_, '_, '_> {
    /// The `back`-th enclosing `AstKind`, skipping `ParenthesizedExpression`
    /// links (upstream's AST has no such node, so parentheses never shield
    /// an expression from its real parent).
    fn ancestor(&self, back: usize) -> Option<AstKind<'_>> {
        self.ancestors
            .iter()
            .rev()
            .filter(|kind| !matches!(kind, AstKind::ParenthesizedExpression(_)))
            .nth(back)
            .copied()
    }

    /// `S881`: whether this `++`/`--` sits in an exempt position — an
    /// `ExpressionStatement` root, a `for` init/update slot, or a member of
    /// the sequence expression forming the `for` update clause.
    fn update_exempt(&self, span: Span) -> bool {
        match self.ancestor(0) {
            Some(AstKind::ExpressionStatement(_)) => true,
            Some(AstKind::ForStatement(for_statement)) => for_header_slot(for_statement, span),
            Some(AstKind::SequenceExpression(sequence)) => matches!(
                self.ancestor(1),
                Some(AstKind::ForStatement(for_statement))
                    if for_statement
                        .update
                        .as_ref()
                        .is_some_and(|update| unparenthesized(update).span() == sequence.span())
            ),
            _ => false,
        }
    }

    /// `S1121`: whether this assignment's parent is one of the exempting
    /// shapes upstream lists (statement root, chain, relation, sequence,
    /// declarator, arrow body, conditional-assignment right side, loop
    /// test, or `for` init/update).
    fn assignment_exempt(&self, span: Span) -> bool {
        match self.ancestor(0) {
            Some(
                AstKind::ExpressionStatement(_)
                | AstKind::AssignmentExpression(_)
                | AstKind::SequenceExpression(_),
            ) => true,
            Some(AstKind::BinaryExpression(binary)) => is_relational_operator(binary.operator),
            Some(AstKind::VariableDeclarator(declarator)) => declarator
                .init
                .as_ref()
                .is_some_and(|init| unparenthesized(init).span() == span),
            Some(AstKind::ArrowFunctionExpression(arrow)) => arrow
                .get_expression()
                .is_some_and(|body| unparenthesized(body).span() == span),
            Some(AstKind::LogicalExpression(logical)) => {
                unparenthesized(&logical.right).span() == span
            }
            Some(AstKind::WhileStatement(while_statement)) => {
                unparenthesized(&while_statement.test).span() == span
            }
            Some(AstKind::DoWhileStatement(do_while)) => {
                unparenthesized(&do_while.test).span() == span
            }
            Some(AstKind::ForStatement(for_statement)) => for_header_slot(for_statement, span),
            _ => false,
        }
    }
}

/// Whether `span` occupies the `for` statement's init or update slot
/// (parentheses around the slot expression are transparent).
fn for_header_slot(for_statement: &ForStatement<'_>, span: Span) -> bool {
    let init = for_statement
        .init
        .as_ref()
        .and_then(|init| init.as_expression());
    [init, for_statement.update.as_ref()]
        .into_iter()
        .flatten()
        .any(|slot| unparenthesized(slot).span() == span)
}

/// The comparison operators upstream treats as an exempting relation
/// parent for `S1121`.
fn is_relational_operator(operator: BinaryOperator) -> bool {
    matches!(
        operator,
        BinaryOperator::Equality
            | BinaryOperator::Inequality
            | BinaryOperator::StrictEquality
            | BinaryOperator::StrictInequality
            | BinaryOperator::LessThan
            | BinaryOperator::LessEqualThan
            | BinaryOperator::GreaterThan
            | BinaryOperator::GreaterEqualThan
    )
}

impl<'a> Visit<'a> for EmbeddedEffectCollector<'_, '_, 'a> {
    fn enter_node(&mut self, kind: AstKind<'a>) {
        self.ancestors.push(kind);
    }

    fn leave_node(&mut self, _kind: AstKind<'a>) {
        self.ancestors.pop();
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        if is_pointless_expression(&it.expression, &self.accessors) {
            self.sink.emit_span(
                RuleScope::Both,
                "S905",
                "Expected an assignment or function call and instead saw an expression.",
                it.span(),
            );
        }
        walk_expression_statement(self, it);
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        match it {
            Expression::UpdateExpression(update) => {
                if !self.update_exempt(update.span()) {
                    let operation = match update.operator {
                        UpdateOperator::Increment => "increment",
                        UpdateOperator::Decrement => "decrement",
                    };
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S881",
                        &format!("Extract this {operation} operation into a dedicated statement."),
                        update.span(),
                    );
                }
            }
            Expression::AssignmentExpression(assign) if !self.assignment_exempt(assign.span()) => {
                let target = assignment_target_name(&assign.left).unwrap_or("value");
                let between_start = assign.left.span().end;
                let between_end = assign.right.span().start;
                let operator_span = self
                    .source
                    .get(between_start as usize..between_end as usize)
                    .and_then(|text| {
                        let start = text.find(|character: char| !character.is_whitespace())?;
                        let operator = text[start..].trim_end();
                        let absolute = between_start + u32::try_from(start).ok()?;
                        Some(oxc_span::Span::new(
                            absolute,
                            absolute + u32::try_from(operator.len()).ok()?,
                        ))
                    })
                    .unwrap_or_else(|| assign.left.span());
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1121",
                    &format!("Extract the assignment of \"{target}\" from this expression."),
                    operator_span,
                );
            }
            _ => {}
        }
        walk_expression(self, it);
    }
}

/// Whether an expression statement provably has no effect: literals,
/// identifiers, templates without substitutions, static member chains over
/// such bases, and pure operators over such operands. Calls, assignments,
/// `delete`, tagged templates, and any unrecognized shape are treated as
/// effectful.
fn is_pointless_expression(expression: &Expression<'_>, accessors: &HashSet<String>) -> bool {
    match expression {
        Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::StringLiteral(_)
        | Expression::Identifier(_)
        | Expression::ThisExpression(_) => true,
        Expression::TemplateLiteral(template) => template.expressions.is_empty(),
        Expression::ParenthesizedExpression(parens) => {
            is_pointless_expression(&parens.expression, accessors)
        }
        Expression::UnaryExpression(unary) => {
            unary.operator != UnaryOperator::Delete
                && is_pointless_expression(&unary.argument, accessors)
        }
        Expression::BinaryExpression(binary) => {
            is_pointless_expression(&binary.left, accessors)
                && is_pointless_expression(&binary.right, accessors)
        }
        Expression::LogicalExpression(logical) => {
            is_pointless_expression(&logical.left, accessors)
                && is_pointless_expression(&logical.right, accessors)
        }
        Expression::SequenceExpression(sequence) => sequence
            .expressions
            .iter()
            .all(|operand| is_pointless_expression(operand, accessors)),
        // A plain property chain (`errorUtil.errToObj`) reads values without
        // running any code of its own.
        Expression::StaticMemberExpression(static_member) => {
            is_pointless_static_member(static_member, accessors)
        }
        _ => false,
    }
}

/// Whether a static member link avoids declared accessors and sits over a
/// pure base. Optional chains, computed or private links, and
/// accessor-named properties stay outside the provably pure family.
fn is_pointless_static_member(
    static_member: &oxc_ast::ast::StaticMemberExpression<'_>,
    accessors: &HashSet<String>,
) -> bool {
    !accessors.contains(static_member.property.name.as_str())
        && is_pointless_expression(&static_member.object, accessors)
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_embedded_effects(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn embedded_updates_and_assignments_require_statement_roots() {
        let source = "\
let i = 0;
i++;
for (i = 0; i < 3; i++) {
  foo(i++);
}
let j = i++;
foo(k = 1);
if (k = 1) {}
m = n = 1;
";
        let report = js(source);
        let embedded: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| {
                matches!(
                    issue.rule_key.as_str(),
                    "javascript:S881" | "javascript:S1121"
                )
            })
            .map(|issue| {
                (
                    issue.rule_key.clone(),
                    (
                        issue.range.start.line,
                        issue.range.start.column,
                        issue.range.end.line,
                        issue.range.end.column,
                    ),
                )
            })
            .collect();
        // Standalone `i++`, the assignments in the `for` header, the
        // statement-root assignment, and the chained `n = 1` (its parent is
        // an assignment) are clean; everything embedded deeper is flagged
        // once per construct.
        let hit = |rule: &str, line: u32, start: u32, end: u32| {
            (rule.to_string(), (line, start, line, end))
        };
        assert_eq!(
            embedded,
            vec![
                hit("javascript:S881", 4, 6, 9),
                hit("javascript:S881", 6, 8, 11),
                hit("javascript:S1121", 7, 6, 7),
                hit("javascript:S1121", 8, 6, 7),
            ]
        );
    }

    #[test]
    fn s905_flags_pointless_expression_statements() {
        assert_eq!(
            count_key(
                &js_keys("foo;\n42;\n1 + 2;\nvoid 0;\n`done`;\n"),
                "javascript:S905"
            ),
            5
        );
    }

    #[test]
    fn s905_allows_effectful_expression_statements() {
        assert_eq!(
            count_key(
                &js_keys("foo();\n`x${y}`;\ndelete obj.p;\nlet q = 1;\ntag`x`;\n"),
                "javascript:S905"
            ),
            0
        );
    }

    #[test]
    fn s905_flags_pure_member_read_statements() {
        // #140: static member chains over a pure base are provably pure
        // reads (pinned Zod shape plus the plain-object control).
        let findings = js_keys("errorUtil.errToObj;\nobj.value;\na.b.c;\n");
        assert_eq!(count_key(&findings, "javascript:S905"), 3);

        let typed = ts_keys("errorUtil.errToObj;\n");
        assert_eq!(count_key(&typed, "typescript:S905"), 1);

        let control =
            js_keys("const obj = { value: 42 };\nobj.value;\nobj;\n42;\nconsole.log(obj.value);\n");
        assert_eq!(count_key(&control, "javascript:S905"), 3);
    }

    #[test]
    fn s905_accessor_like_and_impure_member_reads_stay_clean() {
        // Calls and potentially effectful link shapes stay unreported.
        assert_eq!(count_key(&js_keys("foo.bar();\n"), "javascript:S905"), 0);
        assert_eq!(count_key(&js_keys("a?.b;\n"), "javascript:S905"), 0);
        assert_eq!(count_key(&js_keys("obj[key];\n"), "javascript:S905"), 0);
        assert_eq!(
            count_key(
                &js_keys("class C { #x = 1; read() { this.#x; } }\n"),
                "javascript:S905"
            ),
            0
        );
        assert_eq!(
            count_key(
                &js_keys("class C extends B { read() { super.x; } }\n"),
                "javascript:S905"
            ),
            0
        );

        // A declared accessor of the same name makes the read potentially
        // effectful, so it stays unreported.
        let class_getter =
            js_keys("class C { get value() { return 1; } }\nconst obj = new C();\nobj.value;\n");
        assert_eq!(count_key(&class_getter, "javascript:S905"), 0);

        let object_getter = js_keys("const gate = { get value() { return 1; } };\ngate.value;\n");
        assert_eq!(count_key(&object_getter, "javascript:S905"), 0);

        let setter_in_object = js_keys("const gate = { set value(v) {} };\ngate.value;\n");
        assert_eq!(count_key(&setter_in_object, "javascript:S905"), 0);
    }

    #[test]
    fn s905_reports_pinned_zod_errorutil_member_read() {
        // #140: verbatim colinhacks/zod@46da95720b7293f156ad9c683c14bd8ab9664c2f
        // packages/zod/src/v3/types.ts (MIT). CodeQL and SonarQube
        // 26.8.0.126808 both flag exactly one S905 in this file, the pure
        // member read at line 2575.
        let report = ts(include_str!("../../../fixtures/shapes/zod-types.ts"));
        let sites: Vec<(u32, u32)> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S905")
            .map(|issue| (issue.range.start.line, issue.range.start.column))
            .collect();
        assert_eq!(sites, vec![(2575, 4)]);
    }

    #[test]
    fn s881_flags_updates_inside_sequence_statement_roots() {
        // The sequence expression is the statement root; both updates sit
        // one level deeper and are embedded.
        assert_eq!(count_key(&js_keys("i++, j++;\n"), "javascript:S881"), 2);
    }

    #[test]
    fn s881_and_s1121_exempt_for_update_clause_members() {
        // #499/#500/#501: every member of the `for` update clause —
        // including members of its comma sequence — is a dedicated
        // statement upstream.
        let keys = js_keys(
            "function f(endIndex, startIndex, log2Base) {\n  for (let i = endIndex - 1, bitOffset = 0; i >= startIndex; i--, bitOffset += log2Base) {\n    const segment = bitOffset >>> 4;\n  }\n}\n",
        );
        assert_eq!(count_key(&keys, "javascript:S881"), 0);
        assert_eq!(count_key(&keys, "javascript:S1121"), 0);

        // Updates and assignments nested inside the update clause stay
        // flagged.
        let nested = js_keys("for (let i = 0; i < n; f(i++)) {}\n");
        assert_eq!(count_key(&nested, "javascript:S881"), 1);
        let nested_assign = js_keys("for (let i = 0; i < n; f(j = 2)) {}\n");
        assert_eq!(count_key(&nested_assign, "javascript:S1121"), 1);
    }

    #[test]
    fn s1121_exempts_upstream_parent_shapes() {
        // #501: sequence members, declarator initializers, assignment
        // chains, relational operands, arrow bodies, logical right sides,
        // while/do-while tests, and for init/update slots are all exempt.
        let exempt = js_keys(
            "function f(pos) {\n  return pos += 2, pos;\n}\nconst cache = (m ??= new Map());\nlet a = b = 1;\nif ((c = d) === e) {}\nconst g = () => (h = 1);\ncond && (x = 1);\nwhile ((y = next())) {}\ndo {} while ((z = next()));\nfor (p = 0; p < n; q = p) {}\n",
        );
        assert_eq!(count_key(&exempt, "javascript:S1121"), 0);

        // Genuinely embedded assignments stay flagged.
        let flagged = js_keys("if (x = f()) {}\nfoo(bar = 1);\nlet s = t + (u = 2);\n");
        assert_eq!(count_key(&flagged, "javascript:S1121"), 3);
    }
}
