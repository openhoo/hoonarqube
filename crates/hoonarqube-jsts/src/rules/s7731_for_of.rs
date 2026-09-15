// Rule module s7731_for_of (generated).
//
// `javascript:S7731` + `typescript:S7731` — eslint-plugin-unicorn
// `no-for-loop` (v65.0.1, wrapped by SonarJS S7731): a classic `for`
// statement that only indexes one array is reported on the `for` header
// (from the `for` keyword through the closing parenthesis) with
// "Use a `for-of` loop instead of this `for` loop.". The reference
// conditions, all implemented here: the init declares exactly one index
// variable initialized to literal `0`; the test is a strict `<`/`>`
// comparison between that index and `<identifier>.length`; the update is
// `i++`, `i += 1`, or `i = i + 1`/`i = 1 + i`; the body is a block; the
// index is never written inside the body; and every read of the array
// variable inside the body is an element access `array[index]` that is
// not itself an assignment target. Other index uses inside the body
// (for example `array[i].mark = false` or `i` in a call) do not block
// the report — the reference fixer emits `.entries()` for those — and
// neither does the index being read in the test/update. When the array
// binding's initializer is a statically known non-array value (a string,
// number, boolean, null, object, or template literal) the loop stays
// silent, matching the reference's `getStaticValue` bail-out. Loops
// whose array variable is never read as `array[index]` inside the body
// stay silent. No auto-fix is offered (the unicorn fixer rewrites the
// loop, which the analyzer does not reproduce).
//
// SonarJS reports the rule with scope MAIN: test files (the pinned
// server's filename-based classification, shared with the analyzer's
// other rules) stay silent.
//
// The regression tests below are committed first at the pristine campaign
// base and must fail (RED) until the detector lands.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, is_test_file, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    AssignmentOperator, AssignmentTarget, BindingPattern, Expression, ForStatement,
    ForStatementInit, SimpleAssignmentTarget, Statement,
};
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};
use oxc_syntax::symbol::SymbolId;

/// Entry point: `javascript:S7731` + `typescript:S7731` no-for-loop check
/// over the parsed program. Requires the semantic model for reference
/// resolution, so recoverable-parse files stay silent.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    if is_test_file(ctx.path) {
        // Scope MAIN: the pinned server classifies by filename.
        return sink.issues;
    }
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        if let AstKind::ForStatement(for_statement) = node.kind() {
            check_for_statement(&mut sink, semantic, ctx.source, for_statement);
        }
    }
    sink.issues
}

/// The reference report: a convertible `for` loop, anchored on the
/// header from `for` through the closing parenthesis.
fn check_for_statement(
    sink: &mut IssueSink<'_>,
    semantic: &Semantic<'_>,
    source: &str,
    for_statement: &ForStatement<'_>,
) {
    let Some(index_symbol) = index_symbol(for_statement) else {
        return;
    };
    let Some(array_identifier) = array_identifier(semantic, for_statement, index_symbol) else {
        return;
    };
    if !check_update(semantic, for_statement, index_symbol) {
        return;
    }
    let Statement::BlockStatement(body) = &for_statement.body else {
        return;
    };
    if array_is_statically_not_array(semantic, array_identifier) {
        return;
    }
    if index_written_in_body(semantic, index_symbol, body.span()) {
        return;
    }
    let Some(array_symbol) = reference_symbol(semantic, array_identifier) else {
        return;
    };
    if !array_reads_are_only_indexed_elements(semantic, array_symbol, index_symbol, body.span()) {
        return;
    }
    // Header span: `for` keyword through the closing parenthesis (the
    // last non-trivia position before the body's `{`).
    let header_end = header_end_offset(source, body.span().start);
    sink.emit_span(
        RuleScope::Both,
        "S7731",
        "Use a `for-of` loop instead of this `for` loop.",
        Span::new(for_statement.span().start, header_end),
    );
}

/// The index variable's symbol: `for (let i = 0; …)` with exactly one
/// declarator initialized to literal `0`.
fn index_symbol(for_statement: &ForStatement<'_>) -> Option<SymbolId> {
    let init = for_statement.init.as_ref()?;
    let ForStatementInit::VariableDeclaration(declaration) = init else {
        return None;
    };
    if declaration.declarations.len() != 1 {
        return None;
    }
    let declarator = declaration.declarations.first()?;
    if !is_literal_zero(declarator.init.as_ref()?) {
        return None;
    }
    let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
        return None;
    };
    identifier.symbol_id.get()
}

/// The array identifier from `i < array.length` (or `array.length > i`):
/// a strict comparison between the index and a plain
/// `<identifier>.length` member.
fn array_identifier<'a>(
    semantic: &Semantic<'_>,
    for_statement: &'a ForStatement<'a>,
    index_symbol: SymbolId,
) -> Option<&'a oxc_ast::ast::IdentifierReference<'a>> {
    let Expression::BinaryExpression(test) = for_statement.test.as_ref()? else {
        return None;
    };
    let (lesser, greater) = match test.operator {
        oxc_syntax::operator::BinaryOperator::LessThan => (&test.left, &test.right),
        oxc_syntax::operator::BinaryOperator::GreaterThan => (&test.right, &test.left),
        _ => return None,
    };
    let Expression::Identifier(index) = unparenthesized(lesser) else {
        return None;
    };
    let Expression::StaticMemberExpression(member) = unparenthesized(greater) else {
        return None;
    };
    if member.property.name != "length" {
        return None;
    }
    let Expression::Identifier(array) = unparenthesized(&member.object) else {
        return None;
    };
    // The lesser operand must be the declared index variable; comparing
    // symbol ids keeps shadowed names honest.
    if reference_symbol(semantic, index) != Some(index_symbol) {
        return None;
    }
    Some(array)
}

/// `i++`, `i += 1`, `i = i + 1`, or `i = 1 + i` on the index variable.
fn check_update(
    semantic: &Semantic<'_>,
    for_statement: &ForStatement<'_>,
    index_symbol: SymbolId,
) -> bool {
    let Some(update) = &for_statement.update else {
        return false;
    };
    match unparenthesized(update) {
        Expression::UpdateExpression(update) => {
            update.operator == oxc_syntax::operator::UpdateOperator::Increment
                && matches!(
                    &update.argument,
                    SimpleAssignmentTarget::AssignmentTargetIdentifier(identifier)
                        if reference_symbol(semantic, identifier) == Some(index_symbol)
                )
        }
        Expression::AssignmentExpression(assignment) => {
            let AssignmentTarget::AssignmentTargetIdentifier(target) = &assignment.left else {
                return false;
            };
            if reference_symbol(semantic, target) != Some(index_symbol) {
                return false;
            }
            match assignment.operator {
                AssignmentOperator::Addition => is_literal_one(&assignment.right),
                AssignmentOperator::Assign => {
                    let Expression::BinaryExpression(binary) = unparenthesized(&assignment.right)
                    else {
                        return false;
                    };
                    if binary.operator != oxc_syntax::operator::BinaryOperator::Addition {
                        return false;
                    }
                    (is_index(semantic, &binary.left, index_symbol)
                        && is_literal_one(&binary.right))
                        || (is_literal_one(&binary.left)
                            && is_index(semantic, &binary.right, index_symbol))
                }
                _ => false,
            }
        }
        _ => false,
    }
}

fn is_index(semantic: &Semantic<'_>, expression: &Expression<'_>, index_symbol: SymbolId) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::Identifier(identifier)
            if reference_symbol(semantic, identifier) == Some(index_symbol)
    )
}

/// Symbol a resolved identifier reference points at; `None` for
/// unresolved (global) references.
fn reference_symbol(
    semantic: &Semantic<'_>,
    identifier: &oxc_ast::ast::IdentifierReference<'_>,
) -> Option<SymbolId> {
    identifier
        .reference_id
        .get()
        .and_then(|reference_id| semantic.scoping().get_reference(reference_id).symbol_id())
}

fn is_literal_zero(expression: &Expression<'_>) -> bool {
    is_numeric_literal(expression, 0.0)
}

fn is_literal_one(expression: &Expression<'_>) -> bool {
    is_numeric_literal(expression, 1.0)
}

fn is_numeric_literal(expression: &Expression<'_>, expected: f64) -> bool {
    matches!(
        unparenthesized(expression),
        Expression::NumericLiteral(literal) if literal.value == expected
    )
}

/// The reference `getStaticValue` bail-out: when the array binding's
/// initializer is a statically known non-array value, the loop is not a
/// candidate (for example iterating a string's characters).
fn array_is_statically_not_array(
    semantic: &Semantic<'_>,
    array: &oxc_ast::ast::IdentifierReference<'_>,
) -> bool {
    let Some(symbol) = reference_symbol(semantic, array) else {
        return false;
    };
    let mut declarations = semantic.scoping().symbol_declarations(symbol);
    let Some(declaration) = declarations.next() else {
        return false;
    };
    if declarations.next().is_some() {
        return false;
    }
    let AstKind::VariableDeclarator(declarator) = semantic.nodes().get_node(declaration).kind()
    else {
        return false;
    };
    let Some(init) = declarator.init.as_ref() else {
        return false;
    };
    matches!(
        unparenthesized(init),
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::ObjectExpression(_)
            | Expression::TemplateLiteral(_)
    )
}

/// Whether the index variable is written anywhere inside the body span
/// (the reference checks writes scoped to the loop body).
fn index_written_in_body(semantic: &Semantic<'_>, index_symbol: SymbolId, body: Span) -> bool {
    semantic
        .scoping()
        .get_resolved_references(index_symbol)
        .any(|reference| {
            reference.is_write() && {
                let span = semantic.nodes().get_node(reference.node_id()).span();
                span.start >= body.start && span.end <= body.end
            }
        })
}

/// Every read of the array variable inside the body must be an element
/// access `array[index]` that is not itself an assignment target; at
/// least one such read must exist.
fn array_reads_are_only_indexed_elements(
    semantic: &Semantic<'_>,
    array_symbol: SymbolId,
    index_symbol: SymbolId,
    body: Span,
) -> bool {
    let mut reads = 0usize;
    for reference in semantic.scoping().get_resolved_references(array_symbol) {
        let node = semantic.nodes().get_node(reference.node_id());
        let span = node.span();
        if span.start < body.start || span.end > body.end {
            continue;
        }
        reads += 1;
        let parent = semantic.nodes().parent_node(node.id());
        // The member access must be `array[index]`: a computed member
        // whose expression is the index variable, or the quirk `array.i`
        // (non-computed property literally named like the index) the
        // reference also accepts.
        let (member_object, property_is_index) = match parent.kind() {
            AstKind::ComputedMemberExpression(member) => (
                &member.object,
                matches!(
                    unparenthesized(&member.expression),
                    Expression::Identifier(identifier)
                        if reference_symbol(semantic, identifier) == Some(index_symbol)
                ),
            ),
            AstKind::StaticMemberExpression(member) => (
                &member.object,
                semantic.scoping().symbol_name(index_symbol) == member.property.name.as_str(),
            ),
            _ => return false,
        };
        if !matches!(
            unparenthesized(member_object),
            Expression::Identifier(identifier)
                if reference_symbol(semantic, identifier) == Some(array_symbol)
        ) {
            return false;
        }
        if !property_is_index {
            return false;
        }
        // `array[i] = value` writes to the element: the reference exempts
        // member expressions that are the assignment target itself.
        let grandparent = semantic.nodes().parent_node(parent.id());
        if let AstKind::AssignmentExpression(assignment) = grandparent.kind()
            && matches!(
                &assignment.left,
                AssignmentTarget::ComputedMemberExpression(_)
                    | AssignmentTarget::StaticMemberExpression(_)
            )
        {
            return false;
        }
    }
    reads > 0
}

/// Offset of the `)` closing the `for` header: the last non-trivia byte
/// before the body's `{`.
fn header_end_offset(source: &str, body_start: u32) -> u32 {
    crate::support::previous_non_trivia_offset(source, body_start).map_or(body_start, |offset| {
        u32::try_from(offset).unwrap_or(body_start) + 1
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7731_flags_pinned_exceljs_and_express_sites() {
        // Pinned oracle: exceljs@5bed18b lib/doc/defined-names.js:114
        // (`cells[i].mark = false` — element writes still convert) and
        // express@3ce6d0e lib/application.js:324 (`this.param(name[i])`)
        // plus test/support/tmpl.js:30 (`value = value[parts[i]]`).
        let source = "\
var cells = [];
for (let i = 0; i < cells.length; i++) {
  cells[i].mark = false;
}
var name = [];
for (var i = 0; i < name.length; i++) {
  this.param(name[i], fn);
}
var parts = [];
for (var i = 0; i < parts.length; i++) {
  value = value[parts[i]];
}
";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S7731"), 3);
        let issue = js(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S7731")
            .expect("pinned for loop must be reported");
        assert_eq!(
            issue.message,
            "Use a `for-of` loop instead of this `for` loop."
        );
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.start.column, 0);
        assert_eq!(issue.range.end.line, 2);
        assert_eq!(
            issue.range.end.column,
            u32::try_from("for (let i = 0; i < cells.length; i++)".len()).unwrap()
        );
    }

    #[test]
    fn s7731_flags_reverse_comparison_and_update_forms() {
        let source = "\
var a = [], b = [], c = [], d = [];
for (let i = 0; i < a.length; i++) { use(a[i]); }
for (let i = 0; a.length > i; i++) { use(a[i]); }
for (let i = 0; i < b.length; i += 1) { use(b[i]); }
for (let i = 0; i < c.length; i = i + 1) { use(c[i]); }
for (let i = 0; i < d.length; i = 1 + i) { use(d[i]); }
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7731"), 5);
    }

    #[test]
    fn s7731_non_convertible_loops_stay_silent() {
        let source = "\
var a = [];
for (let i = 1; i < a.length; i++) { use(a[i]); }
for (let i = 0; i <= a.length - 1; i++) { use(a[i]); }
for (let i = 0; i < a.length; i += 2) { use(a[i]); }
for (let i = 0; i < a.length; i++) { use(a[i]); i++; }
for (let i = 0; i < a.length; i++) { a[i] = 0; }
for (let i = 0; i < a.length; i++) { use(i); }
for (let i = 0; i < a.length; i++) use(a[i]);
for (let i = 0, j = 0; i < a.length; i++) { use(a[i]); }
for (i = 0; i < a.length; i++) { use(a[i]); }
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7731"), 0);
    }

    #[test]
    fn s7731_static_non_array_stays_silent() {
        let source = "\
const s = 'abc';
for (let i = 0; i < s.length; i++) { use(s[i]); }
const o = { length: 3 };
for (let i = 0; i < o.length; i++) { use(o[i]); }
";
        assert_eq!(count_key(&js_keys(source), "javascript:S7731"), 0);
    }

    #[test]
    fn s7731_reports_in_both_languages() {
        let source = "var a = [];\nfor (let i = 0; i < a.length; i++) { use(a[i]); }\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S7731"), 1);
        assert_eq!(count_key(&ts_keys(source), "typescript:S7731"), 1);
    }

    #[test]
    fn s7731_stays_silent_in_test_files_like_reference_main_scope() {
        let source = "var a = [];\nfor (let i = 0; i < a.length; i++) { use(a[i]); }\n";
        let test_report = crate::analyze(
            PathBuf::from("test/res.append.spec.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&test_report), "javascript:S7731"), 0);
        let main_report = crate::analyze(
            PathBuf::from("test/res.append.js"),
            source,
            crate::JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(count_key(&report_keys(&main_report), "javascript:S7731"), 1);
    }
}
