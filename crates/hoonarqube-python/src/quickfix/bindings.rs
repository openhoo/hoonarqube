use crate::engine::scope::{FileFacts, SymbolTable};
use crate::support::{child_bodies, for_each_expr, for_each_stmt, stmt_exprs, to_range, to_u32};
use hoonarqube_ir::{Fix, FixAlternative, Issue, TextEdit};
use ruff_python_ast::{ExceptHandler, Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::{LineIndex, LineRanges, OneIndexed, PositionEncoding, SourceLocation};
use ruff_text_size::{Ranged, TextRange, TextSize};

const S1481_ASSIGNMENT_MESSAGE: &str = "Remove assignment target";
const S1481_RENAME_MESSAGE: &str = "Replace with \"_\"";
const S1481_EXCEPT_MESSAGE: &str = "Remove the unused local variable";
const S1854_MESSAGE: &str = "Remove the unused assignment";
const S6974_REMOVE_MESSAGE: &str = "Remove the statement";
const S6974_RENAME_MESSAGE: &str = "Remove all trailing underscores from the variable name";

/// Detector-time alternatives for python:S1481.  The caller owns the issue's
/// symbol facts and folds these validated alternatives into that issue; this
/// keeps the fix tied to the exact binding which produced the finding.
pub(crate) fn alternatives_s1481(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    table: &SymbolTable,
    issue: &Issue,
) -> Vec<FixAlternative> {
    let issue_span = issue_range(issue, index, source);
    let Some((scope_index, _name)) = binding_for_issue(table, issue_span) else {
        return Vec::new();
    };
    let Some(site) = find_binding_site(parsed.syntax().body.as_slice(), issue_span) else {
        return Vec::new();
    };
    alternatives_s1481_site(site, index, source, table, scope_index, issue_span)
}

fn alternatives_s1481_site(
    site: BindingSite<'_>,
    index: &LineIndex,
    source: &str,
    table: &SymbolTable,
    scope_index: usize,
    issue_span: TextRange,
) -> Vec<FixAlternative> {
    match site {
        BindingSite::Except {
            exception, alias, ..
        } => vec![alternative(
            "s1481-remove-except-alias",
            S1481_EXCEPT_MESSAGE,
            vec![text_edit(
                index,
                source,
                TextRange::new(exception.end(), alias.end()),
                "",
            )],
        )],
        BindingSite::For { target } => {
            alternatives_s1481_for(index, source, table, scope_index, issue_span, target)
        }
        BindingSite::Assignment {
            target,
            value,
            targets,
            annotated,
            target_count,
            target_index,
            ..
        } => alternatives_s1481_assignment(
            index,
            source,
            table,
            scope_index,
            issue_span,
            &AssignmentSite {
                target,
                value,
                targets,
                annotated,
                target_count,
                target_index,
            },
        ),
        BindingSite::Named { value, .. } => vec![alternative(
            "s1481-remove-assignment-target",
            S1481_ASSIGNMENT_MESSAGE,
            vec![text_edit(
                index,
                source,
                TextRange::new(issue_span.start(), value.start()),
                "",
            )],
        )],
    }
}

fn alternatives_s1481_for(
    index: &LineIndex,
    source: &str,
    table: &SymbolTable,
    scope_index: usize,
    issue_span: TextRange,
    target: &Expr,
) -> Vec<FixAlternative> {
    if !underscore_is_available(table, scope_index)
        || (!is_sequence_target(target, issue_span) && target.range() != issue_span)
    {
        return Vec::new();
    }
    rename_to_underscore(index, source, issue_span)
}

struct AssignmentSite<'a> {
    target: &'a Expr,
    value: Option<&'a Expr>,
    targets: &'a [Expr],
    annotated: bool,
    target_count: usize,
    target_index: usize,
}

fn alternatives_s1481_assignment(
    index: &LineIndex,
    source: &str,
    table: &SymbolTable,
    scope_index: usize,
    issue_span: TextRange,
    assignment: &AssignmentSite<'_>,
) -> Vec<FixAlternative> {
    let target = assignment.target;
    let value = assignment.value;
    let targets = assignment.targets;
    let annotated = assignment.annotated;
    let target_count = assignment.target_count;
    let target_index = assignment.target_index;
    if is_sequence_target(target, issue_span) {
        return if underscore_is_available(table, scope_index) {
            rename_to_underscore(index, source, issue_span)
        } else {
            Vec::new()
        };
    }
    if annotated && value.is_none() {
        return Vec::new();
    }
    let Some(value) = value else {
        return Vec::new();
    };
    let edit_range = if target_count > 1 {
        let Some(range) = chained_assignment_edit(source, targets, target, value, target_index)
        else {
            return Vec::new();
        };
        range
    } else {
        TextRange::new(issue_span.start(), value.start())
    };
    vec![alternative(
        "s1481-remove-assignment-target",
        S1481_ASSIGNMENT_MESSAGE,
        vec![text_edit(index, source, edit_range, "")],
    )]
}

/// Detector-time alternatives for python:S1854.  The dead-store detector has
/// already established liveness and symbol identity.  This function adds the
/// pinned quick-fix only when its RHS is call-free and the assignment shape is
/// representable without dropping side effects.
pub(crate) fn alternatives_s1854(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    table: &SymbolTable,
    facts: &FileFacts,
    issue: &Issue,
) -> Vec<FixAlternative> {
    let issue_span = issue_range(issue, index, source);
    let Some((scope_index, name)) = binding_for_issue(table, issue_span) else {
        return Vec::new();
    };
    let Some(site) = find_binding_site(parsed.syntax().body.as_slice(), issue_span) else {
        return Vec::new();
    };
    if name.starts_with('_')
        || facts
            .string_texts
            .iter()
            .any(|text| string_template_mentions(text, name))
    {
        return Vec::new();
    }
    if load_is_in_nested_scope(table, scope_index, name, issue_span) {
        return Vec::new();
    }

    let BindingSite::Assignment {
        stmt,
        value,
        annotated,
        target,
        targets,
        target_count,
        target_index,
    } = site
    else {
        return Vec::new();
    };
    let Some(value) = value else {
        return Vec::new();
    };
    if annotated && is_annotated_without_rhs(stmt) {
        return Vec::new();
    }
    if is_assignment_to_falsy_or_true_literal(value) || expression_has_call(value) {
        return Vec::new();
    }
    if is_sequence_target(target, issue_span) {
        // DeadStoreCheck excludes sequence declarations; retaining this guard
        // prevents a future detector widening from deleting an unpacking side.
        return Vec::new();
    }

    if target_count > 1 {
        let Some(edit_range) =
            chained_assignment_edit(source, targets, target, value, target_index)
        else {
            return Vec::new();
        };
        return vec![alternative(
            "s1854-remove-unused-assignment",
            S1854_MESSAGE,
            vec![text_edit(index, source, edit_range, "")],
        )];
    }

    let Some(edit_range) = remove_statement_range(parsed.syntax().body.as_slice(), stmt, source)
    else {
        return Vec::new();
    };
    vec![alternative(
        "s1854-remove-unused-assignment",
        S1854_MESSAGE,
        vec![text_edit(index, source, edit_range.0, edit_range.1)],
    )]
}

/// Detector-time alternatives for python:S6974.  The local detector proves the
/// `BaseEstimator` context and the `self.<name>_` target; this helper proves that
/// every matching receiver is in the same class before issuing a symbol-wide
/// rename.  The statement-removal alternative is restricted to a single
/// `self` assignment with a `None` RHS, exactly as upstream does.
pub(crate) fn alternatives_s6974(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issue: &Issue,
) -> Vec<FixAlternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(class) = containing_class(parsed.syntax().body.as_slice(), issue_span) else {
        return Vec::new();
    };
    let Some(offending) = find_self_attribute_in_class(class, issue_span) else {
        return Vec::new();
    };
    let name = offending.attr.as_str();
    if name.starts_with("__") || !name.ends_with('_') {
        return Vec::new();
    }

    let mut usages = Vec::new();
    collect_self_attributes(class.body.as_slice(), name, &mut usages);
    if usages.is_empty() || usages.iter().any(|usage| usage.attr.as_str() != name) {
        return Vec::new();
    }
    // A same-spelled self attribute in another class may be a distinct symbol;
    // do not guess across class boundaries.
    let mut outside = false;
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if stmt.range().start() >= class.range().start()
            && stmt.range().end() <= class.range().end()
        {
            return;
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if let Expr::Attribute(attribute) = expr
                    && attribute.attr.as_str() == name
                    && is_self_receiver(attribute)
                {
                    outside = true;
                }
            });
        }
    });
    if outside {
        return Vec::new();
    }

    let mut alternatives = Vec::new();
    if let Some(stmt) = containing_single_self_assignment(class.body.as_slice(), issue_span)
        && statement_assigns_none(stmt)
        && is_single_assignment_target(stmt, issue_span)
        && let Some((range, replacement)) =
            remove_statement_range(parsed.syntax().body.as_slice(), stmt, source)
    {
        alternatives.push(alternative(
            "s6974-remove-statement",
            S6974_REMOVE_MESSAGE,
            vec![text_edit(index, source, range, replacement)],
        ));
    }

    let new_name = name.trim_end_matches('_');
    if new_name.is_empty() {
        return alternatives;
    }
    let edits = usages
        .into_iter()
        .map(|usage| text_edit(index, source, usage.attr.range(), new_name))
        .collect();
    alternatives.push(alternative(
        "s6974-rename-trailing-underscore",
        S6974_RENAME_MESSAGE,
        edits,
    ));
    alternatives
}

/// Returns whether an `except <name>` target is known not to derive from
/// `BaseException`.  A local class with no bases is known to derive from
/// `object` and therefore remains a finding; an unresolved/imported base is
/// conservatively treated as possibly exception-derived and stays clean.
pub(crate) fn should_report_s5708(
    parsed: &Parsed<ModModule>,
    source: &str,
    range: TextRange,
) -> bool {
    let Some(Expr::Name(name)) = find_expr_at(parsed.syntax().body.as_slice(), range) else {
        return false;
    };
    if let Some(class) =
        resolve_local_exception_class(parsed.syntax().body.as_slice(), name.id.as_str(), range)
    {
        return !class_has_known_exception_base(class, source)
            && !class_has_unknown_base(class, source);
    }
    is_known_non_exception_builtin(name.id.as_str())
}

/// Detector-time alternatives for python:S5708.  This returns a candidate only
/// for a local class whose bases are known and do not already derive from
/// `BaseException`; unresolved/imported class types never reach this helper from
/// the detector and remain fix-less if an issue is synthesized directly.
pub(crate) fn alternatives_s5708(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issue: &Issue,
) -> Vec<FixAlternative> {
    let issue_span = issue_range(issue, index, source);
    let Some(Expr::Name(name)) = find_expr_at(parsed.syntax().body.as_slice(), issue_span) else {
        return Vec::new();
    };
    let Some(class) = resolve_local_exception_class(
        parsed.syntax().body.as_slice(),
        name.id.as_str(),
        issue_span,
    ) else {
        return Vec::new();
    };
    if class_has_known_exception_base(class, source)
        || class_has_unknown_base(class, source)
        || class_has_keyword_arguments(class)
    {
        return Vec::new();
    }
    let Some((insert_at, insertion)) = exception_base_insertion(class, source) else {
        return Vec::new();
    };
    vec![alternative(
        "s5708-add-exception-base",
        format!(
            "Make \"{}\" deriving from \"Exception\"",
            class.name.as_str()
        ),
        vec![text_edit(
            index,
            source,
            TextRange::empty(insert_at),
            insertion,
        )],
    )]
}

#[derive(Clone, Copy)]
enum BindingSite<'a> {
    Assignment {
        stmt: &'a Stmt,
        target: &'a Expr,
        targets: &'a [Expr],
        value: Option<&'a Expr>,
        annotated: bool,
        target_count: usize,
        target_index: usize,
    },
    For {
        target: &'a Expr,
    },
    Except {
        exception: &'a Expr,
        alias: TextRange,
    },
    Named {
        value: &'a Expr,
    },
}

fn issue_range(issue: &Issue, index: &LineIndex, source: &str) -> TextRange {
    TextRange::new(
        offset(issue.range.start, index, source),
        offset(issue.range.end, index, source),
    )
}

fn offset(pos: hoonarqube_ir::Pos, index: &LineIndex, source: &str) -> TextSize {
    if pos.line == 0 {
        return TextSize::default();
    }
    index.offset(
        SourceLocation {
            line: OneIndexed::from_zero_indexed(pos.line.saturating_sub(1) as usize),
            character_offset: OneIndexed::from_zero_indexed(pos.column as usize),
        },
        source,
        PositionEncoding::Utf32,
    )
}

fn text_edit(
    index: &LineIndex,
    source: &str,
    range: TextRange,
    replacement: impl Into<String>,
) -> TextEdit {
    TextEdit {
        range: to_range(range, index, source),
        replacement: replacement.into(),
    }
}

fn alternative(id: &str, message: impl Into<String>, edits: Vec<TextEdit>) -> FixAlternative {
    FixAlternative {
        id: id.to_string(),
        fix: Fix {
            message: message.into(),
            edits,
        },
    }
}

fn binding_for_issue(table: &SymbolTable, issue_span: TextRange) -> Option<(usize, &str)> {
    table
        .scopes
        .iter()
        .enumerate()
        .find_map(|(scope_index, scope)| {
            scope.bindings.iter().find_map(|(name, bindings)| {
                bindings
                    .iter()
                    .find(|binding| binding.range == issue_span)
                    .map(|_| (scope_index, name.as_str()))
            })
        })
}

fn underscore_is_available(table: &SymbolTable, scope_index: usize) -> bool {
    !table.scopes[scope_index].bindings.contains_key("_")
}

fn rename_to_underscore(index: &LineIndex, source: &str, range: TextRange) -> Vec<FixAlternative> {
    vec![alternative(
        "s1481-rename-to-underscore",
        S1481_RENAME_MESSAGE,
        vec![text_edit(index, source, range, "_")],
    )]
}

fn find_binding_site(body: &[Stmt], range: TextRange) -> Option<BindingSite<'_>> {
    body.iter()
        .find_map(|statement| find_binding_site_in_statement(statement, range))
}

fn find_binding_site_in_statement(statement: &Stmt, range: TextRange) -> Option<BindingSite<'_>> {
    if let Some(site) = binding_site_for_statement(statement, range) {
        return Some(site);
    }
    if let Some(site) = named_binding_site(statement, range) {
        return Some(site);
    }
    child_bodies(statement)
        .into_iter()
        .find_map(|child| find_binding_site(child, range))
}

fn binding_site_for_statement(statement: &Stmt, range: TextRange) -> Option<BindingSite<'_>> {
    match statement {
        Stmt::Assign(assign) => assignment_binding_site(statement, assign, range),
        Stmt::AnnAssign(assign) => annotated_binding_site(statement, assign, range),
        Stmt::For(for_stmt) => for_binding_site(for_stmt, range),
        Stmt::Try(try_stmt) => except_binding_site(try_stmt, range),
        _ => None,
    }
}

fn assignment_binding_site<'a>(
    statement: &'a Stmt,
    assign: &'a ruff_python_ast::StmtAssign,
    range: TextRange,
) -> Option<BindingSite<'a>> {
    assign
        .targets
        .iter()
        .enumerate()
        .find_map(|(target_index, target)| {
            find_expr_with_range(target, range)
                .is_some()
                .then_some(BindingSite::Assignment {
                    stmt: statement,
                    target,
                    targets: assign.targets.as_slice(),
                    value: Some(assign.value.as_ref()),
                    annotated: false,
                    target_count: assign.targets.len(),
                    target_index,
                })
        })
}

fn annotated_binding_site<'a>(
    statement: &'a Stmt,
    assign: &'a ruff_python_ast::StmtAnnAssign,
    range: TextRange,
) -> Option<BindingSite<'a>> {
    find_expr_with_range(assign.target.as_ref(), range)
        .is_some()
        .then_some(BindingSite::Assignment {
            stmt: statement,
            target: assign.target.as_ref(),
            targets: &[],
            value: assign.value.as_deref(),
            annotated: true,
            target_count: 1,
            target_index: 0,
        })
}

fn for_binding_site(
    for_stmt: &ruff_python_ast::StmtFor,
    range: TextRange,
) -> Option<BindingSite<'_>> {
    find_expr_with_range(&for_stmt.target, range)
        .is_some()
        .then_some(BindingSite::For {
            target: &for_stmt.target,
        })
}

fn except_binding_site(
    try_stmt: &ruff_python_ast::StmtTry,
    range: TextRange,
) -> Option<BindingSite<'_>> {
    for handler in &try_stmt.handlers {
        let ExceptHandler::ExceptHandler(handler) = handler;
        if let Some(alias) = &handler.name
            && alias.range() == range
            && let Some(exception) = handler.type_.as_deref()
        {
            return Some(BindingSite::Except {
                exception,
                alias: alias.range(),
            });
        }
    }
    None
}

fn named_binding_site(statement: &Stmt, range: TextRange) -> Option<BindingSite<'_>> {
    for expr in stmt_exprs(statement) {
        let mut named = None;
        for_each_expr(expr, &mut |expr| {
            if named.is_none()
                && let Expr::Named(assignment) = expr
                && assignment.target.range() == range
            {
                named = Some(BindingSite::Named {
                    value: assignment.value.as_ref(),
                });
            }
        });
        if named.is_some() {
            return named;
        }
    }
    None
}

fn find_expr_with_range(root: &Expr, range: TextRange) -> Option<&Expr> {
    let mut found = None;
    for_each_expr(root, &mut |expr| {
        if found.is_none() && expr.range() == range {
            found = Some(expr);
        }
    });
    found
}

fn is_sequence_target(target: &Expr, binding_range: TextRange) -> bool {
    let mut sequence = false;
    for_each_expr(target, &mut |expr| {
        if let Expr::Tuple(tuple) = expr
            && tuple.elts.len() > 1
            && find_expr_with_range(expr, binding_range).is_some()
        {
            sequence = true;
        }
        if let Expr::List(list) = expr
            && list.elts.len() > 1
            && find_expr_with_range(expr, binding_range).is_some()
        {
            sequence = true;
        }
    });
    sequence
}

fn expression_has_call(expr: &Expr) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |expr| found |= matches!(expr, Expr::Call(_)));
    found
}

fn is_annotated_without_rhs(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::AnnAssign(assign) if assign.value.is_none())
}

fn is_assignment_to_falsy_or_true_literal(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_) | Expr::BooleanLiteral(_) => true,
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => {
                value.as_i64().is_some_and(|value| value == 0 || value == 1)
            }
            ruff_python_ast::Number::Float(value) => {
                value
                    .partial_cmp(&0.0)
                    .is_some_and(std::cmp::Ordering::is_eq)
                    || value
                        .partial_cmp(&1.0)
                        .is_some_and(std::cmp::Ordering::is_eq)
            }
            ruff_python_ast::Number::Complex { .. } => false,
        },
        Expr::UnaryOp(unary) if unary.op == ruff_python_ast::UnaryOp::USub => {
            matches!(
                unary.operand.as_ref(),
                Expr::NumberLiteral(number)
                    if matches!(&number.value, ruff_python_ast::Number::Int(value) if value.as_i64() == Some(1))
            )
        }
        Expr::StringLiteral(string) => string.value.is_empty(),
        Expr::List(list) => list.elts.is_empty(),
        Expr::Tuple(tuple) => tuple.elts.is_empty(),
        Expr::Set(set) => set.elts.is_empty(),
        Expr::Dict(dict) => dict.items.is_empty(),
        _ => false,
    }
}

fn string_template_mentions(text: &str, name: &str) -> bool {
    let marker = format!("@{name}");
    text.split_once(&marker).is_some_and(|(_, tail)| {
        tail.is_empty() || tail.chars().next().is_some_and(char::is_whitespace)
    })
}

fn load_is_in_nested_scope(
    table: &SymbolTable,
    scope_index: usize,
    name: &str,
    binding_range: TextRange,
) -> bool {
    table.resolved_loads.iter().any(|load| {
        load.name == name
            && load.target == Some(scope_index)
            && load.scope != scope_index
            && load.range.start() > binding_range.end()
    })
}

fn chained_assignment_edit(
    _source: &str,
    targets: &[Expr],
    target: &Expr,
    value: &Expr,
    target_index: usize,
) -> Option<TextRange> {
    if target_index == 0 {
        let next_target = targets.get(1)?;
        Some(TextRange::new(targets[0].start(), next_target.start()))
    } else {
        Some(TextRange::new(target.start(), value.start()))
    }
}

fn remove_statement_range(
    body: &[Stmt],
    statement: &Stmt,
    source: &str,
) -> Option<(TextRange, String)> {
    let (siblings, index) = find_statement_siblings(body, statement)?;
    let previous = index.checked_sub(1).and_then(|i| siblings.get(i));
    let next = siblings.get(index + 1);
    let stmt_start = statement.start().to_usize();
    let line_start = source.line_start(statement.start()).to_usize();
    let statement_end = statement.end().to_usize();
    let line_end = source.line_end(statement.start()).to_usize();
    let full_line_end = source.full_line_end(statement.start()).to_usize();
    let same_line = source.line_start(statement.start()) == source.line_start(statement.end());
    let removal_end = if same_line {
        let inline_tail = &source[statement_end..line_end];
        if inline_tail.trim().is_empty() {
            full_line_end
        } else {
            statement_end
        }
    } else {
        statement_end
    };
    let previous_same_line = previous.is_some_and(|previous| {
        source.line_start(previous.start()) == source.line_start(statement.start())
    });
    let next_same_line = next.is_some_and(|next| {
        source.line_start(next.start()) == source.line_start(statement.start())
    });

    if previous.is_none() && next.is_none() {
        return Some((statement.range(), "pass".to_string()));
    }
    if next_same_line {
        return Some((
            TextRange::new(statement.start(), next?.start()),
            String::new(),
        ));
    }
    if previous_same_line {
        let previous = previous?;
        let mut start = previous.end().to_usize();
        if let Some(separator) = source[start..stmt_start].rfind(';') {
            start += separator;
        }
        return Some((
            TextRange::new(TextSize::from(to_u32(start)), statement.end()),
            String::new(),
        ));
    }
    Some((
        TextRange::new(
            TextSize::from(to_u32(line_start)),
            TextSize::from(to_u32(removal_end)),
        ),
        String::new(),
    ))
}

fn find_statement_siblings<'a>(body: &'a [Stmt], target: &Stmt) -> Option<(&'a [Stmt], usize)> {
    if let Some(index) = body.iter().position(|stmt| std::ptr::eq(stmt, target)) {
        return Some((body, index));
    }
    for statement in body {
        for child in child_bodies(statement) {
            if let Some(found) = find_statement_siblings(child, target) {
                return Some(found);
            }
        }
    }
    None
}

fn containing_class(body: &[Stmt], range: TextRange) -> Option<&ruff_python_ast::StmtClassDef> {
    let mut candidate = None;
    for_each_stmt(body, &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt
            && class.range().start() <= range.start()
            && range.end() <= class.range().end()
            && candidate.is_none_or(|old: &ruff_python_ast::StmtClassDef| {
                class.range().len() < old.range().len()
            })
        {
            candidate = Some(class);
        }
    });
    candidate
}

fn find_self_attribute_in_class(
    class: &ruff_python_ast::StmtClassDef,
    range: TextRange,
) -> Option<&ruff_python_ast::ExprAttribute> {
    let mut found = None;
    collect_class_attributes(class.body.as_slice(), &mut |attribute| {
        if found.is_none() && attribute.range() == range && is_self_receiver(attribute) {
            found = Some(attribute);
        }
    });
    found
}

fn collect_self_attributes<'a>(
    body: &'a [Stmt],
    name: &str,
    out: &mut Vec<&'a ruff_python_ast::ExprAttribute>,
) {
    collect_class_attributes(body, &mut |attribute| {
        if attribute.attr.as_str() == name && is_self_receiver(attribute) {
            out.push(attribute);
        }
    });
}

fn collect_class_attributes<'a>(
    body: &'a [Stmt],
    visit: &mut impl FnMut(&'a ruff_python_ast::ExprAttribute),
) {
    for stmt in body {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if let Expr::Attribute(attribute) = expr
                    && is_self_receiver(attribute)
                {
                    visit(attribute);
                }
            });
        }
        if matches!(stmt, Stmt::ClassDef(_)) {
            continue;
        }
        for child in child_bodies(stmt) {
            collect_class_attributes(child, visit);
        }
    }
}

fn is_self_receiver(attribute: &ruff_python_ast::ExprAttribute) -> bool {
    matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
}

fn containing_single_self_assignment(body: &[Stmt], range: TextRange) -> Option<&Stmt> {
    let mut result = None;
    for_each_stmt(body, &mut |stmt| {
        if result.is_some() {
            return;
        }
        match stmt {
            Stmt::Assign(assign)
                if assign.targets.len() == 1
                    && assign.targets[0].range() == range
                    && matches!(
                        &assign.targets[0],
                        Expr::Attribute(attribute) if is_self_receiver(attribute)
                    ) =>
            {
                result = Some(stmt);
            }
            _ => {}
        }
    });
    result
}

fn statement_assigns_none(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Assign(assign) if matches!(assign.value.as_ref(), Expr::NoneLiteral(_)))
}

fn is_single_assignment_target(stmt: &Stmt, range: TextRange) -> bool {
    matches!(stmt, Stmt::Assign(assign) if assign.targets.len() == 1 && assign.targets[0].range() == range)
}

fn find_expr_at(body: &[Stmt], range: TextRange) -> Option<&Expr> {
    let mut found = None;
    for_each_stmt(body, &mut |stmt| {
        if found.is_some() {
            return;
        }
        if let Stmt::Try(try_stmt) = stmt {
            for handler in &try_stmt.handlers {
                let ExceptHandler::ExceptHandler(handler) = handler;
                if handler
                    .type_
                    .as_deref()
                    .is_some_and(|expr| expr.range() == range)
                {
                    found = handler.type_.as_deref();
                    return;
                }
            }
        }
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if found.is_none() && expr.range() == range {
                    found = Some(expr);
                }
            });
        }
    });
    found
}

fn resolve_local_exception_class<'a>(
    body: &'a [Stmt],
    name: &str,
    range: TextRange,
) -> Option<&'a ruff_python_ast::StmtClassDef> {
    let mut classes = Vec::new();
    collect_visible_classes(body, None, 0, &mut classes);
    let exception_scope = enclosing_function_scope(body, range, None, 0);
    classes
        .into_iter()
        .filter(|(class, function_scope, _depth)| {
            class.name.as_str() == name
                && class.range().start() < range.start()
                && *function_scope == exception_scope
        })
        .max_by_key(|(class, _, _)| class.range().start())
        .map(|(class, _, _)| class)
}

fn collect_visible_classes<'a>(
    body: &'a [Stmt],
    function_scope: Option<TextRange>,
    class_depth: usize,
    classes: &mut Vec<(&'a ruff_python_ast::StmtClassDef, Option<TextRange>, usize)>,
) {
    for stmt in body {
        match stmt {
            Stmt::ClassDef(class) => {
                if class_depth == 0 {
                    classes.push((class, function_scope, class_depth));
                }
                // Class scopes are deliberately not searched through: a
                // method cannot resolve a class-body local by ordinary lexical
                // lookup, and unknown class identity must stay fix-less.
            }
            Stmt::FunctionDef(function) => {
                collect_visible_classes(
                    function.body.as_slice(),
                    Some(function.range()),
                    class_depth,
                    classes,
                );
            }
            _ => {
                for child in child_bodies(stmt) {
                    collect_visible_classes(child, function_scope, class_depth, classes);
                }
            }
        }
    }
}

enum FunctionScopeMatch {
    NotContained,
    Contained(Option<TextRange>),
}

fn enclosing_function_scope(
    body: &[Stmt],
    range: TextRange,
    function_scope: Option<TextRange>,
    class_depth: usize,
) -> Option<TextRange> {
    match search_enclosing_function_scope(body, range, function_scope, class_depth) {
        FunctionScopeMatch::Contained(scope) => scope,
        FunctionScopeMatch::NotContained => function_scope,
    }
}

fn search_enclosing_function_scope(
    body: &[Stmt],
    range: TextRange,
    function_scope: Option<TextRange>,
    class_depth: usize,
) -> FunctionScopeMatch {
    for statement in body {
        match enclosing_function_scope_statement(statement, range, function_scope, class_depth) {
            found @ FunctionScopeMatch::Contained(_) => return found,
            FunctionScopeMatch::NotContained => {}
        }
    }
    FunctionScopeMatch::NotContained
}

fn enclosing_function_scope_statement(
    statement: &Stmt,
    range: TextRange,
    function_scope: Option<TextRange>,
    class_depth: usize,
) -> FunctionScopeMatch {
    if !statement.range().contains_range(range) {
        return FunctionScopeMatch::NotContained;
    }
    match statement {
        Stmt::FunctionDef(function) => FunctionScopeMatch::Contained(Some(function.range())),
        Stmt::ClassDef(_) => {
            if class_depth > 0 {
                FunctionScopeMatch::Contained(function_scope)
            } else {
                FunctionScopeMatch::NotContained
            }
        }
        _ => {
            for child in child_bodies(statement) {
                match search_enclosing_function_scope(child, range, function_scope, class_depth) {
                    FunctionScopeMatch::Contained(scope) => {
                        return FunctionScopeMatch::Contained(scope);
                    }
                    FunctionScopeMatch::NotContained => {}
                }
            }
            FunctionScopeMatch::NotContained
        }
    }
}

fn class_has_known_exception_base(class: &ruff_python_ast::StmtClassDef, source: &str) -> bool {
    class.arguments.as_ref().is_some_and(|arguments| {
        arguments.args.iter().any(|base| {
            let text = source[base.range()].trim();
            matches!(text, "Exception" | "BaseException")
        })
    })
}

fn class_has_unknown_base(class: &ruff_python_ast::StmtClassDef, source: &str) -> bool {
    class.arguments.as_ref().is_some_and(|arguments| {
        arguments.args.iter().any(|base| {
            let text = source[base.range()].trim();
            !matches!(text, "Exception" | "BaseException") && !is_known_non_exception_builtin(text)
        })
    })
}

fn class_has_keyword_arguments(class: &ruff_python_ast::StmtClassDef) -> bool {
    class
        .arguments
        .as_ref()
        .is_some_and(|arguments| !arguments.keywords.is_empty())
}

fn is_known_non_exception_builtin(name: &str) -> bool {
    matches!(
        name,
        "bool"
            | "bytearray"
            | "bytes"
            | "complex"
            | "dict"
            | "enumerate"
            | "filter"
            | "float"
            | "frozenset"
            | "int"
            | "list"
            | "map"
            | "memoryview"
            | "object"
            | "property"
            | "range"
            | "reversed"
            | "set"
            | "slice"
            | "str"
            | "super"
            | "zip"
    )
}

fn exception_base_insertion(
    class: &ruff_python_ast::StmtClassDef,
    source: &str,
) -> Option<(TextSize, String)> {
    let class_start = class.range().start().to_usize();
    let class_end = class.range().end().to_usize().min(source.len());
    let header = &source[class_start..class_end];
    let open_rel = header.find('(');
    let colon_rel = header.find(':');
    if let Some(colon_rel) = colon_rel {
        let name_end = class.name.range().end().to_usize();
        let colon = class_start + colon_rel;
        if name_end < colon && source[name_end..colon].contains('[') {
            // Generic type parameters need the base after `[...]`; inserting
            // after the name would produce invalid Python, so stay fix-less.
            return None;
        }
    }
    match (open_rel, colon_rel) {
        (Some(open_rel), Some(colon_rel)) if open_rel < colon_rel => {
            let open = class_start + open_rel;
            let close = matching_delimiter(source, open, b'(', b')')?;
            let inner = source[open + 1..close].trim();
            if inner.is_empty() {
                Some((TextSize::from(to_u32(open + 1)), "Exception".to_string()))
            } else {
                Some((TextSize::from(to_u32(close)), ", Exception".to_string()))
            }
        }
        _ => Some((class.name.range().end(), "(Exception)".to_string())),
    }
}

fn matching_delimiter(source: &str, open: usize, left: u8, right: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote = None;
    for (relative, &byte) in source.as_bytes()[open..].iter().enumerate() {
        let at = open + relative;
        if consume_quote(&mut quote, byte, at, source) {
            continue;
        }
        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            continue;
        }
        if byte == left {
            depth += 1;
        } else if byte == right {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Some(at);
            }
        }
    }
    None
}

fn consume_quote(quote: &mut Option<u8>, byte: u8, at: usize, source: &str) -> bool {
    let Some(quote_byte) = *quote else {
        return false;
    };
    if byte == quote_byte && (at == 0 || source.as_bytes()[at - 1] != b'\\') {
        *quote = None;
    }
    true
}
