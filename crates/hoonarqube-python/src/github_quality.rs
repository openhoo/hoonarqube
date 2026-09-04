//! Independently implemented GitHub `CodeQL` Python quality queries.
//!
//! The entrypoint in this module deliberately has a strict parse gate.  `CodeQL`
//! runs on a complete AST; a recovered Ruff tree is not evidence for a finding.

use hoonarqube_ir::Issue;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};
use std::collections::HashMap;

use crate::engine::file_context::FileContext;
use crate::engine::rx::{RxUnit, decode_string_part, for_each_class, parse_regex};
use crate::support::{
    called_name, child_bodies, child_exprs, collect_target_names, for_each_stmt,
    for_each_stmt_in_scope, issue_at, parse, significant_tokens, sort_issues, stmt_exprs,
    stmt_store_names, string_value_text,
};
#[derive(Clone, Debug, PartialEq, Eq)]
enum BindingValue {
    ReModule,
    ReFunction,
    BuiltinsModule,
    FormatFunction,
    Template(String),
    Name(String),
    BuiltinsFormat,
    Unknown,
}

#[derive(Default)]
struct BindingFacts {
    bindings: HashMap<String, Vec<BindingValue>>,
}

impl BindingFacts {
    fn build(parsed: &Parsed<ModModule>) -> Self {
        let mut facts = Self::default();
        for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
            facts.record_statement(stmt);
        });
        for expr in expressions_in_source(parsed) {
            facts.record_named_expression(expr);
        }
        facts
    }

    fn record_statement(&mut self, stmt: &Stmt) {
        match stmt {
            Stmt::Import(import) => self.record_import(import),
            Stmt::ImportFrom(import) if import.level == 0 => self.record_import_from(import),
            Stmt::ImportFrom(_) => {}
            Stmt::FunctionDef(function) => self.record_function(function),
            Stmt::ClassDef(class) => self.bind(class.name.as_str(), BindingValue::Unknown),
            Stmt::Assign(assign) => self.record_assignment(assign),
            Stmt::AnnAssign(assign) => self.record_ann_assignment(assign),
            Stmt::AugAssign(assign) => self.record_aug_assignment(assign),
            _ => {
                for name in stmt_store_names(stmt) {
                    self.bind(&name, BindingValue::Unknown);
                }
            }
        }
    }

    fn record_import(&mut self, import: &ruff_python_ast::StmtImport) {
        for alias in &import.names {
            let local = alias.asname.as_deref().map_or_else(
                || {
                    alias
                        .name
                        .as_str()
                        .split('.')
                        .next()
                        .unwrap_or("")
                        .to_string()
                },
                str::to_string,
            );
            let value = match alias.name.as_str() {
                "re" => BindingValue::ReModule,
                "builtins" => BindingValue::BuiltinsModule,
                _ => BindingValue::Unknown,
            };
            self.bind(&local, value);
        }
    }

    fn record_import_from(&mut self, import: &ruff_python_ast::StmtImportFrom) {
        let module = import
            .module
            .as_ref()
            .map(ruff_python_ast::Identifier::as_str);
        for alias in &import.names {
            let local = alias
                .asname
                .as_deref()
                .map_or_else(|| alias.name.as_str().to_string(), str::to_string);
            let value = match (module, alias.name.as_str()) {
                (
                    Some("re"),
                    "compile" | "search" | "match" | "fullmatch" | "split" | "findall" | "finditer"
                    | "sub" | "subn",
                ) => BindingValue::ReFunction,
                (Some("builtins"), "format") => BindingValue::FormatFunction,
                _ => BindingValue::Unknown,
            };
            self.bind(&local, value);
        }
    }

    fn record_function(&mut self, function: &ruff_python_ast::StmtFunctionDef) {
        self.bind(function.name.as_str(), BindingValue::Unknown);
        for parameter in &function.parameters {
            self.bind(parameter.name().as_str(), BindingValue::Unknown);
        }
    }

    fn record_assignment(&mut self, assign: &ruff_python_ast::StmtAssign) {
        let value = binding_value(&assign.value);
        for target in &assign.targets {
            if let Expr::Name(name) = target {
                self.bind(name.id.as_str(), value.clone());
            } else {
                let mut names = Vec::new();
                collect_target_names(target, &mut names);
                for name in names {
                    self.bind(&name, BindingValue::Unknown);
                }
            }
        }
    }

    fn record_ann_assignment(&mut self, assign: &ruff_python_ast::StmtAnnAssign) {
        let value = assign
            .value
            .as_deref()
            .map_or(BindingValue::Unknown, binding_value);
        let mut names = Vec::new();
        collect_target_names(&assign.target, &mut names);
        for name in names {
            self.bind(&name, value.clone());
        }
    }

    fn record_aug_assignment(&mut self, assign: &ruff_python_ast::StmtAugAssign) {
        let mut names = Vec::new();
        collect_target_names(&assign.target, &mut names);
        for name in names {
            self.bind(&name, BindingValue::Unknown);
        }
    }

    fn record_named_expression(&mut self, expr: &Expr) {
        if let Expr::Named(named) = expr {
            let mut names = Vec::new();
            collect_target_names(&named.target, &mut names);
            for name in names {
                self.bind(&name, BindingValue::Unknown);
            }
        }
    }

    fn bind(&mut self, name: &str, value: BindingValue) {
        self.bindings
            .entry(name.to_string())
            .or_default()
            .push(value);
    }

    fn resolve(&self, name: &str) -> Option<BindingValue> {
        self.resolve_inner(name, &mut Vec::new())
    }

    fn resolve_inner(&self, name: &str, visiting: &mut Vec<String>) -> Option<BindingValue> {
        if name == "format" && !self.bindings.contains_key(name) {
            return Some(BindingValue::FormatFunction);
        }
        if visiting.iter().any(|seen| seen == name) {
            return None;
        }
        let values = self.bindings.get(name)?;
        visiting.push(name.to_string());
        let mut resolved = None;
        for value in values {
            let current = match value {
                BindingValue::Name(other) => self.resolve_inner(other, visiting),
                BindingValue::BuiltinsFormat => {
                    if self.bindings.get("builtins").is_none_or(|_| {
                        self.resolve_inner("builtins", visiting)
                            == Some(BindingValue::BuiltinsModule)
                    }) {
                        Some(BindingValue::FormatFunction)
                    } else {
                        None
                    }
                }
                concrete => Some(concrete.clone()),
            };
            if current.is_none()
                || resolved
                    .as_ref()
                    .is_some_and(|old| old != current.as_ref().unwrap())
            {
                visiting.pop();
                return None;
            }
            resolved = current;
        }
        visiting.pop();
        resolved
    }
}

fn binding_value(expr: &Expr) -> BindingValue {
    match expr {
        Expr::Name(name) => BindingValue::Name(name.id.to_string()),
        Expr::Attribute(attribute)
            if attribute.attr.as_str() == "format"
                && matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "builtins") =>
        {
            BindingValue::BuiltinsFormat
        }
        Expr::StringLiteral(literal) => BindingValue::Template(string_value_text(&literal.value)),
        _ => BindingValue::Unknown,
    }
}

fn regex_pattern(call: &ruff_python_ast::ExprCall) -> Option<&Expr> {
    call.arguments
        .keywords
        .iter()
        .find(|keyword| {
            keyword
                .arg
                .as_ref()
                .is_some_and(|name| name.as_str() == "pattern")
        })
        .map(|keyword| &keyword.value)
        .or_else(|| call.arguments.args.first())
}
const FORMAT_METHOD: &str = "format";

/// Runs the GitHub `CodeQL` quality queries for one complete Python source file.
/// Syntax-invalid source is intentionally silent: the Sonar parsing rule owns
/// malformed input and a partial tree must not produce quality findings.
#[must_use]
pub(crate) fn analyze(source: &str) -> Vec<Issue> {
    let parsed = parse(source);
    if !parsed.errors().is_empty() {
        return Vec::new();
    }

    let index = LineIndex::from_source_text(source);
    let mut issues = Vec::new();
    check_regex_backspace(&parsed, &index, source, &mut issues);
    check_implicit_string_in_list(&parsed, &index, source, &mut issues);
    check_redundant_globals(&parsed, &index, source, &mut issues);
    check_explicit_del(&parsed, &index, source, &mut issues);
    check_mixed_format_fields(&parsed, &index, source, &mut issues);
    sort_issues(&mut issues);
    issues
}

fn push(
    issues: &mut Vec<Issue>,
    key: &str,
    message: &str,
    range: TextRange,
    index: &LineIndex,
    source: &str,
) {
    issues.push(issue_at(key, message, range, index, source));
}

fn expressions_in_source(parsed: &Parsed<ModModule>) -> impl Iterator<Item = &Expr> {
    FileContext::build(parsed).exprs.into_iter()
}

// ---------------------------------------------------------------------------
// py/regex/backspace-escape and py/implicit-string-concatenation-in-list
// ---------------------------------------------------------------------------

fn check_regex_backspace(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let facts = BindingFacts::build(parsed);
    for expr in expressions_in_source(parsed) {
        let Expr::Call(call) = expr else { continue };
        if !is_regex_call(&call.func, &facts) {
            continue;
        }
        let Some(pattern) = regex_pattern(call) else {
            continue;
        };
        let (literal_range, units) = match pattern {
            Expr::StringLiteral(literal) => {
                let mut units = Vec::new();
                for part in &literal.value {
                    units.extend(decode_string_part(
                        &source[part.range()],
                        part.range.start(),
                    ));
                }
                (literal.range(), units)
            }
            Expr::BytesLiteral(literal) if !literal.value.is_implicit_concatenated() => (
                literal.range(),
                decode_string_part(&source[literal.range()], literal.range.start()),
            ),
            _ => continue,
        };
        for offset in backspace_offsets_in_class(&units) {
            push(
                issues,
                "py/regex/backspace-escape",
                &format!("Backspace escape in regular expression at offset {offset}."),
                literal_range,
                index,
                source,
            );
        }
    }
}

fn is_regex_call(func: &Expr, facts: &BindingFacts) -> bool {
    const METHODS: &[&str] = &[
        "compile",
        "search",
        "match",
        "fullmatch",
        "split",
        "findall",
        "finditer",
        "sub",
        "subn",
    ];
    match func {
        Expr::Attribute(attribute) => {
            METHODS.contains(&attribute.attr.as_str())
                && matches!(
                    attribute.value.as_ref(),
                    Expr::Name(name)
                        if facts.resolve(name.id.as_str()) == Some(BindingValue::ReModule)
                )
        }
        Expr::Name(name) => facts.resolve(name.id.as_str()) == Some(BindingValue::ReFunction),
        _ => false,
    }
}

fn backspace_offsets_in_class(units: &[RxUnit]) -> Vec<usize> {
    let Ok(parsed) = parse_regex(units) else {
        return Vec::new();
    };
    let mut classes = Vec::new();
    for_each_class(&parsed.root, &mut |class| classes.push(class.span));
    let mut offsets = Vec::new();
    let mut utf16_offset = 0;
    let mut i = 0;
    while i < units.len() {
        let unit = units[i];
        if unit.ch == '\\' && i + 1 < units.len() {
            let next = units[i + 1];
            if next.ch == 'b'
                && classes
                    .iter()
                    .any(|range| range.start() <= unit.at && unit.at < range.end())
            {
                offsets.push(utf16_offset);
            }
            utf16_offset += unit.ch.len_utf16() + next.ch.len_utf16();
            i += 2;
        } else {
            utf16_offset += unit.ch.len_utf16();
            i += 1;
        }
    }
    offsets
}

fn check_implicit_string_in_list(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for expr in expressions_in_source(parsed) {
        let Expr::List(list) = expr else { continue };
        for (index_of_candidate, element) in list.elts.iter().enumerate() {
            let Expr::StringLiteral(literal) = element else {
                continue;
            };
            let has_other_string = list.elts.iter().enumerate().any(|(other_index, other)| {
                other_index != index_of_candidate && is_string_constant(other)
            });
            if has_other_string
                && literal.value.is_implicit_concatenated()
                && !is_parenthesized(parsed, literal.range())
            {
                push(
                    issues,
                    "py/implicit-string-concatenation-in-list",
                    "Implicit string concatenation. Maybe missing a comma?",
                    literal.range(),
                    index,
                    source,
                );
            }
        }
    }
}

fn is_string_constant(expr: &Expr) -> bool {
    match expr {
        Expr::StringLiteral(_) => true,
        Expr::BinOp(binary) => {
            is_string_constant(&binary.left) && is_string_constant(&binary.right)
        }
        _ => false,
    }
}

fn is_parenthesized(parsed: &Parsed<ModModule>, range: TextRange) -> bool {
    let tokens = significant_tokens(parsed);
    let before = tokens
        .iter()
        .rev()
        .find(|token| token.end() <= range.start())
        .map(|token| token.kind());
    let after = tokens
        .iter()
        .find(|token| token.start() >= range.end())
        .map(|token| token.kind());
    before == Some(TokenKind::Lpar) && after == Some(TokenKind::Rpar)
}

// ---------------------------------------------------------------------------
// py/redundant-global-declaration
// ---------------------------------------------------------------------------

fn check_redundant_globals(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for_each_stmt_in_scope(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Global(global) = stmt else { return };
        for name in &global.names {
            push(
                issues,
                "py/redundant-global-declaration",
                &format!("Declaring '{name}' as global at module-level is redundant."),
                global.range(),
                index,
                source,
            );
        }
    });
}

// ---------------------------------------------------------------------------
// py/explicit-call-to-delete
// ---------------------------------------------------------------------------

fn check_explicit_del(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    visit_explicit_del_scope(
        parsed.syntax().body.as_slice(),
        false,
        None,
        index,
        source,
        issues,
    );
}

fn visit_explicit_del_scope(
    suite: &[Stmt],
    in_del_method: bool,
    self_name: Option<&str>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let mut work = vec![(suite, in_del_method, self_name)];
    while let Some((scope, in_del_method, self_name)) = work.pop() {
        report_explicit_del_calls(scope, in_del_method, self_name, index, source, issues);
        schedule_explicit_del_scopes(scope, in_del_method, self_name, &mut work);
    }
}

fn report_explicit_del_calls(
    scope: &[Stmt],
    in_del_method: bool,
    self_name: Option<&str>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for stmt in scope {
        for expr in stmt_exprs(stmt) {
            let mut pending = vec![(expr, in_del_method, self_name)];
            while let Some((expr, expr_in_del_method, expr_self_name)) = pending.pop() {
                if let Some(call) = explicit_del_call(expr, expr_in_del_method, expr_self_name) {
                    push(
                        issues,
                        "py/explicit-call-to-delete",
                        "The __del__ special method is called explicitly.",
                        call.range(),
                        index,
                        source,
                    );
                }
                let (child_in_del_method, child_self_name) = if matches!(expr, Expr::Lambda(_)) {
                    (false, None)
                } else {
                    (expr_in_del_method, expr_self_name)
                };
                pending.extend(
                    child_exprs(expr)
                        .into_iter()
                        .rev()
                        .map(|child| (child, child_in_del_method, child_self_name)),
                );
            }
        }
    }
}

fn explicit_del_call<'a>(
    expr: &'a Expr,
    in_del_method: bool,
    self_name: Option<&str>,
) -> Option<&'a ruff_python_ast::ExprCall> {
    let Expr::Call(call) = expr else {
        return None;
    };
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    (attribute.attr.as_str() == "__del__" && !is_super_del(call, in_del_method, self_name))
        .then_some(call)
}

fn schedule_explicit_del_scopes<'a>(
    scope: &'a [Stmt],
    in_del_method: bool,
    self_name: Option<&'a str>,
    work: &mut Vec<(&'a [Stmt], bool, Option<&'a str>)>,
) {
    for stmt in scope {
        match stmt {
            Stmt::FunctionDef(function) => {
                let first = function
                    .parameters
                    .iter()
                    .next()
                    .map(|parameter| parameter.name().as_str());
                work.push((&function.body, function.name.as_str() == "__del__", first));
            }
            Stmt::ClassDef(class) => work.push((&class.body, false, None)),
            _ => {
                for body in child_bodies(stmt).into_iter().rev() {
                    work.push((body, in_del_method, self_name));
                }
            }
        }
    }
}

fn is_super_del(
    call: &ruff_python_ast::ExprCall,
    in_del_method: bool,
    self_name: Option<&str>,
) -> bool {
    if !in_del_method {
        return false;
    }
    if let Some(name) = self_name
        && call
            .arguments
            .args
            .first()
            .is_some_and(|arg| matches!(arg, Expr::Name(value) if value.id.as_str() == name))
    {
        return true;
    }
    matches!(
        call.func.as_ref(),
        Expr::Attribute(attribute)
            if matches!(attribute.value.as_ref(), Expr::Call(super_call)
                if called_name(&super_call.func) == Some("super"))
    )
}

// ---------------------------------------------------------------------------
// py/str-format/mixed-fields
// ---------------------------------------------------------------------------

fn check_mixed_format_fields(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let facts = BindingFacts::build(parsed);
    for expr in expressions_in_source(parsed) {
        let Expr::Call(call) = expr else { continue };
        let Some((text, range)) = format_literal_for_call(call, &facts) else {
            continue;
        };
        let (implicit, explicit) = format_field_kinds(&text);
        if implicit && explicit {
            push(
                issues,
                "py/str-format/mixed-fields",
                "Formatting string mixes implicitly and explicitly numbered fields.",
                range,
                index,
                source,
            );
        }
    }
}

fn format_literal_for_call(
    call: &ruff_python_ast::ExprCall,
    facts: &BindingFacts,
) -> Option<(String, TextRange)> {
    match call.func.as_ref() {
        Expr::Attribute(attribute) if attribute.attr.as_str() == FORMAT_METHOD => {
            format_method_literal(call, attribute.value.as_ref(), facts)
        }
        Expr::Name(name)
            if facts.resolve(name.id.as_str()) == Some(BindingValue::FormatFunction) =>
        {
            first_string_literal(call)
        }
        _ => None,
    }
}

fn format_method_literal(
    call: &ruff_python_ast::ExprCall,
    receiver: &Expr,
    facts: &BindingFacts,
) -> Option<(String, TextRange)> {
    if is_builtin_format_receiver(receiver, facts) {
        first_string_literal(call)
    } else {
        format_receiver_literal(receiver, facts)
    }
}

fn is_builtin_format_receiver(receiver: &Expr, facts: &BindingFacts) -> bool {
    matches!(
        receiver,
        Expr::Name(name)
            if facts.resolve(name.id.as_str()) == Some(BindingValue::BuiltinsModule)
    )
}

fn format_receiver_literal(receiver: &Expr, facts: &BindingFacts) -> Option<(String, TextRange)> {
    match receiver {
        Expr::StringLiteral(literal) => Some((string_value_text(&literal.value), literal.range())),
        Expr::Name(name) => match facts.resolve(name.id.as_str()) {
            Some(BindingValue::Template(text)) => Some((text, receiver.range())),
            _ => None,
        },
        _ => None,
    }
}

fn first_string_literal(call: &ruff_python_ast::ExprCall) -> Option<(String, TextRange)> {
    call.arguments.args.first().and_then(string_literal)
}

fn string_literal(expr: &Expr) -> Option<(String, TextRange)> {
    match expr {
        Expr::StringLiteral(literal) => Some((string_value_text(&literal.value), literal.range())),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// py/str-format/mixed-fields
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FormatFieldKinds {
    implicit: bool,
    explicit: bool,
}

fn format_field_kinds(text: &str) -> (bool, bool) {
    let chars: Vec<char> = text.chars().collect();
    let mut kinds = FormatFieldKinds::default();
    let mut regions = vec![(0usize, chars.len())];
    while let Some((start, limit)) = regions.pop() {
        scan_format_region(&chars, start, limit, &mut regions, &mut kinds);
    }
    (kinds.implicit, kinds.explicit)
}

fn scan_format_region(
    chars: &[char],
    start: usize,
    limit: usize,
    regions: &mut Vec<(usize, usize)>,
    kinds: &mut FormatFieldKinds,
) {
    let mut i = start;
    while i < limit {
        if chars[i] != '{' {
            i += 1;
            continue;
        }
        if i + 1 < limit && chars[i + 1] == '{' {
            i += 2;
            continue;
        }
        let Some(end) = find_format_field_end(chars, i + 1, limit) else {
            break;
        };
        scan_format_field(chars, i + 1, end, regions, kinds);
        i = end + 1;
    }
}

fn find_format_field_end(chars: &[char], start: usize, limit: usize) -> Option<usize> {
    let mut depth = 1usize;
    let mut end = start;
    while end < limit {
        match chars[end] {
            '{' if end + 1 >= limit || chars[end + 1] != '{' => depth += 1,
            '}' if end + 1 < limit && chars[end + 1] == '}' => end += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(end);
                }
            }
            _ => {}
        }
        end += 1;
    }
    None
}

fn scan_format_field(
    chars: &[char],
    field_start: usize,
    end: usize,
    regions: &mut Vec<(usize, usize)>,
    kinds: &mut FormatFieldKinds,
) {
    let field = &chars[field_start..end];
    let split = field
        .iter()
        .position(|ch| matches!(ch, '!' | ':'))
        .unwrap_or(field.len());
    let field_name = &field[..split];
    if field_name.is_empty() {
        kinds.implicit = true;
    } else if is_explicit_field_name(field_name) {
        kinds.explicit = true;
    }
    if let Some(colon) = field.iter().position(|ch| *ch == ':') {
        regions.push((field_start + colon + 1, end));
    }
}

fn is_explicit_field_name(field_name: &[char]) -> bool {
    field_name
        .split(|ch| *ch == '.')
        .next()
        .is_some_and(|part| !part.is_empty() && part.iter().all(char::is_ascii_digit))
}

#[cfg(test)]
mod tests {
    use super::analyze;

    fn assert_single_issue(
        source: &str,
        key: &str,
        message: &str,
        start: (u32, u32),
        end: (u32, u32),
    ) {
        let issues = analyze(source);
        assert_eq!(issues.len(), 1, "{source:?}: {issues:?}");
        let issue = &issues[0];
        assert_eq!(issue.rule_key, key);
        assert_eq!(issue.message, message);
        assert_eq!((issue.range.start.line, issue.range.start.column), start);
        assert_eq!((issue.range.end.line, issue.range.end.column), end);
    }

    fn assert_clean(source: &str) {
        assert!(analyze(source).is_empty(), "{source:?}");
    }

    #[test]
    fn malformed_source_is_fail_closed() {
        assert_clean("def broken(:\n");
    }

    #[test]
    fn regex_backspace_escape_reports_literal_range() {
        let source = "import re\nre.compile(r'[\\b]')\n";
        assert_single_issue(
            source,
            "py/regex/backspace-escape",
            "Backspace escape in regular expression at offset 1.",
            (2, 11),
            (2, 18),
        );
        assert_clean("import re\nre.compile(r'\\b')\n");
        assert_single_issue(
            "import re\nre.compile(br'[\\b]')\n",
            "py/regex/backspace-escape",
            "Backspace escape in regular expression at offset 1.",
            (2, 11),
            (2, 19),
        );
    }

    #[test]
    fn regex_requires_import_identity_and_accepts_pattern_keyword() {
        assert_single_issue(
            "import re as rx\nrx.search(pattern=r'[\\b]', string='x')\n",
            "py/regex/backspace-escape",
            "Backspace escape in regular expression at offset 1.",
            (2, 18),
            (2, 25),
        );
        assert_single_issue(
            "from re import compile as c\nc(pattern=r'[\\b]')\n",
            "py/regex/backspace-escape",
            "Backspace escape in regular expression at offset 1.",
            (2, 10),
            (2, 17),
        );
        assert_clean("def search(pattern): pass\nsearch(r'[\\b]')\n");
        assert_clean("re = object()\nre.search(r'[\\b]')\n");
        assert_clean("import re\nre.compile(r'[\\b')\n");
    }

    #[test]
    fn regex_offsets_are_utf16_and_classes_are_validated() {
        assert_clean("import re\nre.compile(r'[\\b')\n");
        assert_single_issue(
            "import re\nre.compile(r'😀[\\b]')\n",
            "py/regex/backspace-escape",
            "Backspace escape in regular expression at offset 3.",
            (2, 11),
            (2, 19),
        );
    }

    #[test]
    fn implicit_string_concatenation_in_list_reports_literal_range() {
        let source = "items = [\"a\" \"b\", \"c\"]\n";
        assert_single_issue(
            source,
            "py/implicit-string-concatenation-in-list",
            "Implicit string concatenation. Maybe missing a comma?",
            (1, 9),
            (1, 16),
        );
        assert_clean("items = [\"a\", \"b\"]\n");
        assert_clean("items = [( # keep this grouping\n    \"a\"\n    \"b\"), \"c\"]\n");
    }

    #[test]
    fn redundant_global_declaration_reports_statement_range() {
        let source = "global value\n";
        assert_single_issue(
            source,
            "py/redundant-global-declaration",
            "Declaring 'value' as global at module-level is redundant.",
            (1, 0),
            (1, 12),
        );
        assert_clean("def load():\n    global value\n");
    }

    #[test]
    fn explicit_call_to_delete_reports_call_range_and_headers() {
        let source = concat!(
            "obj.__del__()\n",
            "@obj.__del__()\n",
            "def f(x=obj.__del__(), y: obj.__del__() = 1) -> obj.__del__():\n",
            "    pass\n",
            "class C(obj.__del__()):\n",
            "    pass\n",
        );
        assert_eq!(
            analyze(source)
                .iter()
                .filter(|issue| issue.rule_key == "py/explicit-call-to-delete")
                .count(),
            6
        );
        assert_clean("class C:\n    def __del__(self):\n        super().__del__()\n");
        let lambda = concat!(
            "class C:\n",
            "    def __del__(self):\n",
            "        callback = lambda self: obj.__del__(self)\n",
        );
        assert_eq!(
            analyze(lambda)
                .iter()
                .filter(|issue| issue.rule_key == "py/explicit-call-to-delete")
                .count(),
            1
        );
    }

    #[test]
    fn mixed_format_supports_builtin_and_safe_aliases() {
        assert_single_issue(
            "format('{} {1}', a, b)\n",
            "py/str-format/mixed-fields",
            "Formatting string mixes implicitly and explicitly numbered fields.",
            (1, 7),
            (1, 15),
        );
        assert_single_issue(
            "fmt = format\nfmt('{} {1}', a, b)\n",
            "py/str-format/mixed-fields",
            "Formatting string mixes implicitly and explicitly numbered fields.",
            (2, 4),
            (2, 12),
        );
        assert_clean("def format(value, *args): pass\nformat('{} {1}', a, b)\n");
        assert_clean("template = '{} {}'\ntemplate.format(a, b)\n");
    }
}
