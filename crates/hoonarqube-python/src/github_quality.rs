//! Independently implemented GitHub `CodeQL` Python quality queries.
//!
//! The entrypoint in this module deliberately has a strict parse gate.  `CodeQL`
//! runs on a complete AST; a recovered Ruff tree is not evidence for a finding.

use hoonarqube_ir::Issue;
use ruff_python_ast::token::TokenKind;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};
use std::collections::HashMap;

use crate::engine::file_context::FileContext;
use crate::engine::rx::{RxUnit, decode_string_part, for_each_class, parse_regex};
use crate::support::{
    called_name, child_bodies, child_exprs, collect_target_names, for_each_stmt_in_scope, issue_at,
    named_parameters, parse, significant_tokens, sort_issues, stmt_exprs, stmt_store_names,
    string_value_text,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScopeKind {
    Module,
    Function,
    Class,
    Comprehension,
}
struct ScopeFacts {
    kind: ScopeKind,
    parent: Option<usize>,
    regions: Vec<TextRange>,
    bindings: HashMap<String, Vec<ScopedBinding>>,
}

struct ScopedBinding {
    value: BindingValue,
    range: TextRange,
}

impl ScopeFacts {
    fn new(kind: ScopeKind, parent: Option<usize>, regions: Vec<TextRange>) -> Self {
        Self {
            kind,
            parent,
            regions,
            bindings: HashMap::new(),
        }
    }
}

#[derive(Default)]
struct BindingFacts {
    scopes: Vec<ScopeFacts>,
}

impl BindingFacts {
    fn build(parsed: &Parsed<ModModule>) -> Self {
        let mut facts = Self {
            scopes: vec![ScopeFacts::new(
                ScopeKind::Module,
                None,
                vec![parsed.syntax().range()],
            )],
        };
        facts.record_statements(0, parsed.syntax().body.as_slice());
        facts
    }

    fn record_statements(&mut self, scope: usize, statements: &[Stmt]) {
        for statement in statements {
            self.record_statement(scope, statement);
        }
    }

    fn record_statement(&mut self, scope: usize, statement: &Stmt) {
        match statement {
            Stmt::Import(import) => {
                self.record_import(scope, import);
                self.record_statement_expressions(scope, statement);
            }
            Stmt::ImportFrom(import) if import.level == 0 => {
                self.record_import_from(scope, import);
                self.record_statement_expressions(scope, statement);
            }
            Stmt::ImportFrom(_) => {}
            Stmt::FunctionDef(function) => {
                self.bind(
                    scope,
                    function.name.as_str(),
                    BindingValue::Unknown,
                    statement.range(),
                );
                self.record_statement_expressions(scope, statement);
                let function_scope =
                    self.push_scope(ScopeKind::Function, scope, body_range(&function.body));
                self.bind_parameters(function_scope, &function.parameters);
                self.record_statements(function_scope, &function.body);
            }
            Stmt::ClassDef(class) => {
                self.bind(
                    scope,
                    class.name.as_str(),
                    BindingValue::Unknown,
                    statement.range(),
                );
                self.record_statement_expressions(scope, statement);
                let class_scope = self.push_scope(ScopeKind::Class, scope, body_range(&class.body));
                self.record_statements(class_scope, &class.body);
            }
            Stmt::Assign(assign) => {
                let value = binding_value(&assign.value);
                for target in &assign.targets {
                    let mut names = Vec::new();
                    collect_target_names(target, &mut names);
                    for name in names {
                        self.bind(scope, &name, value.clone(), statement.range());
                    }
                }
                self.record_statement_expressions(scope, statement);
            }
            Stmt::AnnAssign(assign) => {
                let value = assign
                    .value
                    .as_deref()
                    .map_or(BindingValue::Unknown, binding_value);
                let mut names = Vec::new();
                collect_target_names(&assign.target, &mut names);
                for name in names {
                    self.bind(scope, &name, value.clone(), statement.range());
                }
                self.record_statement_expressions(scope, statement);
            }
            Stmt::AugAssign(assign) => {
                let mut names = Vec::new();
                collect_target_names(&assign.target, &mut names);
                for name in names {
                    self.bind(scope, &name, BindingValue::Unknown, statement.range());
                }
                self.record_statement_expressions(scope, statement);
            }
            _ => {
                for name in stmt_store_names(statement) {
                    self.bind(
                        scope,
                        &name,
                        BindingValue::Unknown,
                        statement_binding_range(statement),
                    );
                }
                self.record_statement_expressions(scope, statement);
                for body in child_bodies(statement) {
                    self.record_statements(scope, body);
                }
            }
        }
    }

    fn record_statement_expressions(&mut self, scope: usize, statement: &Stmt) {
        for expression in stmt_exprs(statement) {
            self.record_expression(scope, expression);
        }
    }

    fn record_import(&mut self, scope: usize, import: &ruff_python_ast::StmtImport) {
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
            self.bind(scope, &local, value, alias.range());
        }
    }

    fn record_import_from(&mut self, scope: usize, import: &ruff_python_ast::StmtImportFrom) {
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
            self.bind(scope, &local, value, alias.range());
        }
    }
    fn record_expression(&mut self, scope: usize, expression: &Expr) {
        match expression {
            Expr::Named(named) => {
                self.record_expression(scope, &named.value);
                let target_scope = self.nearest_non_comprehension(scope);
                let mut target_names = Vec::new();
                collect_target_names(&named.target, &mut target_names);
                for name in target_names {
                    self.bind(
                        target_scope,
                        &name,
                        BindingValue::Unknown,
                        named.target.range(),
                    );
                }
            }
            Expr::Lambda(lambda) => {
                if let Some(parameters) = &lambda.parameters {
                    let mut expressions = Vec::new();
                    crate::support::push_parameter_exprs(parameters, &mut expressions);
                    for expression in expressions {
                        self.record_expression(scope, expression);
                    }
                }
                let lambda_scope =
                    self.push_scope(ScopeKind::Function, scope, vec![lambda.body.range()]);
                if let Some(parameters) = &lambda.parameters {
                    self.bind_parameters(lambda_scope, parameters);
                }
                self.record_expression(lambda_scope, &lambda.body);
            }
            Expr::ListComp(comp) => {
                self.record_comprehension(scope, &comp.elt, &comp.generators);
            }
            Expr::SetComp(comp) => {
                self.record_comprehension(scope, &comp.elt, &comp.generators);
            }
            Expr::Generator(comp) => {
                self.record_comprehension(scope, &comp.elt, &comp.generators);
            }
            Expr::DictComp(comp) => {
                let mut results = Vec::new();
                if let Some(key) = &comp.key {
                    results.push(key.as_ref());
                }
                results.push(comp.value.as_ref());
                self.record_comprehension_results(scope, &results, &comp.generators);
            }
            _ => {
                for child in child_exprs(expression) {
                    self.record_expression(scope, child);
                }
            }
        }
    }

    fn record_comprehension(
        &mut self,
        parent: usize,
        result: &Expr,
        generators: &[ruff_python_ast::Comprehension],
    ) {
        self.record_comprehension_results(parent, &[result], generators);
    }

    fn record_comprehension_results(
        &mut self,
        parent: usize,
        results: &[&Expr],
        generators: &[ruff_python_ast::Comprehension],
    ) {
        if generators.is_empty() {
            for result in results {
                self.record_expression(parent, result);
            }
            return;
        }
        let mut regions = Vec::new();
        for generator in generators {
            regions.push(generator.target.range());
            regions.extend(generator.ifs.iter().map(ruff_text_size::Ranged::range));
        }
        for generator in generators.iter().skip(1) {
            regions.push(generator.iter.range());
        }
        regions.extend(
            results
                .iter()
                .map(|result| ruff_text_size::Ranged::range(*result)),
        );
        let comprehension = self.push_scope(ScopeKind::Comprehension, parent, regions);
        for (index, generator) in generators.iter().enumerate() {
            let iter_scope = if index == 0 { parent } else { comprehension };
            self.record_expression(iter_scope, &generator.iter);
            let mut names = Vec::new();
            collect_target_names(&generator.target, &mut names);
            for name in names {
                self.bind(
                    comprehension,
                    &name,
                    BindingValue::Unknown,
                    generator.target.range(),
                );
            }
            for condition in &generator.ifs {
                self.record_expression(comprehension, condition);
            }
        }
        for result in results {
            self.record_expression(comprehension, result);
        }
    }

    fn push_scope(&mut self, kind: ScopeKind, parent: usize, regions: Vec<TextRange>) -> usize {
        self.scopes
            .push(ScopeFacts::new(kind, Some(parent), regions));
        self.scopes.len() - 1
    }
    fn bind_parameters(&mut self, scope: usize, parameters: &ruff_python_ast::Parameters) {
        for parameter in named_parameters(parameters) {
            self.bind(
                scope,
                parameter.parameter.name.as_str(),
                BindingValue::Unknown,
                parameter.parameter.name.range(),
            );
        }
        for parameter in [parameters.vararg.as_deref(), parameters.kwarg.as_deref()]
            .into_iter()
            .flatten()
        {
            self.bind(
                scope,
                parameter.name.as_str(),
                BindingValue::Unknown,
                parameter.name.range(),
            );
        }
    }

    fn bind(&mut self, scope: usize, name: &str, value: BindingValue, range: TextRange) {
        self.scopes[scope]
            .bindings
            .entry(name.to_string())
            .or_default()
            .push(ScopedBinding { value, range });
    }

    fn nearest_non_comprehension(&self, mut scope: usize) -> usize {
        while self.scopes[scope].kind == ScopeKind::Comprehension {
            scope = self.scopes[scope].parent.unwrap_or(scope);
        }
        scope
    }

    fn resolve_for(&self, range: TextRange, name: &str) -> Option<BindingValue> {
        let scope = self.scope_for(range);
        self.resolve_inner(scope, name, Some(range.start()), &mut Vec::new())
    }

    fn scope_for(&self, range: TextRange) -> usize {
        self.scopes
            .iter()
            .enumerate()
            .filter(|(_, scope)| {
                scope
                    .regions
                    .iter()
                    .any(|region| region.start() <= range.start() && range.end() <= region.end())
            })
            .min_by_key(|(_, scope)| {
                scope
                    .regions
                    .iter()
                    .filter(|region| region.start() <= range.start() && range.end() <= region.end())
                    .map(|region| u32::from(region.end()) - u32::from(region.start()))
                    .min()
                    .unwrap_or(u32::MAX)
            })
            .map_or(0, |(index, _)| index)
    }

    fn active_bindings(
        &self,
        scope: usize,
        name: &str,
        position: Option<TextSize>,
    ) -> Option<Vec<&ScopedBinding>> {
        self.scopes[scope].bindings.get(name).map(|bindings| {
            bindings
                .iter()
                .filter(|binding| position.is_none_or(|position| binding.range.end() <= position))
                .collect()
        })
    }

    fn resolve_inner(
        &self,
        scope: usize,
        name: &str,
        position: Option<TextSize>,
        visiting: &mut Vec<String>,
    ) -> Option<BindingValue> {
        let Some(values) = self
            .active_bindings(scope, name, position)
            .filter(|values| !values.is_empty())
        else {
            return self.resolve_missing(scope, name, position, visiting);
        };
        if visiting.iter().any(|seen| seen == name) {
            return None;
        }
        self.resolve_bindings(scope, name, values, visiting)
    }

    fn resolve_missing(
        &self,
        scope: usize,
        name: &str,
        position: Option<TextSize>,
        visiting: &mut Vec<String>,
    ) -> Option<BindingValue> {
        if self.scopes[scope].bindings.contains_key(name) {
            return match self.scopes[scope].kind {
                ScopeKind::Class => self.resolve_inner(0, name, position, visiting),
                ScopeKind::Function | ScopeKind::Comprehension | ScopeKind::Module => None,
            };
        }
        self.lexical_parent(scope).map_or_else(
            || (name == "format").then_some(BindingValue::FormatFunction),
            |parent| self.resolve_inner(parent, name, None, visiting),
        )
    }

    fn resolve_bindings(
        &self,
        scope: usize,
        name: &str,
        values: Vec<&ScopedBinding>,
        visiting: &mut Vec<String>,
    ) -> Option<BindingValue> {
        visiting.push(name.to_string());
        let mut resolved = None;
        for binding in values {
            let current = self.resolve_binding_value(scope, binding, visiting);
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

    fn resolve_binding_value(
        &self,
        scope: usize,
        binding: &ScopedBinding,
        visiting: &mut Vec<String>,
    ) -> Option<BindingValue> {
        let position = binding.range.start();
        match &binding.value {
            BindingValue::Name(other) => self.resolve_inner(scope, other, Some(position), visiting),
            BindingValue::BuiltinsFormat => self.resolve_builtins_format(scope, position, visiting),
            concrete => Some(concrete.clone()),
        }
    }

    fn resolve_builtins_format(
        &self,
        scope: usize,
        position: TextSize,
        visiting: &mut Vec<String>,
    ) -> Option<BindingValue> {
        let builtins = self.resolve_inner(scope, "builtins", Some(position), visiting);
        if builtins == Some(BindingValue::BuiltinsModule)
            || (builtins.is_none() && !self.has_binding_in_chain(scope, "builtins"))
        {
            Some(BindingValue::FormatFunction)
        } else {
            None
        }
    }

    fn has_binding_in_chain(&self, scope: usize, name: &str) -> bool {
        self.scopes[scope].bindings.contains_key(name)
            || self
                .lexical_parent(scope)
                .is_some_and(|parent| self.has_binding_in_chain(parent, name))
    }

    fn lexical_parent(&self, scope: usize) -> Option<usize> {
        let mut parent = self.scopes[scope].parent?;
        if self.scopes[scope].kind != ScopeKind::Module {
            while self.scopes[parent].kind == ScopeKind::Class {
                parent = self.scopes[parent].parent?;
            }
        }
        Some(parent)
    }
}

fn body_range(body: &[Stmt]) -> Vec<TextRange> {
    body.first()
        .zip(body.last())
        .map(|(first, last)| vec![TextRange::new(first.range().start(), last.range().end())])
        .unwrap_or_default()
}

fn statement_binding_range(statement: &Stmt) -> TextRange {
    match statement {
        Stmt::For(for_stmt) => for_stmt.target.range(),
        Stmt::With(with_stmt) => with_stmt
            .items
            .iter()
            .find_map(|item| {
                item.optional_vars
                    .as_deref()
                    .map(ruff_text_size::Ranged::range)
            })
            .unwrap_or_else(|| statement.range()),
        _ => statement.range(),
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
                        if facts.resolve_for(attribute.value.range(), name.id.as_str())
                            == Some(BindingValue::ReModule)
                )
        }
        Expr::Name(name) => {
            facts.resolve_for(name.range(), name.id.as_str()) == Some(BindingValue::ReFunction)
        }
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
            if facts.resolve_for(name.range(), name.id.as_str())
                == Some(BindingValue::FormatFunction) =>
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
            if facts.resolve_for(name.range(), name.id.as_str())
                == Some(BindingValue::BuiltinsModule)
    )
}

fn format_receiver_literal(receiver: &Expr, facts: &BindingFacts) -> Option<(String, TextRange)> {
    match receiver {
        Expr::StringLiteral(literal) => Some((string_value_text(&literal.value), literal.range())),
        Expr::Name(name) => match facts.resolve_for(name.range(), name.id.as_str()) {
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
    #[test]
    fn binding_facts_keep_nested_imports_and_assignments_in_their_scope() {
        let source = concat!(
            "import re\n",
            "def local():\n",
            "    import re as rx\n",
            "    rx.search(r'[\\b]')\n",
            "    re = object()\n",
            "    re.search(r'[\\b]')\n",
            "re.compile(r'[\\b]')\n",
        );
        let issues = analyze(source);
        let regex_issues: Vec<_> = issues
            .iter()
            .filter(|issue| issue.rule_key == "py/regex/backspace-escape")
            .collect();
        assert_eq!(regex_issues.len(), 2, "{issues:?}");
        assert_eq!(
            regex_issues
                .iter()
                .map(|issue| (issue.range.start.line, issue.range.start.column))
                .collect::<Vec<_>>(),
            vec![(4, 14), (7, 11)]
        );
    }

    #[test]
    fn binding_facts_do_not_use_imports_before_their_binding() {
        let source = concat!(
            "def local():\n",
            "    rx.search(r'[\\b]')\n",
            "    import re as rx\n",
        );
        assert_clean(source);
    }

    #[test]
    fn binding_facts_resolve_enclosing_imports_for_nested_function_bodies() {
        assert_single_issue(
            concat!(
                "def outer():\n",
                "    def inner():\n",
                "        re.search(r'[\\b]')\n",
                "    import re\n",
                "    inner()\n",
                "outer()\n",
            ),
            "py/regex/backspace-escape",
            "Backspace escape in regular expression at offset 1.",
            (3, 18),
            (3, 25),
        );
    }

    #[test]
    fn binding_facts_keep_prior_import_visible_in_assignment_rhs() {
        assert_single_issue(
            "import re\nre = re.compile(r'[\\b]')\n",
            "py/regex/backspace-escape",
            "Backspace escape in regular expression at offset 1.",
            (2, 16),
            (2, 23),
        );
    }

    #[test]
    fn binding_facts_isolate_parameters_lambdas_and_class_attributes() {
        let source = concat!(
            "import re\n",
            "class C:\n",
            "    re = object()\n",
            "    def method(self, re):\n",
            "        re.search(r'[\\b]')\n",
            "    def inherited(self):\n",
            "        re.search(r'[\\b]')\n",
            "callback = lambda re: re.search(r'[\\b]')\n",
            "re.search(r'[\\b]')\n",
        );
        let issues = analyze(source);
        let regex_issues: Vec<_> = issues
            .iter()
            .filter(|issue| issue.rule_key == "py/regex/backspace-escape")
            .collect();
        assert_eq!(regex_issues.len(), 2, "{issues:?}");
        assert_eq!(
            regex_issues
                .iter()
                .map(|issue| (issue.range.start.line, issue.range.start.column))
                .collect::<Vec<_>>(),
            vec![(7, 18), (9, 10)]
        );
    }

    #[test]
    fn binding_facts_class_locals_fallback_to_module_globals() {
        let source = concat!(
            "re = object()\n",
            "def outer():\n",
            "    import re\n",
            "    class C:\n",
            "        re.search(r'[\\b]')\n",
            "        re = object()\n",
        );
        assert_clean(source);
    }

    #[test]
    fn binding_facts_respect_parent_builtins_shadowing() {
        let source = concat!(
            "builtins = object()\n",
            "def local():\n",
            "    fmt = builtins.format\n",
            "    fmt('{} {1}', a, b)\n",
        );
        assert_clean(source);
    }

    #[test]
    fn binding_facts_scope_comprehension_targets_without_leaking_them() {
        let source = concat!(
            "import re\n",
            "values = []\n",
            "[re.search(r'[\\b]') for re in values]\n",
            "re.search(r'[\\b]')\n",
        );
        let issues = analyze(source);
        let regex_issues: Vec<_> = issues
            .iter()
            .filter(|issue| issue.rule_key == "py/regex/backspace-escape")
            .collect();
        assert_eq!(regex_issues.len(), 1, "{issues:?}");
        assert_eq!(
            (
                regex_issues[0].range.start.line,
                regex_issues[0].range.start.column
            ),
            (4, 10)
        );
    }

    #[test]
    fn binding_facts_do_not_leak_nested_templates_into_format_calls() {
        let source = concat!(
            "template = '{} {1}'\n",
            "def local(template):\n",
            "    template.format(a, b)\n",
            "template.format(a, b)\n",
        );
        let issues = analyze(source);
        let format_issues: Vec<_> = issues
            .iter()
            .filter(|issue| issue.rule_key == "py/str-format/mixed-fields")
            .collect();
        assert_eq!(format_issues.len(), 1, "{issues:?}");
        assert_eq!(
            (
                format_issues[0].range.start.line,
                format_issues[0].range.start.column
            ),
            (4, 0)
        );
    }

    #[test]
    fn binding_facts_do_not_create_outer_templates_from_nested_assignments() {
        let source = concat!(
            "def local():\n",
            "    template = '{} {1}'\n",
            "    template.format(a, b)\n",
            "template.format(a, b)\n",
        );
        let issues = analyze(source);
        let format_issues: Vec<_> = issues
            .iter()
            .filter(|issue| issue.rule_key == "py/str-format/mixed-fields")
            .collect();
        assert_eq!(format_issues.len(), 1, "{issues:?}");
        assert_eq!(
            (
                format_issues[0].range.start.line,
                format_issues[0].range.start.column
            ),
            (3, 4)
        );
    }
}
