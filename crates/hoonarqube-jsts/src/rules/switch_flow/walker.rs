// Family walker for 'switch_flow' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::statement_ends_with_jump;
use crate::support::{
    IssueSink, LineIndex, RuleScope, ScannedComment, source_slice, unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionExpression, BindingPattern, BlockStatement, CatchClause, Class, ClassType,
    Declaration, Expression, ForInStatement, ForOfStatement, ForStatement, Function, FunctionType,
    IfStatement, LogicalOperator, Statement, StaticBlock, SwitchCase, SwitchStatement, TSEnumBody,
    TSEnumMemberName, TSInterfaceBody, TSLiteral, TSModuleBlock, TSPropertySignature, TSSignature,
    TSType, TSTypeName, VariableDeclaration,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_block_statement, walk_catch_clause, walk_class,
    walk_for_in_statement, walk_for_of_statement, walk_for_statement, walk_function, walk_program,
    walk_static_block, walk_switch_case, walk_switch_statement, walk_ts_module_block,
    walk_variable_declaration,
};
use oxc_span::GetSpan;
use std::collections::HashMap;

fn check_switch_flow(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    comments: &[ScannedComment],
) -> Vec<Issue> {
    let mut collector = SwitchFlowCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        comments,
        in_else_if_chain: false,
        case_depth: 0,
        switch_cases: Vec::new(),
        binding_scopes: Vec::new(),
        type_decls: HashMap::new(),
    };
    collector.collect_type_decls(program);
    collector.visit_program(program);
    collector.sink.issues
}

/// Switch-statement and if-chain flow rules in one traversal: `S126`
/// (chain without final `else`), `S128` (case fall-through), `S131`
/// (missing `default`), `S4524` (default not last), `S3616` (sequence or
/// logical-OR case test), `S1479` (too many cases), `S1301` (switch
/// convertible to `if`), and `S1821` (switch nested inside a case).
struct SwitchFlowCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    comments: &'a [ScannedComment],
    /// Set while visiting the `alternate` of an enclosing `if`; detects
    /// chains whose last link lacks a final `else` (`S126`).
    in_else_if_chain: bool,
    /// Number of enclosing `SwitchCase` consequents (`S1821`).
    case_depth: u32,
    /// Case lists of enclosing switches, innermost last (`S128` needs the
    /// following case's start to find `falls through` comments and to skip
    /// the last case).
    switch_cases: Vec<&'a [SwitchCase<'a>]>,
    /// Lexical scopes of value bindings, innermost last; used by `S131` to
    /// resolve a switch discriminant's declared type.
    binding_scopes: Vec<Vec<Binding<'a>>>,
    /// Top-level type declarations used by `S131` exhaustiveness.
    type_decls: HashMap<&'a str, TypeDecl<'a>>,
}

/// A value binding visible to `S131` discriminant resolution: the bound
/// name plus its declared type annotation when present.
struct Binding<'a> {
    name: &'a str,
    annotation: Option<&'a TSType<'a>>,
}

/// A top-level type declaration usable for `S131` exhaustiveness.
enum TypeDecl<'a> {
    Alias(&'a TSType<'a>),
    Enum(&'a TSEnumBody<'a>),
    Interface(&'a TSInterfaceBody<'a>),
}

/// A case-test or union-member identity for `S131` coverage comparison.
#[derive(PartialEq)]
enum CaseKey<'a> {
    Str(&'a str),
    Num(f64),
    Bool(bool),
    /// `(enum type name, member name)` for `case E.Member` tests.
    EnumMember(&'a str, &'a str),
}

/// Bound on alias/interface indirection during `S131` type resolution.
const MAX_TYPE_RESOLUTION_DEPTH: u32 = 8;

impl<'a> Visit<'a> for SwitchFlowCollector<'a, '_> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        self.binding_scopes.push(Vec::new());
        walk_program(self, it);
        self.binding_scopes.pop();
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        if self.in_else_if_chain && it.alternate.is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S126",
                "Add the missing \"else\" clause.",
                oxc_span::Span::new(
                    it.span.start.saturating_sub(5),
                    it.span.start.saturating_add(2),
                ),
            );
        }
        let saved_in_chain = self.in_else_if_chain;
        self.in_else_if_chain = false;
        self.visit_statement(&it.consequent);
        self.in_else_if_chain = matches!(&it.alternate, Some(Statement::IfStatement(_)));
        if let Some(alternate) = &it.alternate {
            self.visit_statement(alternate);
        }
        self.in_else_if_chain = saved_in_chain;
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        // Declared function names bind in the enclosing scope; expression
        // names bind inside the function itself.
        let outer_name = matches!(
            it.r#type,
            FunctionType::FunctionDeclaration | FunctionType::TSDeclareFunction
        );
        if outer_name && let Some(id) = &it.id {
            self.record_name(id.name.as_str(), None);
        }
        self.binding_scopes.push(Vec::new());
        if !outer_name && let Some(id) = &it.id {
            self.record_name(id.name.as_str(), None);
        }
        for param in &it.params.items {
            let annotation = param
                .type_annotation
                .as_deref()
                .map(|a| &self.alloc(a).type_annotation);
            self.record_pattern(&param.pattern, annotation);
        }
        if let Some(rest) = &it.params.rest {
            let annotation = rest
                .type_annotation
                .as_deref()
                .map(|a| &self.alloc(a).type_annotation);
            self.record_pattern(&rest.rest.argument, annotation);
        }
        walk_function(self, it, flags);
        self.binding_scopes.pop();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.binding_scopes.push(Vec::new());
        for param in &it.params.items {
            let annotation = param
                .type_annotation
                .as_deref()
                .map(|a| &self.alloc(a).type_annotation);
            self.record_pattern(&param.pattern, annotation);
        }
        if let Some(rest) = &it.params.rest {
            let annotation = rest
                .type_annotation
                .as_deref()
                .map(|a| &self.alloc(a).type_annotation);
            self.record_pattern(&rest.rest.argument, annotation);
        }
        walk_arrow_function_expression(self, it);
        self.binding_scopes.pop();
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        if it.r#type == ClassType::ClassDeclaration
            && let Some(id) = &it.id
        {
            self.record_name(id.name.as_str(), None);
        }
        walk_class(self, it);
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.binding_scopes.push(Vec::new());
        walk_block_statement(self, it);
        self.binding_scopes.pop();
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.binding_scopes.push(Vec::new());
        walk_static_block(self, it);
        self.binding_scopes.pop();
    }

    fn visit_ts_module_block(&mut self, it: &TSModuleBlock<'a>) {
        self.binding_scopes.push(Vec::new());
        walk_ts_module_block(self, it);
        self.binding_scopes.pop();
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        if let Some(test) = &it.test
            && let Some((count, effective)) = case_test_details(test)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3616",
                &format!(
                    "Explicitly specify {count} separate cases that fall through; currently this case clause only works for \"{}\".",
                    source_slice(self.source, effective)
                ),
                test.span(),
            );
        }
        if let Some(next_start) = self.next_case_start(it)
            && let Some(last) = it.consequent.last()
            && !statement_ends_with_jump(last)
            && !self.has_fallthrough_comment(it.span().end, next_start)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S128",
                "End this case with an unconditional break, return, throw, or continue statement.",
                it.span(),
            );
        }
        self.case_depth += 1;
        self.binding_scopes.push(Vec::new());
        walk_switch_case(self, it);
        self.binding_scopes.pop();
        self.case_depth -= 1;
    }

    fn visit_switch_statement(&mut self, it: &SwitchStatement<'a>) {
        if self.case_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1821",
                "Refactor the code to eliminate this nested \"switch\".",
                oxc_span::Span::new(it.span.start, it.span.start.saturating_add(6)),
            );
        }
        if it.cases.iter().all(|case| case.test.is_some()) && !self.is_exhaustive_switch(it) {
            self.sink.emit_span(
                RuleScope::Both,
                "S131",
                "Add a \"default\" clause to this \"switch\" statement.",
                oxc_span::Span::new(it.span.start, it.span.start.saturating_add(6)),
            );
        }
        let last_case_index = it.cases.len().saturating_sub(1);
        for (case_index, case) in it.cases.iter().enumerate() {
            if case.test.is_none() && case_index != last_case_index {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4524",
                    "Move this \"default\" clause to the end of this \"switch\" statement.",
                    oxc_span::Span::new(case.span.start, case.span.start.saturating_add(7)),
                );
            }
        }
        let tested_cases = it.cases.iter().filter(|case| case.test.is_some()).count();
        if tested_cases > MAX_SWITCH_CASES {
            self.sink.emit_span(
                RuleScope::Both,
                "S1479",
                &format!("Reduce the number of non-empty switch cases from {tested_cases} to at most {MAX_SWITCH_CASES}."),
                oxc_span::Span::new(it.span.start, it.span.start.saturating_add(6)),
            );
        }
        if (1..=MAX_TINY_SWITCH_CASES).contains(&tested_cases) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1301",
                "Replace this switch statement with an if statement.",
                it.span(),
            );
        }
        self.switch_cases.push(self.alloc(&it.cases).as_slice());
        walk_switch_statement(self, it);
        self.switch_cases.pop();
    }

    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        for declarator in &it.declarations {
            let annotation = declarator
                .type_annotation
                .as_deref()
                .map(|a| &self.alloc(a).type_annotation);
            self.record_pattern(&declarator.id, annotation);
        }
        walk_variable_declaration(self, it);
    }

    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        self.binding_scopes.push(Vec::new());
        if let Some(param) = &it.param {
            let annotation = param
                .type_annotation
                .as_deref()
                .map(|a| &self.alloc(a).type_annotation);
            self.record_pattern(&param.pattern, annotation);
        }
        walk_catch_clause(self, it);
        self.binding_scopes.pop();
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.binding_scopes.push(Vec::new());
        walk_for_statement(self, it);
        self.binding_scopes.pop();
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.binding_scopes.push(Vec::new());
        walk_for_in_statement(self, it);
        self.binding_scopes.pop();
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.binding_scopes.push(Vec::new());
        walk_for_of_statement(self, it);
        self.binding_scopes.pop();
    }
}

impl<'a> SwitchFlowCollector<'a, '_> {
    /// Records a binding name in the innermost scope; `annotation` is the
    /// declared type when the binding carries one.
    fn record_name(&mut self, name: &'a str, annotation: Option<&'a TSType<'a>>) {
        if let Some(scope) = self.binding_scopes.last_mut() {
            scope.push(Binding { name, annotation });
        }
    }

    /// Records every identifier a binding pattern introduces; destructured
    /// names shadow outer bindings without a usable annotation.
    fn record_pattern(&mut self, pattern: &BindingPattern<'a>, annotation: Option<&'a TSType<'a>>) {
        match pattern {
            BindingPattern::BindingIdentifier(id) => {
                self.record_name(id.name.as_str(), annotation);
            }
            BindingPattern::ObjectPattern(object) => {
                for property in &object.properties {
                    self.record_pattern(&property.value, None);
                }
                if let Some(rest) = &object.rest {
                    self.record_pattern(&rest.argument, None);
                }
            }
            BindingPattern::ArrayPattern(array) => {
                for element in array.elements.iter().flatten() {
                    self.record_pattern(element, None);
                }
                if let Some(rest) = &array.rest {
                    self.record_pattern(&rest.argument, None);
                }
            }
            BindingPattern::AssignmentPattern(assignment) => {
                self.record_pattern(&assignment.left, annotation);
            }
        }
    }

    /// Collects top-level type aliases, enums, and interfaces (including
    /// `export`ed declarations) for `S131` exhaustiveness resolution.
    fn collect_type_decls(&mut self, program: &oxc_ast::ast::Program<'a>) {
        for statement in &program.body {
            let declaration = match statement {
                Statement::ExportDeclaration(export) => Some(&export.declaration),
                _ => statement.as_declaration(),
            };
            match declaration {
                Some(Declaration::TSTypeAliasDeclaration(alias)) => {
                    self.type_decls.insert(
                        alias.id.name.as_str(),
                        TypeDecl::Alias(self.alloc(&alias.type_annotation)),
                    );
                }
                Some(Declaration::TSEnumDeclaration(enumeration)) => {
                    self.type_decls.insert(
                        enumeration.id.name.as_str(),
                        TypeDecl::Enum(self.alloc(&enumeration.body)),
                    );
                }
                Some(Declaration::TSInterfaceDeclaration(interface)) => {
                    self.type_decls.insert(
                        interface.id.name.as_str(),
                        TypeDecl::Interface(self.alloc(&interface.body)),
                    );
                }
                _ => {}
            }
        }
    }

    /// The start offset of the case following `it` in its enclosing switch;
    /// `None` for the last case (nothing can fall through past it) or when
    /// the enclosing case list is unavailable.
    fn next_case_start(&self, it: &SwitchCase<'a>) -> Option<u32> {
        let cases = self.switch_cases.last()?;
        let index = cases.iter().position(|case| case.span() == it.span())?;
        cases.get(index + 1).map(|next| next.span().start)
    }

    /// Whether a `falls? through`-style comment sits between the end of a
    /// case's consequent and the next case (`S128` intentional fallthrough).
    fn has_fallthrough_comment(&self, gap_start: u32, gap_end: u32) -> bool {
        self.comments.iter().any(|comment| {
            comment.token.start >= gap_start
                && comment.token.end <= gap_end
                && is_fallthrough_comment(source_slice(self.source, comment.body))
        })
    }

    /// `S131`: whether the switch provably covers every member of the
    /// discriminant's union or enum type. Only a positive resolution
    /// suppresses the missing-`default` finding.
    fn is_exhaustive_switch(&mut self, it: &SwitchStatement<'a>) -> bool {
        let it = self.alloc(it);
        if it.cases.is_empty() {
            return false;
        }
        let Some(discriminant_type) = self.discriminant_type(&it.discriminant) else {
            return false;
        };
        let Some(members) = self.exhaustible_members(discriminant_type, 0) else {
            return false;
        };
        if members.is_empty() {
            return false;
        }
        let mut keys = Vec::new();
        for case in &it.cases {
            let Some(test) = &case.test else {
                return false;
            };
            let Some(key) = case_key(test) else {
                return false;
            };
            keys.push(key);
        }
        members.iter().all(|member| keys.contains(member))
    }

    /// Resolves the declared type of a switch discriminant expression:
    /// either a bound identifier or a static member chain rooted at one.
    fn discriminant_type(&self, expression: &Expression<'a>) -> Option<&'a TSType<'a>> {
        match unparenthesized(expression) {
            Expression::Identifier(identifier) => self.lookup_binding(identifier.name.as_str()),
            Expression::StaticMemberExpression(member) => {
                let object_type = self.discriminant_type(&member.object)?;
                self.property_type(object_type, member.property.name.as_str(), 0)
            }
            _ => None,
        }
    }

    /// The declared type of `name` in the innermost binding scope that
    /// declares it; `None` when unbound or declared without an annotation.
    fn lookup_binding(&self, name: &str) -> Option<&'a TSType<'a>> {
        for scope in self.binding_scopes.iter().rev() {
            if let Some(binding) = scope.iter().find(|binding| binding.name == name) {
                return binding.annotation;
            }
        }
        None
    }

    /// The type of property `name` on `object_type`, following aliases and
    /// interfaces; `None` when the property cannot be resolved.
    fn property_type(
        &self,
        object_type: &'a TSType<'a>,
        name: &str,
        depth: u32,
    ) -> Option<&'a TSType<'a>> {
        if depth >= MAX_TYPE_RESOLUTION_DEPTH {
            return None;
        }
        match object_type {
            TSType::TSTypeLiteral(literal) => self.object_property_type(&literal.members, name),
            TSType::TSTypeReference(reference) => {
                let TSTypeName::IdentifierReference(id) = &reference.type_name else {
                    return None;
                };
                match self.type_decls.get(id.name.as_str()) {
                    Some(TypeDecl::Alias(target)) => self.property_type(target, name, depth + 1),
                    Some(TypeDecl::Interface(body)) => self.object_property_type(&body.body, name),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The declared type of property `name` among object/interface members.
    fn object_property_type(
        &self,
        members: &[TSSignature<'a>],
        name: &str,
    ) -> Option<&'a TSType<'a>> {
        for member in members {
            let TSSignature::TSPropertySignature(property) = member else {
                continue;
            };
            let property: &'a TSPropertySignature<'a> = self.alloc(property);
            if property_key_name(&property.key) == Some(name)
                && let Some(annotation) = &property.type_annotation
            {
                return Some(&annotation.type_annotation);
            }
        }
        None
    }

    /// The members a union alias or enum type contributes for `S131`
    /// coverage; `None` when the type is not exhaustively enumerable.
    fn exhaustible_members(&self, ts_type: &'a TSType<'a>, depth: u32) -> Option<Vec<CaseKey<'a>>> {
        if depth >= MAX_TYPE_RESOLUTION_DEPTH {
            return None;
        }
        match ts_type {
            TSType::TSUnionType(union) => {
                let mut members = Vec::new();
                for member in &union.types {
                    members.push(self.union_member_key(member, depth)?);
                }
                Some(members)
            }
            TSType::TSTypeReference(reference) => {
                let TSTypeName::IdentifierReference(id) = &reference.type_name else {
                    return None;
                };
                match self.type_decls.get(id.name.as_str()) {
                    Some(TypeDecl::Alias(target)) => self.exhaustible_members(target, depth + 1),
                    Some(TypeDecl::Enum(body)) => Some(
                        body.members
                            .iter()
                            .filter_map(|member| enum_member_name(&member.id))
                            .map(|name| CaseKey::EnumMember(id.name.as_str(), name))
                            .collect(),
                    ),
                    _ => None,
                }
            }
            _ => None,
        }
    }

    /// The `CaseKey` one union member contributes: a literal member maps
    /// directly; a single-member enum reference contributes that member.
    fn union_member_key(&self, member: &'a TSType<'a>, depth: u32) -> Option<CaseKey<'a>> {
        match member {
            TSType::TSLiteralType(literal) => literal_key(&literal.literal),
            TSType::TSTypeReference(_) => {
                let members = self.exhaustible_members(member, depth + 1)?;
                if members.len() == 1 {
                    members.into_iter().next()
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// The static name of an object/interface property key.
fn property_key_name<'a>(key: &oxc_ast::ast::PropertyKey<'a>) -> Option<&'a str> {
    match key {
        oxc_ast::ast::PropertyKey::StaticIdentifier(id) => Some(id.name.as_str()),
        oxc_ast::ast::PropertyKey::StringLiteral(literal) => Some(literal.value.as_str()),
        _ => None,
    }
}

/// The static name of an enum member; computed names do not resolve.
fn enum_member_name<'a>(name: &'a TSEnumMemberName<'a>) -> Option<&'a str> {
    match name {
        TSEnumMemberName::Identifier(id) => Some(id.name.as_str()),
        TSEnumMemberName::String(literal) | TSEnumMemberName::ComputedString(literal) => {
            Some(literal.value.as_str())
        }
        TSEnumMemberName::ComputedTemplateString(_) => None,
    }
}

/// The `CaseKey` of a literal type member.
fn literal_key<'a>(literal: &'a TSLiteral<'a>) -> Option<CaseKey<'a>> {
    match literal {
        TSLiteral::StringLiteral(literal) => Some(CaseKey::Str(literal.value.as_str())),
        TSLiteral::NumericLiteral(literal) => Some(CaseKey::Num(literal.value)),
        TSLiteral::BooleanLiteral(literal) => Some(CaseKey::Bool(literal.value)),
        _ => None,
    }
}

/// The `CaseKey` of a case test expression: a string/number/boolean
/// literal or a `EnumName.Member` static access.
fn case_key<'a>(test: &Expression<'a>) -> Option<CaseKey<'a>> {
    match unparenthesized(test) {
        Expression::StringLiteral(literal) => Some(CaseKey::Str(literal.value.as_str())),
        Expression::NumericLiteral(literal) => Some(CaseKey::Num(literal.value)),
        Expression::BooleanLiteral(literal) => Some(CaseKey::Bool(literal.value)),
        Expression::StaticMemberExpression(member) => {
            let Expression::Identifier(object) = unparenthesized(&member.object) else {
                return None;
            };
            Some(CaseKey::EnumMember(
                object.name.as_str(),
                member.property.name.as_str(),
            ))
        }
        _ => None,
    }
}

/// Whether comment text matches `ESLint`'s default `no-fallthrough` marker
/// pattern `/falls?\s?through/i`.
fn is_fallthrough_comment(text: &str) -> bool {
    let bytes = text.as_bytes();
    for start in 0..bytes.len() {
        let Some(head) = bytes.get(start..start + 4) else {
            break;
        };
        if !head.eq_ignore_ascii_case(b"fall") {
            continue;
        }
        let mut cursor = start + 4;
        if bytes
            .get(cursor)
            .is_some_and(|b| b.eq_ignore_ascii_case(&b's'))
        {
            cursor += 1;
        }
        if bytes.get(cursor).is_some_and(u8::is_ascii_whitespace) {
            cursor += 1;
        }
        if bytes
            .get(cursor..cursor + 7)
            .is_some_and(|tail| tail.eq_ignore_ascii_case(b"through"))
        {
            return true;
        }
    }
    false
}

/// `S1301`: switches with at most this many tested cases are flagged as
/// convertible to `if` (frozen catalog default).
const MAX_TINY_SWITCH_CASES: usize = 2;

// ===== Batch2b: statement-shape and control-flow walks =====
//
// Family A — switch/if-chain flow: `S126`, `S128`, `S131`, `S4524`,
// `S3616`, `S1479`, `S1301`, and `S1821`. Catalog parameters used by
// this section are kept as local constants mirroring the frozen
// catalog defaults.

/// `S1479`: switch statements carrying more cases than this are flagged
/// (frozen catalog default of the `maximum` parameter).
pub(crate) const MAX_SWITCH_CASES: usize = 30;

/// Whether a case test uses a sequence expression or a logical OR
/// (`S3616`).
fn case_test_details(test: &Expression<'_>) -> Option<(usize, oxc_span::Span)> {
    match unparenthesized(test) {
        Expression::SequenceExpression(sequence) => Some((
            sequence.expressions.len(),
            sequence.expressions.last()?.span(),
        )),
        Expression::LogicalExpression(logical) if logical.operator == LogicalOperator::Or => {
            Some((logical_or_operand_count(test), logical.left.span()))
        }
        _ => None,
    }
}

fn logical_or_operand_count(test: &Expression<'_>) -> usize {
    match unparenthesized(test) {
        Expression::LogicalExpression(logical) if logical.operator == LogicalOperator::Or => {
            logical_or_operand_count(&logical.left) + logical_or_operand_count(&logical.right)
        }
        _ => 1,
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_switch_flow(
        ctx.program,
        ctx.source,
        ctx.index,
        ctx.language,
        &ctx.comments,
    )
}

#[cfg(test)]
mod tests {
    use super::MAX_SWITCH_CASES;
    use crate::test_support::*;

    #[test]
    fn s126_flags_else_if_chain_without_final_else() {
        let chained =
            js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else if (c) {\n  h();\n}\n");
        assert_eq!(count_key(&chained, "javascript:S126"), 1);
        let tail_line = chained
            .iter()
            .find(|(key, _)| key == "javascript:S126")
            .map(|(_, line)| *line);
        assert_eq!(tail_line, Some(5));

        let with_final_else =
            js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n} else {\n  h();\n}\n");
        assert_eq!(count_key(&with_final_else, "javascript:S126"), 0);

        // A lone `if` is not a chain.
        let plain_if = js_keys("if (a) {\n  f();\n}\n");
        assert_eq!(count_key(&plain_if, "javascript:S126"), 0);
    }

    #[test]
    fn s128_requires_unconditional_case_termination() {
        let falling_through =
            js_keys("switch (x) {\n  case 1:\n    f();\n  case 2:\n    g();\n    break;\n}\n");
        assert_eq!(count_key(&falling_through, "javascript:S128"), 1);

        let with_break = js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n}\n");
        assert_eq!(count_key(&with_break, "javascript:S128"), 0);

        // Empty consequents (case grouping) and block-wrapped jumps stay
        // clean.
        let grouped = js_keys("switch (x) {\n  case 1:\n  case 2:\n    f();\n    break;\n}\n");
        assert_eq!(count_key(&grouped, "javascript:S128"), 0);

        let via_block_return = js_keys(
            "function f(x) {\n  switch (x) {\n    case 1:\n      { g(); return; }\n  }\n}\n",
        );
        assert_eq!(count_key(&via_block_return, "javascript:S128"), 0);
    }

    #[test]
    fn s131_flags_switch_without_default_case() {
        let source = "switch (x) {\n  case 1:\n    break;\n}\n";
        let missing = js_keys(source);
        assert_eq!(count_key(&missing, "javascript:S131"), 1);

        let with_default =
            js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&with_default, "javascript:S131"), 0);

        let typescript = findings(source, JstsLanguage::TypeScript);
        assert_eq!(count_key(&typescript, "typescript:S131"), 1);
        assert_eq!(count_key(&typescript, "javascript:S131"), 0);
    }

    #[test]
    fn s4524_flags_default_case_not_in_last_position() {
        let misplaced = js_keys("switch (x) {\n  default:\n    break;\n  case 1:\n    break;\n}\n");
        assert_eq!(count_key(&misplaced, "javascript:S4524"), 1);

        let last = js_keys("switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&last, "javascript:S4524"), 0);
    }

    #[test]
    fn s3616_flags_sequence_and_logical_or_case_tests() {
        let sequence = js_keys("switch (x) {\n  case (a(), b):\n    break;\n}\n");
        assert_eq!(count_key(&sequence, "javascript:S3616"), 1);

        let logical_or = js_keys("switch (x) {\n  case a || b:\n    break;\n}\n");
        assert_eq!(count_key(&logical_or, "javascript:S3616"), 1);

        // Logical AND tests are ordinary expressions.
        let logical_and = js_keys("switch (x) {\n  case a && b:\n    break;\n}\n");
        assert_eq!(count_key(&logical_and, "javascript:S3616"), 0);
    }

    #[test]
    fn s1479_flags_switches_with_more_than_thirty_cases() {
        let build = |case_count: usize| {
            let mut source = String::from("switch (x) {\n");
            for case_number in 0..case_count {
                let _ = write!(source, "  case {case_number}:\n    break;\n");
            }
            source.push_str("}\n");
            source
        };

        let at_limit = js_keys(&build(MAX_SWITCH_CASES));
        assert_eq!(count_key(&at_limit, "javascript:S1479"), 0);

        let over_limit = js_keys(&build(MAX_SWITCH_CASES + 1));
        assert_eq!(count_key(&over_limit, "javascript:S1479"), 1);
    }

    #[test]
    fn s1301_flags_switches_convertible_to_if() {
        let two_cases = js_keys(
            "switch (x) {\n  case 1:\n    f();\n    break;\n  case 2:\n    g();\n    break;\n  default:\n    break;\n}\n",
        );
        assert_eq!(count_key(&two_cases, "javascript:S1301"), 1);

        let one_case =
            js_keys("switch (x) {\n  case 1:\n    f();\n    break;\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&one_case, "javascript:S1301"), 1);

        let mut three_cases_source = String::from("switch (x) {\n  default:\n    break;\n");
        for case_number in 0..3 {
            let _ = write!(three_cases_source, "  case {case_number}:\n    break;\n");
        }
        three_cases_source.push_str("}\n");
        let three_cases = js_keys(&three_cases_source);
        assert_eq!(count_key(&three_cases, "javascript:S1301"), 0);
    }

    #[test]
    fn s1821_flags_switch_nested_inside_case_consequent() {
        let nested = js_keys(
            "switch (x) {\n  case 1:\n    switch (y) {\n      case 2:\n        break;\n    }\n    break;\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S1821"), 1);
        let inner_line = nested
            .iter()
            .find(|(key, _)| key == "javascript:S1821")
            .map(|(_, line)| *line);
        assert_eq!(inner_line, Some(3));

        // Sibling switches at the top level stay clean.
        let sibling = js_keys(
            "switch (x) {\n  case 1:\n    break;\n}\nswitch (y) {\n  default:\n    break;\n}\n",
        );
        assert_eq!(count_key(&sibling, "javascript:S1821"), 0);
    }
    #[test]
    fn s126_nested_if_is_not_a_chain() {
        let nested = js_keys("if (a) {\n  if (b) {\n    f();\n  }\n}\n");
        assert_eq!(count_key(&nested, "javascript:S126"), 0);
    }

    #[test]
    fn s128_return_and_throw_terminate_cases() {
        let via_return =
            js_keys("function f(x) {\n  switch (x) {\n    case 1:\n      return g();\n  }\n}\n");
        assert_eq!(count_key(&via_return, "javascript:S128"), 0);

        let via_throw = js_keys(
            "function f(x) {\n  switch (x) {\n    case 1:\n      throw new Error('bad');\n  }\n}\n",
        );
        assert_eq!(count_key(&via_throw, "javascript:S128"), 0);
    }

    #[test]
    fn s131_default_only_switch_passes_and_stays_last() {
        let default_only = js_keys("switch (x) {\n  default:\n    break;\n}\n");
        assert_eq!(count_key(&default_only, "javascript:S131"), 0);
        assert_eq!(count_key(&default_only, "javascript:S4524"), 0);
    }

    #[test]
    fn s3616_bitwise_and_case_test_passes() {
        let bitwise = js_keys("switch (x) {\n  case a & b:\n    break;\n}\n");
        assert_eq!(count_key(&bitwise, "javascript:S3616"), 0);
    }

    #[test]
    fn s4524_default_between_cases_still_flags() {
        let middle = js_keys(
            "switch (x) {\n  case 1:\n    break;\n  default:\n    break;\n  case 2:\n    break;\n}\n",
        );
        assert_eq!(count_key(&middle, "javascript:S4524"), 1);
    }

    #[test]
    fn s1301_two_cases_without_default_remain_convertible() {
        let no_default = js_keys(
            "switch (x) {\n  case 1:\n    f();\n    break;\n  case 2:\n    g();\n    break;\n}\n",
        );
        assert_eq!(count_key(&no_default, "javascript:S1301"), 1);
    }

    #[test]
    fn s1821_deeply_nested_switches_flag_per_level() {
        let deep = js_keys(
            "switch (x) {\n  case 1:\n    switch (y) {\n      case 2:\n        switch (z) {\n          case 3:\n            break;\n        }\n        break;\n    }\n    break;\n}\n",
        );
        assert_eq!(count_key(&deep, "javascript:S1821"), 2);
    }

    #[test]
    fn s128_last_case_needs_no_terminating_statement() {
        // Nothing can fall through past the last case.
        let last_default = js_keys(
            "function f(state) {\n    switch (state) {\n        case 0:\n            state = 1;\n            break;\n        default:\n            state = 0;\n    }\n    return state;\n}\n",
        );
        assert_eq!(count_key(&last_default, "javascript:S128"), 0);

        // A non-last case without a jump still flags; the last default
        // stays silent.
        let mixed = js_keys(
            "function f(state) {\n    switch (state) {\n        case 0:\n            state = 1;\n        default:\n            state = 0;\n    }\n    return state;\n}\n",
        );
        assert_eq!(count_key(&mixed, "javascript:S128"), 1);
    }

    #[test]
    fn s128_falls_through_comment_marks_intentional_fallthrough() {
        let annotated = ts_keys(
            "function f(ch: number): number[] {\n    const result: number[] = [];\n    let pos = 0;\n    switch (ch) {\n        case 13:\n            if (ch === 13) {\n                pos++;\n            }\n        // falls through\n        case 10:\n            result.push(pos);\n            break;\n        default:\n            break;\n    }\n    return result;\n}\n",
        );
        assert_eq!(count_key(&annotated, "typescript:S128"), 0);

        // The same switch without the marker still flags.
        let bare = ts_keys(
            "function f(ch: number): number[] {\n    const result: number[] = [];\n    let pos = 0;\n    switch (ch) {\n        case 13:\n            if (ch === 13) {\n                pos++;\n            }\n        case 10:\n            result.push(pos);\n            break;\n        default:\n            break;\n    }\n    return result;\n}\n",
        );
        assert_eq!(count_key(&bare, "typescript:S128"), 1);

        // Block comments and the `fallthrough` spelling work too; a doubled
        // space exceeds the pattern's single optional whitespace.
        let variants = js_keys(
            "switch (x) {\n  case 1:\n    f();\n    /* fallthrough */\n  case 2:\n    g();\n    // falls  through\n  case 3:\n    h();\n    break;\n}\n",
        );
        assert_eq!(count_key(&variants, "javascript:S128"), 1);

        // A comment inside the consequent (before its last statement) does
        // not mark the fallthrough.
        let inside = js_keys(
            "switch (x) {\n  case 1:\n    // falls through\n    f();\n  case 2:\n    g();\n    break;\n}\n",
        );
        assert_eq!(count_key(&inside, "javascript:S128"), 1);
    }

    #[test]
    fn s131_exhaustive_union_switch_needs_no_default() {
        let exhaustive = ts_keys(
            "type Kind = \"primitive\" | \"kind\" | \"node\" | \"alias\" | \"list\" | \"typeParameter\" | \"union\";\nfunction key(type: { kind: Kind }): string {\n    switch (type.kind) {\n        case \"primitive\": return `primitive:${type.kind}`;\n        case \"kind\": return `kind:${type.kind}`;\n        case \"node\": return `node:${type.kind}`;\n        case \"alias\": return `alias:${type.kind}`;\n        case \"list\": return `list:${type.kind}`;\n        case \"typeParameter\": return `tp:${type.kind}`;\n        case \"union\": return `union:${type.kind}`;\n    }\n}\n",
        );
        assert_eq!(count_key(&exhaustive, "typescript:S131"), 0);

        // Missing one union member still requires a default.
        let missing = ts_keys(
            "type Kind = \"a\" | \"b\" | \"c\";\nfunction key(type: { kind: Kind }): string {\n    switch (type.kind) {\n        case \"a\": return \"a\";\n        case \"b\": return \"b\";\n    }\n}\n",
        );
        assert_eq!(count_key(&missing, "typescript:S131"), 1);

        // An enum discriminant covered by `Enum.Member` cases is exempt.
        let enum_switch = ts_keys(
            "enum Color { Red, Green }\nfunction paint(c: Color): string {\n    switch (c) {\n        case Color.Red: return \"r\";\n        case Color.Green: return \"g\";\n    }\n}\n",
        );
        assert_eq!(count_key(&enum_switch, "typescript:S131"), 0);

        // A discriminant whose type cannot be resolved still flags.
        let unresolved = ts_keys(
            "function key(type: { kind: string }): string {\n    switch (type.kind) {\n        case \"a\": return \"a\";\n    }\n}\n",
        );
        assert_eq!(count_key(&unresolved, "typescript:S131"), 1);

        // An unannotated binding does not resolve to a union.
        let unannotated = ts_keys(
            "type Kind = \"a\" | \"b\";\nfunction key(type): string {\n    switch (type) {\n        case \"a\": return \"a\";\n        case \"b\": return \"b\";\n    }\n}\n",
        );
        assert_eq!(count_key(&unannotated, "typescript:S131"), 1);

        // A shadowed binding resolves to the shadow, not the outer param.
        let shadowed = ts_keys(
            "type Kind = \"a\" | \"b\";\nfunction key(type: Kind): string {\n    {\n        let type = other();\n        switch (type) {\n            case \"a\": return \"a\";\n            case \"b\": return \"b\";\n        }\n    }\n}\n",
        );
        assert_eq!(count_key(&shadowed, "typescript:S131"), 1);
    }
}
