// Family walker for 'statement' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope, source_slice, static_property_name};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BlockStatement, CallExpression, ContinueStatement, DebuggerStatement, EmptyStatement,
    Expression, ExpressionStatement, Function, FunctionBody, FunctionType, IfStatement,
    ImportDeclaration, ImportDeclarationSpecifier, LabeledStatement, NewExpression,
    ReturnStatement, Statement, StaticBlock, SwitchCase, ThrowStatement, VariableDeclaration,
    VariableDeclarationKind, WithStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_block_statement, walk_expression_statement, walk_function, walk_function_body,
    walk_if_statement, walk_import_declaration, walk_labeled_statement, walk_program,
    walk_return_statement, walk_statement, walk_static_block, walk_switch_case,
    walk_throw_statement, walk_variable_declaration, walk_with_statement,
};
use oxc_span::{GetSpan, Span};

fn check_statement_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = StatementCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        last_import: None,
        statement_scopes: Vec::new(),
        s1199_list_kinds: Vec::new(),
        s1199_candidates: Vec::new(),
        s1199_active_blocks: Vec::new(),
        strict_scopes: Vec::new(),
        current_statement_is_if: false,
        if_parent_is_if: false,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Statement-list parent kinds used by the `S1199` lone-block check.
#[derive(Clone, Copy, PartialEq, Eq)]
enum S1199ListKind {
    Program,
    // OXC stores directives outside the function's statement list.
    FunctionBody { has_directives: bool },
    Block,
    StaticBlock,
    SwitchCase,
}

/// Statement-level batch rules in one traversal: `S909`, `S1119`, `S1321`,
/// `S1525`, `S108`, `S1199`, `S121`, `S2681`, `S6660`, `S1066`, `S6836`,
/// `S1116`, `S3696`, `S3984`, `S1848`, `S1154`, `S2201`, `S1126`, `S3504`,
/// `S2208`, `S6859`, and `S3863`.
struct StatementCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
    last_import: Option<(String, u32)>,
    /// Active statement lists used to find the return immediately following
    /// an if statement without reparsing source text.
    statement_scopes: Vec<&'a [Statement<'a>]>,
    /// Parallel list kinds used to identify genuine lone-block parents.
    s1199_list_kinds: Vec<S1199ListKind>,
    /// Candidate blocks are removed when a direct lexical declaration gives
    /// them a legitimate scope.
    s1199_candidates: Vec<(Span, S1199ListKind)>,
    s1199_active_blocks: Vec<Span>,
    /// Strictness inherited through all OXC scopes, for strict function
    /// declarations (which also create a lexical scope).
    strict_scopes: Vec<bool>,
    /// Tracks whether the current statement is a direct child of an if.
    current_statement_is_if: bool,
    if_parent_is_if: bool,
}

impl<'a> Visit<'a> for StatementCollector<'a, '_> {
    fn enter_scope(
        &mut self,
        flags: oxc_syntax::scope::ScopeFlags,
        _: &std::cell::Cell<Option<oxc_syntax::scope::ScopeId>>,
    ) {
        let inherited = self.strict_scopes.last().copied().unwrap_or(false);
        self.strict_scopes.push(inherited || flags.is_strict_mode());
    }

    fn leave_scope(&mut self) {
        self.strict_scopes.pop();
    }

    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        self.statement_scopes.push(self.alloc(&it.body).as_slice());
        self.s1199_list_kinds.push(S1199ListKind::Program);
        walk_program(self, it);
        self.s1199_list_kinds.pop();
        self.statement_scopes.pop();
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: oxc_syntax::scope::ScopeFlags) {
        if matches!(it.r#type, FunctionType::FunctionDeclaration)
            && (self.strict_scopes.last().copied().unwrap_or(false)
                || flags.is_strict_mode()
                || it
                    .body
                    .as_ref()
                    .is_some_and(|body| body.has_use_strict_directive()))
        {
            self.mark_lone_block();
        }
        walk_function(self, it, flags);
    }

    fn visit_statement(&mut self, it: &Statement<'a>) {
        let previous_current = self.current_statement_is_if;
        let previous_parent = self.if_parent_is_if;
        self.if_parent_is_if = previous_current && matches!(it, Statement::IfStatement(_));
        self.current_statement_is_if = matches!(it, Statement::IfStatement(_));
        if matches!(it, Statement::ClassDeclaration(_)) {
            self.mark_lone_block();
        }
        walk_statement(self, it);
        self.current_statement_is_if = previous_current;
        self.if_parent_is_if = previous_parent;
    }

    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S909",
            "Unexpected use of continue statement.",
            it.span(),
        );
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1119",
            "Refactor the code to remove this label and the need for it.",
            it.label.span(),
        );
        walk_labeled_statement(self, it);
    }

    fn visit_with_statement(&mut self, it: &WithStatement<'a>) {
        self.sink.emit_span(
            RuleScope::JsOnly,
            "S1321",
            "Unexpected use of 'with' statement.",
            it.span(),
        );
        walk_with_statement(self, it);
    }

    fn visit_debugger_statement(&mut self, it: &DebuggerStatement) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1525",
            "Unexpected 'debugger' statement.",
            it.span,
        );
    }

    fn visit_empty_statement(&mut self, it: &EmptyStatement) {
        self.sink
            .emit_span(RuleScope::Both, "S1116", "Unnecessary semicolon.", it.span);
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        let parent_kind = self.s1199_parent_kind(it);
        let fallback = matches!(
            parent_kind,
            Some(
                S1199ListKind::Block
                    | S1199ListKind::StaticBlock
                    | S1199ListKind::FunctionBody {
                        has_directives: false
                    }
            )
        ) && self
            .statement_scopes
            .last()
            .is_some_and(|statements| statements.len() == 1);

        if let Some(parent_kind) = parent_kind {
            self.s1199_candidates.push((it.span(), parent_kind));
        }
        if it.body.is_empty() {
            self.check_empty_block(it);
        }
        self.s1199_active_blocks.push(it.span());
        self.statement_scopes.push(self.alloc(&it.body).as_slice());
        self.s1199_list_kinds.push(S1199ListKind::Block);
        walk_block_statement(self, it);
        self.s1199_list_kinds.pop();
        self.statement_scopes.pop();
        self.s1199_active_blocks.pop();

        let reported_candidate = self
            .s1199_candidates
            .last()
            .is_some_and(|(span, _)| *span == it.span());
        if reported_candidate {
            let (_, parent_kind) = self.s1199_candidates.pop().expect("candidate was present");
            let message = match parent_kind {
                S1199ListKind::Block
                | S1199ListKind::StaticBlock
                | S1199ListKind::FunctionBody { .. } => "Nested block is redundant.",
                S1199ListKind::Program | S1199ListKind::SwitchCase => "Block is redundant.",
            };
            self.sink
                .emit_span(RuleScope::Both, "S1199", message, it.span());
        } else if fallback {
            self.sink.emit_span(
                RuleScope::Both,
                "S1199",
                "Nested block is redundant.",
                it.span(),
            );
        }
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        if it.body.is_empty() {
            self.check_empty_block_span(it.span());
        }
        let saved_current = self.current_statement_is_if;
        let saved_parent = self.if_parent_is_if;
        self.current_statement_is_if = false;
        self.if_parent_is_if = false;
        self.statement_scopes.push(self.alloc(&it.body).as_slice());
        self.s1199_list_kinds.push(S1199ListKind::StaticBlock);
        walk_static_block(self, it);
        self.s1199_list_kinds.pop();
        self.statement_scopes.pop();
        self.if_parent_is_if = saved_parent;
        self.current_statement_is_if = saved_current;
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        let saved_current = self.current_statement_is_if;
        let saved_parent = self.if_parent_is_if;
        self.current_statement_is_if = false;
        self.if_parent_is_if = false;
        self.statement_scopes
            .push(self.alloc(&it.statements).as_slice());
        self.s1199_list_kinds.push(S1199ListKind::FunctionBody {
            has_directives: !it.directives.is_empty(),
        });
        walk_function_body(self, it);
        self.s1199_list_kinds.pop();
        self.statement_scopes.pop();
        self.if_parent_is_if = saved_parent;
        self.current_statement_is_if = saved_current;
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.check_s1126_if(it);
        self.check_control_structure_body(&it.consequent);
        if let Some(alternate) = &it.alternate
            && !matches!(alternate, Statement::IfStatement(_))
        {
            self.check_control_structure_body(alternate);
        }
        self.check_collapsible_if(it);
        walk_if_statement(self, it);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        if let Some(first) = it.consequent.first() {
            self.check_case_leading_declaration(first);
        }
        self.statement_scopes
            .push(self.alloc(&it.consequent).as_slice());
        self.s1199_list_kinds.push(S1199ListKind::SwitchCase);
        walk_switch_case(self, it);
        self.s1199_list_kinds.pop();
        self.statement_scopes.pop();
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        match &it.expression {
            Expression::NewExpression(new) => {
                self.check_discarded_new(new, it.span());
            }
            Expression::CallExpression(call) => {
                self.check_discarded_pure_call(call);
            }
            _ => {}
        }
        walk_expression_statement(self, it);
    }

    fn visit_throw_statement(&mut self, it: &ThrowStatement<'a>) {
        if matches!(
            &it.argument,
            Expression::StringLiteral(_)
                | Expression::NumericLiteral(_)
                | Expression::BooleanLiteral(_)
                | Expression::NullLiteral(_)
                | Expression::TemplateLiteral(_)
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3696",
                "Expected an error object to be thrown.",
                it.span(),
            );
        }
        walk_throw_statement(self, it);
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let Some(Expression::ConditionalExpression(conditional)) = &it.argument
            && let (Expression::BooleanLiteral(consequent), Expression::BooleanLiteral(alternate)) =
                (&conditional.consequent, &conditional.alternate)
            && consequent.value != alternate.value
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S1126",
                "Return the condition directly instead of this ternary.",
                conditional.span(),
            );
        }
        walk_return_statement(self, it);
    }

    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if it.kind == VariableDeclarationKind::Var {
            let span = it.declarations.first().map_or(it.span(), |declaration| {
                Span::new(it.span.start, declaration.id.span().end)
            });
            self.sink.emit_span(
                RuleScope::Both,
                "S3504",
                "Unexpected var, use let or const instead.",
                span,
            );
        } else {
            self.mark_lone_block();
        }
        walk_variable_declaration(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.check_namespace_import(it);
        self.check_absolute_import_path(it);
        self.check_duplicate_import(it);
        walk_import_declaration(self, it);
    }
}

impl StatementCollector<'_, '_> {
    fn s1199_parent_kind(&self, it: &BlockStatement<'_>) -> Option<S1199ListKind> {
        let statements = self.statement_scopes.last()?;
        let kind = *self.s1199_list_kinds.last()?;
        let is_direct_child = statements.iter().any(|statement| {
            matches!(
                statement,
                Statement::BlockStatement(block) if block.span() == it.span()
            )
        });
        if !is_direct_child {
            return None;
        }
        // ESLint intentionally keeps a block that is the sole statement of a
        // switch case: the case itself already supplies the statement scope.
        if kind == S1199ListKind::SwitchCase && statements.len() == 1 {
            return None;
        }
        Some(kind)
    }

    fn mark_lone_block(&mut self) {
        let Some(active_block) = self.s1199_active_blocks.last().copied() else {
            return;
        };
        if self
            .s1199_candidates
            .last()
            .is_some_and(|(candidate, _)| *candidate == active_block)
        {
            self.s1199_candidates.pop();
        }
    }

    fn boolean_return(statement: &Statement<'_>) -> Option<bool> {
        match statement {
            Statement::ReturnStatement(return_statement) => {
                match return_statement.argument.as_ref() {
                    Some(Expression::BooleanLiteral(literal)) => Some(literal.value),
                    _ => None,
                }
            }
            Statement::BlockStatement(block) if block.body.len() == 1 => {
                Self::boolean_return(&block.body[0])
            }
            _ => None,
        }
    }

    fn check_s1126_if(&mut self, statement: &IfStatement<'_>) {
        if self.if_parent_is_if {
            return;
        }
        let Some(consequent) = Self::boolean_return(&statement.consequent) else {
            return;
        };
        let alternate = if let Some(alternate) = statement.alternate.as_ref() {
            let Some(value) = Self::boolean_return(alternate) else {
                return;
            };
            value
        } else {
            let Some(siblings) = self.statement_scopes.last() else {
                return;
            };
            let Some(index) = siblings
                .iter()
                .position(|sibling| sibling.span() == statement.span())
            else {
                return;
            };
            if siblings[..index].iter().any(|sibling| {
                matches!(
                    sibling,
                    Statement::IfStatement(previous)
                        if Self::boolean_return(&previous.consequent).is_some()
                )
            }) {
                return;
            }
            let Some(next) = siblings.get(index + 1) else {
                return;
            };
            let Some(value) = Self::boolean_return(next) else {
                return;
            };
            value
        };
        if consequent == alternate {
            return;
        }
        self.sink.emit_span(
            RuleScope::JsOnly,
            "S1126",
            "Replace this if-then-else flow by a single return statement.",
            statement.span(),
        );
    }
    /// `S108`: empty blocks are flagged unless their span interior still
    /// holds comments the parser dropped.
    fn check_empty_block(&mut self, block: &BlockStatement<'_>) {
        self.check_empty_block_span(block.span());
    }

    fn check_empty_block_span(&mut self, span: Span) {
        let interior = Span::new(span.start + 1, span.end.saturating_sub(1));
        let interior_text = source_slice(self.source, interior);
        if interior_text.trim().is_empty() {
            self.sink
                .emit_span(RuleScope::Both, "S108", "Empty block statement.", span);
        }
    }

    /// `S121` (unbraced control-structure bodies) and `S2681` (the same
    /// bodies spanning several lines).
    fn check_control_structure_body(&mut self, body: &Statement<'_>) {
        if matches!(body, Statement::BlockStatement(_)) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S121",
            "Expected { after 'if' condition.",
            body.span(),
        );
        if self.sink.index.covered_lines(body.span()).count() > 1 {
            self.sink.emit_span(
                RuleScope::Both,
                "S2681",
                "Put this unbraced statement on one line or use curly braces.",
                body.span(),
            );
        }
    }

    /// `S1066`: an `if` whose consequent block holds exactly one `if`.
    /// `S6660`: an `else` block holding exactly one `if`.
    fn check_collapsible_if(&mut self, it: &IfStatement<'_>) {
        if let Statement::BlockStatement(block) = &it.consequent
            && block.body.len() == 1
            && matches!(&block.body[0], Statement::IfStatement(_))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1066",
                "Merge this if statement with the nested one.",
                Span::new(it.span.start, it.span.start.saturating_add(2)),
            );
        }
        if let Some(Statement::BlockStatement(block)) = &it.alternate
            && block.body.len() == 1
            && let Statement::IfStatement(inner) = &block.body[0]
            && inner.alternate.is_none()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6660",
                "Collapse this \"else\" block into an \"else if\".",
                block.span(),
            );
        }
    }

    /// `S6836`: lexical declarations leading a switch case.
    fn check_case_leading_declaration(&mut self, first: &Statement<'_>) {
        let lexical = match first {
            Statement::VariableDeclaration(declaration) => {
                declaration.kind != VariableDeclarationKind::Var
            }
            Statement::FunctionDeclaration(_) | Statement::ClassDeclaration(_) => true,
            _ => false,
        };
        if lexical {
            self.sink.emit_span(
                RuleScope::Both,
                "S6836",
                "Wrap this declaration in a block.",
                first.span(),
            );
        }
    }

    /// `S1848` (discarded instantiation) and `S3984` (discarded `Error`).
    fn check_discarded_new(&mut self, new: &NewExpression<'_>, _statement_span: Span) {
        let name = source_slice(self.source, new.callee.span());
        self.sink.emit_span(
            RuleScope::Both,
            "S1848",
            &format!("Either remove this useless object instantiation of \"{name}\" or use it."),
            Span::new(new.span.start, new.callee.span().end),
        );
        if name.ends_with("Error") || name.ends_with("Exception") {
            self.sink.emit_span(
                RuleScope::Both,
                "S3984",
                "Throw this error or remove this useless statement.",
                new.span(),
            );
        }
    }

    /// `S1154` and `S2201`: bare statements calling known side-effect-free
    /// APIs.
    fn check_discarded_pure_call(&mut self, call: &CallExpression<'_>) {
        let Some(member) = call.callee.as_member_expression() else {
            return;
        };
        let Some(property) = static_property_name(member) else {
            return;
        };
        let rule = match (
            PURE_STRING_METHODS.contains(&property),
            SIDE_EFFECT_FREE_APIS.contains(&property),
        ) {
            (true, _) => "S1154",
            (false, true) => "S2201",
            (false, false) => return,
        };
        self.sink.emit_span(
            RuleScope::Both,
            rule,
            "Remove this useless statement; the result is discarded.",
            call.span(),
        );
    }

    /// `S2208`: `import * as` namespace specifiers.
    fn check_namespace_import(&mut self, it: &ImportDeclaration<'_>) {
        if let Some(specifiers) = &it.specifiers {
            for specifier in specifiers {
                if matches!(
                    specifier,
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(_)
                ) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S2208",
                        "Explicitly import the specific member needed.",
                        specifier.span(),
                    );
                }
            }
        }
    }

    /// `S6859`: absolute import paths.
    fn check_absolute_import_path(&mut self, it: &ImportDeclaration<'_>) {
        if it.source.value.starts_with('/') {
            self.sink.emit_span(
                RuleScope::Both,
                "S6859",
                "Remove the leading slash from this import path.",
                it.source.span(),
            );
        }
    }

    /// `S3863`: adjacent imports of the same module (adjacency approximated
    /// by line distance of at most one line).
    fn check_duplicate_import(&mut self, it: &ImportDeclaration<'_>) {
        let module = it.source.value.to_string();
        let start_line = self.sink.index.pos(it.span().start).line;
        if let Some((last_module, last_end_line)) = &self.last_import
            && *last_module == module
            && start_line <= last_end_line + 1
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3863",
                &format!("'{}' import is duplicated.", it.source.value),
                it.span(),
            );
        }
        self.last_import = Some((module, self.sink.index.pos(it.span().end).line));
    }
}

/// Known side-effect-free array/string APIs whose bare statement call `S2201`
/// flags (callbacks are assumed pure in this subset).
const SIDE_EFFECT_FREE_APIS: [&str; 20] = [
    "concat",
    "every",
    "filter",
    "find",
    "findIndex",
    "flat",
    "flatMap",
    "includes",
    "indexOf",
    "join",
    "lastIndexOf",
    "map",
    "reduce",
    "reduceRight",
    "slice",
    "some",
    "keys",
    "values",
    "entries",
    "at",
];

/// Known-pure string methods whose bare statement call `S1154` flags.
const PURE_STRING_METHODS: [&str; 15] = [
    "toUpperCase",
    "toLowerCase",
    "trim",
    "trimStart",
    "trimEnd",
    "split",
    "concat",
    "slice",
    "substring",
    "substr",
    "charAt",
    "charCodeAt",
    "indexOf",
    "lastIndexOf",
    "includes",
];

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_statement_rules(ctx.program, ctx.source, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn one_statement_per_line_flags_only_second_onwards_including_nesting() {
        let source = "\
let a = 1; let b = 2;
function f() {
  let c = 3; let d = 4;
}
if (a) { g(); h(); }
while (false) { i(); j(); }
try { k(); l(); } catch { m(); n(); }
";
        let report = js(source);
        let s122: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S122"))
            .collect();
        // One issue per additional statement sharing a line: top level, the
        // function body, the `if` block, the `while` block, and two in the
        // try/catch line (`l()` and `n()`).
        assert_eq!(s122.len(), 6);
        assert!(
            s122.iter()
                .all(|issue| issue.message == "This line has 2 statements. Maximum allowed is 1.")
        );
        assert_eq!(
            s122[0].range,
            hoonarqube_ir::Range {
                start: pos(1, 11),
                end: pos(1, 21),
            }
        );
    }

    #[test]
    fn switch_and_loop_single_statement_bodies_are_walked() {
        let source = "\
for (let i = 0; i < 1; i++) o(); p();
switch (x) { case 1: q(); r(); }
label: s(); t();
with (obj) { u(); v(); }
";
        let report = js(source);
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S122"))
                .count(),
            4
        );
    }

    #[test]
    fn multiline_block_comment_between_statements_is_fully_counted() {
        let source = "let a = 1;\n/* one\ntwo\nthree */\nlet b = 2;\n";
        let report = js(source);
        assert_eq!(report.metrics.comment_lines, 3);
        assert_eq!(report.metrics.code_lines, 2);
    }

    #[test]
    fn statement_level_batch_rules_fire() {
        let source = "\
debugger;
with (o) { }
var v = 1;
import * as ns from 'm';
import x from '/abs';
throw 'oops';
new Error('x');
;;
";
        let flagged = js_keys(source);
        for key in [
            "S1525", "S1321", "S3504", "S2208", "S6859", "S3696", "S3984", "S1848", "S1116",
        ] {
            assert!(
                count_key(&flagged, &format!("javascript:{key}")) >= 1,
                "expected {key}"
            );
        }
    }

    #[test]
    fn control_structure_batch_rules_fire() {
        let source = "\
if (a) b();
else { if (c) d(); }
if (e) { if (f) g(); }
switch (s) { case 1: let z = 2; }
while (x) continue;
";
        let flagged = js_keys(source);
        for key in [
            "javascript:S121",
            "javascript:S6660",
            "javascript:S1066",
            "javascript:S6836",
            "javascript:S909",
        ] {
            assert!(count_key(&flagged, key) >= 1, "expected {key}");
        }
    }

    #[test]
    fn statements_after_jumps_are_unreachable() {
        let source = "\
function f() {
  return 1;
  g();
}
function clean() {
  if (a) {
    return 1;
  }
  g();
}
";
        let report = js(source);
        let s1763: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1763"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s1763, vec![3]);
    }
    #[test]
    fn s1119_flags_any_label_and_unlabeled_jumps_pass() {
        let flagged = js_keys("outer: while (a) {\n  break outer;\n}\n");
        assert_eq!(count_key(&flagged, "javascript:S1119"), 1);

        let unlabeled = js_keys("while (a) {\n  break;\n}\n");
        assert_eq!(count_key(&unlabeled, "javascript:S1119"), 0);
    }

    #[test]
    fn s1199_matches_lone_block_context_and_lexical_scope_rules() {
        let nested = js_keys("{\n  {\n    g();\n  }\n}\n");
        assert_eq!(count_key(&nested, "javascript:S1199"), 2);

        let function_body = js_keys("function work() {\n  {\n    prepare();\n  }\n}\n");
        assert_eq!(count_key(&function_body, "javascript:S1199"), 1);

        let control_body = js_keys("function work() {\n  if (ready) {\n    prepare();\n  }\n}\n");
        assert_eq!(count_key(&control_body, "javascript:S1199"), 0);

        let lexical_scope = js_keys(
            "function work() {\n  {\n    let value = prepare();\n    use(value);\n  }\n}\n",
        );
        assert_eq!(count_key(&lexical_scope, "javascript:S1199"), 1);

        let class_scope = js_keys("function work() {\n  {\n    class Local {}\n  }\n}\n");
        assert_eq!(count_key(&class_scope, "javascript:S1199"), 1);

        let required_lexical_scope = js_keys(
            "function work() {\n  const value = prepare();\n  {\n    let value = prepare();\n    use(value);\n  }\n  use(value);\n}\n",
        );
        assert_eq!(count_key(&required_lexical_scope, "javascript:S1199"), 0);

        let directive_and_lexical_scope = js_keys(
            "function work() {\n  'use strict';\n  {\n    let value = prepare();\n    use(value);\n  }\n}\n",
        );
        assert_eq!(
            count_key(&directive_and_lexical_scope, "javascript:S1199"),
            0
        );
    }

    #[test]
    fn s1199_uses_the_owning_message_and_full_block_range() {
        let report = js("function work() {\n  {\n    prepare();\n  }\n}\n");
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S1199")
            .expect("nested block should be reported");
        assert_eq!(issue.message, "Nested block is redundant.");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.start.column, 2);
        assert_eq!(issue.range.end.line, 4);
        assert_eq!(issue.range.end.column, 3);
    }

    #[test]
    fn s1126_flags_boolean_ternary_returns_js_only() {
        let boolean = js_keys("function f(c) {\n  return c ? true : false;\n}\n");
        assert_eq!(count_key(&boolean, "javascript:S1126"), 1);

        let numeric = js_keys("function f(c) {\n  return c ? 1 : 2;\n}\n");
        assert_eq!(count_key(&numeric, "javascript:S1126"), 0);

        let typescript = ts_keys("function f(c) {\n  return c ? true : false;\n}\n");
        assert_eq!(count_key(&typescript, "typescript:S1126"), 0);
    }

    #[test]
    fn s1154_and_s2201_flag_discarded_pure_results_consumed_calls_pass() {
        let flagged = js_keys("text.toUpperCase();\nitems.filter(isEven);\n");
        assert_eq!(count_key(&flagged, "javascript:S1154"), 1);
        assert_eq!(count_key(&flagged, "javascript:S2201"), 1);

        let consumed =
            js_keys("const upper = text.toUpperCase();\nconst evens = items.filter(isEven);\n");
        assert_eq!(count_key(&consumed, "javascript:S1154"), 0);
        assert_eq!(count_key(&consumed, "javascript:S2201"), 0);

        let opaque = js_keys("text.mutate();\n");
        assert_eq!(count_key(&opaque, "javascript:S1154"), 0);
        assert_eq!(count_key(&opaque, "javascript:S2201"), 0);
    }

    #[test]
    fn s108_flags_empty_block_commented_or_populated_blocks_pass() {
        let empty = js_keys("if (a) {\n}\n");
        assert_eq!(count_key(&empty, "javascript:S108"), 1);

        let commented = js_keys("if (a) {\n  /* intentionally blank */\n}\n");
        assert_eq!(count_key(&commented, "javascript:S108"), 0);

        let populated = js_keys("if (a) {\n  g();\n}\n");
        assert_eq!(count_key(&populated, "javascript:S108"), 0);
    }

    #[test]
    fn s121_and_s2681_distinguish_braced_else_if_and_unbraced_bodies() {
        let multiline = js_keys("if (a)\n  g(\n    b);\n");
        assert_eq!(count_key(&multiline, "javascript:S2681"), 1);
        assert_eq!(count_key(&multiline, "javascript:S121"), 1);

        let oneline = js_keys("if (a) g(b);\n");
        assert_eq!(count_key(&oneline, "javascript:S2681"), 0);

        let braced = js_keys("if (a) {\n  g(b);\n}\n");
        assert_eq!(count_key(&braced, "javascript:S2681"), 0);
        assert_eq!(count_key(&braced, "javascript:S121"), 0);
        let unbraced_else = js_keys("if (a) {\n  f();\n} else\n  g(\n    c);\n");
        assert_eq!(count_key(&unbraced_else, "javascript:S2681"), 1);
        assert_eq!(count_key(&unbraced_else, "javascript:S121"), 1);

        // A standard `else if` is itself a braced if statement, not an
        // unbraced else body. Its own branches still undergo normal checks.
        let else_if = js_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n}\n");
        assert_eq!(count_key(&else_if, "javascript:S2681"), 0);
        assert_eq!(count_key(&else_if, "javascript:S121"), 0);
        assert_eq!(count_key(&else_if, "javascript:S126"), 1);

        let typescript_else_if = ts_keys("if (a) {\n  f();\n} else if (b) {\n  g();\n}\n");
        assert_eq!(count_key(&typescript_else_if, "typescript:S2681"), 0);
        assert_eq!(count_key(&typescript_else_if, "typescript:S121"), 0);
        assert_eq!(count_key(&typescript_else_if, "typescript:S126"), 1);

        let nested_unbraced_else_if =
            js_keys("if (a) {\n  f();\n} else /* keep this comment */ if (b)\n  g(\n    c);\n");
        assert_eq!(count_key(&nested_unbraced_else_if, "javascript:S2681"), 1);
        assert_eq!(count_key(&nested_unbraced_else_if, "javascript:S121"), 1);
    }

    #[test]
    fn s3863_flags_adjacent_duplicate_imports_gapped_pair_passes() {
        let adjacent = js_keys("import { a } from 'm';\nimport { b } from 'm';\n");
        assert_eq!(count_key(&adjacent, "javascript:S3863"), 1);

        let gapped = js_keys("import { a } from 'm';\n\nimport { b } from 'm';\n");
        assert_eq!(count_key(&gapped, "javascript:S3863"), 0);

        let separated =
            js_keys("import { a } from 'm';\nimport { x } from 'o';\nimport { b } from 'm';\n");
        assert_eq!(count_key(&separated, "javascript:S3863"), 0);
    }

    #[test]
    fn s1066_and_s6660_collapse_edges_stay_clean() {
        let wide = js_keys("if (a) {\n  g();\n  h();\n}\n");
        assert_eq!(count_key(&wide, "javascript:S1066"), 0);
        assert_eq!(count_key(&wide, "javascript:S6660"), 0);

        let inner_with_else = js_keys(
            "if (a) {\n  g();\n} else {\n  if (b) {\n    h();\n  } else {\n    k();\n  }\n}\n",
        );
        assert_eq!(count_key(&inner_with_else, "javascript:S6660"), 0);

        let else_if = js_keys("if (a) {\n  g();\n} else if (b) {\n  h();\n}\n");
        assert_eq!(count_key(&else_if, "javascript:S6660"), 0);
    }

    #[test]
    fn statement_compliant_fixture_emits_none_of_the_family_keys() {
        let source = "\
const limit = 10;
let total = 0;

function accumulate(values) {
  for (const value of values) {
    total += pick(value);
  }
  return total;
}

function pick(value) {
  if (value > 0) {
    return value;
  }
  return -1;
}

export { accumulate };
";
        let flagged = js_keys(source);
        for key in [
            "S108", "S121", "S2681", "S909", "S1066", "S1116", "S1119", "S1126", "S1154", "S1199",
            "S1321", "S1525", "S1848", "S2201", "S2208", "S3504", "S3696", "S3863", "S3984",
            "S6660", "S6836", "S6859",
        ] {
            assert_eq!(
                count_key(&flagged, &format!("javascript:{key}")),
                0,
                "unexpected {key}"
            );
        }
    }

    #[test]
    fn with_statement_walks_nested_statements() {
        let report = js("with (scope) {\n  debugger;\n}\n");
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S1321"))
                .count(),
            1
        );
        assert_eq!(
            report
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S1525"))
                .count(),
            1
        );
    }
}
