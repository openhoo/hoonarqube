// Family walker for 'statement' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, ScannedComment, source_slice, static_property_name,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    BlockStatement, CallExpression, ContinueStatement, DebuggerStatement, DoWhileStatement,
    EmptyStatement, ExportAllDeclaration, Expression, ExpressionStatement, ForInStatement,
    ForOfStatement, ForStatement, Function, FunctionBody, FunctionType, IfStatement,
    ImportDeclaration, ImportDeclarationSpecifier, ImportOrExportKind, LabeledStatement,
    NewExpression, ReturnStatement, Statement, StaticBlock, SwitchCase, ThrowStatement,
    VariableDeclaration, VariableDeclarationKind, WhileStatement, WithStatement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_block_statement, walk_do_while_statement, walk_export_all_declaration,
    walk_expression_statement, walk_for_in_statement, walk_for_of_statement, walk_for_statement,
    walk_function, walk_function_body, walk_if_statement, walk_import_declaration,
    walk_labeled_statement, walk_program, walk_return_statement, walk_statement, walk_static_block,
    walk_switch_case, walk_throw_statement, walk_variable_declaration, walk_while_statement,
    walk_with_statement,
};
use oxc_span::{GetSpan, Span};
use std::collections::HashMap;

fn check_statement_rules(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
    comments: &[ScannedComment],
) -> Vec<Issue> {
    let mut collector = StatementCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
        import_facts: Vec::new(),
        no_var_suppression: NoVarSuppression::from_comments(comments, source, index),
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
    /// Every `import` declaration seen, grouped at end of walk for `S3863`.
    import_facts: Vec<ImportFact>,
    /// `eslint-disable` regions/lines that suppress `no-var` (`S3504`).
    no_var_suppression: NoVarSuppression,
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
    /// Tracks whether the current `statement` is a direct child of an if.
    current_statement_is_if: bool,
    if_parent_is_if: bool,
}

/// One `import` declaration's `S3863` grouping key plus its report span.
struct ImportFact {
    module: String,
    is_type: bool,
    span: Span,
}

/// `eslint-disable`/`eslint-enable` regions and single-line directives that
/// cover `no-var`, resolved once per file for `S3504`.
struct NoVarSuppression {
    /// Half-open byte ranges where `no-var` reports are suppressed.
    regions: Vec<(u32, u32)>,
    /// Individual lines suppressed by `eslint-disable-line`/`next-line`.
    lines: Vec<u32>,
}

impl NoVarSuppression {
    fn from_comments(comments: &[ScannedComment], source: &str, index: &LineIndex) -> Self {
        let mut regions = Vec::new();
        let mut lines = Vec::new();
        // Position where `no-var` became disabled, while disabled.
        let mut disabled_start: Option<u32> = None;
        for comment in comments {
            let body = source_slice(source, comment.body).trim();
            let Some((directive, rule_list)) = eslint_directive(body) else {
                continue;
            };
            let applies =
                rule_list.is_empty() || rule_list.split(',').any(|rule| rule.trim() == "no-var");
            match directive {
                EslintDirective::Disable if applies && disabled_start.is_none() => {
                    disabled_start = Some(comment.token.start);
                }
                EslintDirective::Enable if applies => {
                    if let Some(start) = disabled_start.take() {
                        regions.push((start, comment.token.start));
                    }
                }
                EslintDirective::DisableLine if applies => {
                    lines.push(index.pos(comment.token.start).line);
                }
                EslintDirective::DisableNextLine if applies => {
                    lines.push(index.pos(comment.token.end).line + 1);
                }
                _ => {}
            }
        }
        if let Some(start) = disabled_start {
            regions.push((start, u32::MAX));
        }
        Self { regions, lines }
    }

    /// Whether a `var` declaration starting at `start` is suppressed.
    fn suppressed(&self, index: &LineIndex, start: u32) -> bool {
        self.regions
            .iter()
            .any(|&(from, to)| from <= start && start < to)
            || self.lines.iter().any(|&line| line == index.pos(start).line)
    }
}

/// The `eslint-*` directives that can suppress `no-var` reports.
enum EslintDirective {
    Disable,
    Enable,
    DisableLine,
    DisableNextLine,
}

/// Parses an `eslint-disable`/`eslint-enable`/`eslint-disable-line`/
/// `eslint-disable-next-line` comment body into its directive and trimmed
/// comma-separated rule list, after splitting off a ` -- justification`.
fn eslint_directive(body: &str) -> Option<(EslintDirective, &str)> {
    let part = strip_justification(body);
    for (label, directive) in [
        ("eslint-disable-next-line", EslintDirective::DisableNextLine),
        ("eslint-disable-line", EslintDirective::DisableLine),
        ("eslint-disable", EslintDirective::Disable),
        ("eslint-enable", EslintDirective::Enable),
    ] {
        if let Some(rest) = part.strip_prefix(label)
            && (rest.is_empty() || rest.starts_with(char::is_whitespace))
        {
            return Some((directive, rest.trim()));
        }
    }
    None
}

/// The part of `trimmed` before the first whitespace-surrounded run of two
/// or more hyphens (`ESLint`'s justification separator `\s-{2,}\s`).
fn strip_justification(trimmed: &str) -> &str {
    for (index, character) in trimmed.char_indices() {
        if !character.is_whitespace() {
            continue;
        }
        let after_character = &trimmed[index + character.len_utf8()..];
        let hyphen_run = after_character.chars().take_while(|c| *c == '-').count();
        if hyphen_run < 2 {
            continue;
        }
        if after_character[hyphen_run..].starts_with(char::is_whitespace) {
            return trimmed[..index].trim_end();
        }
    }
    trimmed
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
        self.check_duplicate_imports();
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
        self.check_control_structure_body(&it.consequent, "Expected { after 'if' condition.");
        if let Some(alternate) = &it.alternate
            && !matches!(alternate, Statement::IfStatement(_))
        {
            self.check_control_structure_body(alternate, "Expected { after 'if' condition.");
        }
        self.check_collapsible_if(it);
        walk_if_statement(self, it);
    }

    fn visit_while_statement(&mut self, it: &WhileStatement<'a>) {
        self.check_control_structure_body(&it.body, "Expected { after 'while' condition.");
        walk_while_statement(self, it);
    }

    fn visit_do_while_statement(&mut self, it: &DoWhileStatement<'a>) {
        self.check_control_structure_body(&it.body, "Expected { after 'do'.");
        walk_do_while_statement(self, it);
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        self.check_control_structure_body(&it.body, "Expected { after 'for' condition.");
        walk_for_statement(self, it);
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        self.check_control_structure_body(&it.body, "Expected { after 'for' condition.");
        walk_for_in_statement(self, it);
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        self.check_control_structure_body(&it.body, "Expected { after 'for' condition.");
        walk_for_of_statement(self, it);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        for statement in &it.consequent {
            self.check_case_lexical_declaration(statement);
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
            if !self
                .no_var_suppression
                .suppressed(self.sink.index, it.span().start)
            {
                let span = it.declarations.first().map_or(it.span(), |declaration| {
                    Span::new(it.span.start, declaration.id.span().end)
                });
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3504",
                    "Unexpected var, use let or const instead.",
                    span,
                );
            }
        } else {
            self.mark_lone_block();
        }
        walk_variable_declaration(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        self.check_namespace_import(it);
        self.check_absolute_import_path(it);
        self.import_facts.push(ImportFact {
            module: it.source.value.to_string(),
            is_type: it.import_kind == ImportOrExportKind::Type,
            span: it.span(),
        });
        walk_import_declaration(self, it);
    }

    fn visit_export_all_declaration(&mut self, it: &ExportAllDeclaration<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S2208",
            "Explicitly export the specific member needed.",
            it.span(),
        );
        walk_export_all_declaration(self, it);
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
    fn check_control_structure_body(&mut self, body: &Statement<'_>, message: &str) {
        if matches!(body, Statement::BlockStatement(_)) {
            return;
        }
        self.sink
            .emit_span(RuleScope::Both, "S121", message, body.span());
        if self.sink.index.covered_lines(body.span()).count() > 1 {
            self.sink.emit_span(
                RuleScope::Both,
                "S2681",
                "Put this unbraced statement on one line or use curly braces.",
                body.span(),
            );
        }
    }

    /// `S1066`: an `if` whose consequent block holds exactly one `if`
    /// without an `else` (an inner `else` would be dropped by merging).
    /// `S6660`: an `else` block holding exactly one `if`.
    fn check_collapsible_if(&mut self, it: &IfStatement<'_>) {
        if let Statement::BlockStatement(block) = &it.consequent
            && block.body.len() == 1
            && let Statement::IfStatement(inner) = &block.body[0]
            && inner.alternate.is_none()
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

    /// `S6836`: lexical declarations directly inside an unbraced switch
    /// case consequent.
    fn check_case_lexical_declaration(&mut self, statement: &Statement<'_>) {
        let lexical = match statement {
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
                statement.span(),
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

    /// `S3863`: imports of the same module and import kind anywhere in the
    /// file; every member of a duplicate group is flagged.
    fn check_duplicate_imports(&mut self) {
        let mut counts: HashMap<(&str, bool), usize> = HashMap::new();
        for fact in &self.import_facts {
            *counts
                .entry((fact.module.as_str(), fact.is_type))
                .or_insert(0) += 1;
        }
        for fact in &self.import_facts {
            if counts[&(fact.module.as_str(), fact.is_type)] > 1 {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3863",
                    &format!("'{}' import is duplicated.", fact.module),
                    fact.span,
                );
            }
        }
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
    check_statement_rules(
        ctx.program,
        ctx.source,
        ctx.index,
        ctx.language,
        &ctx.comments,
    )
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
        // One issue per line beyond the first statement: top level, the
        // function body, the `if` block, the `while` block, and the
        // try/catch line (five statements share it).
        let mut sites: Vec<(u32, &str)> = s122
            .iter()
            .map(|issue| (issue.range.start.line, issue.message.as_str()))
            .collect();
        sites.sort_unstable();
        assert_eq!(
            sites,
            vec![
                (1, "This line has 2 statements. Maximum allowed is 1."),
                (3, "This line has 2 statements. Maximum allowed is 1."),
                (5, "This line has 3 statements. Maximum allowed is 1."),
                (6, "This line has 3 statements. Maximum allowed is 1."),
                (7, "This line has 5 statements. Maximum allowed is 1."),
            ]
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
    fn s3863_flags_every_member_of_same_kind_duplicate_groups() {
        // Same module + same import kind anywhere in the file: every member
        // of the group is flagged, regardless of adjacency.
        let adjacent = js_keys("import { a } from 'm';\nimport { b } from 'm';\n");
        assert_eq!(count_key(&adjacent, "javascript:S3863"), 2);

        let gapped = js_keys("import { a } from 'm';\n\nimport { b } from 'm';\n");
        assert_eq!(count_key(&gapped, "javascript:S3863"), 2);

        let separated =
            js_keys("import { a } from 'm';\nimport { x } from 'o';\nimport { b } from 'm';\n");
        assert_eq!(count_key(&separated, "javascript:S3863"), 2);

        // A type-only import and a value import from the same module are
        // distinct groups and stay silent.
        let mixed = ts_keys("import type { D } from './a2';\nimport { v } from './a2';\n");
        assert_eq!(count_key(&mixed, "typescript:S3863"), 0);

        // Non-adjacent same-kind duplicates flag both members.
        let nonadjacent = ts_keys(
            "import type { A } from './a';\nimport type { B } from './b';\nimport type { C } from './a';\n",
        );
        assert_eq!(count_key(&nonadjacent, "typescript:S3863"), 2);
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

    #[test]
    fn s121_flags_unbraced_loop_bodies() {
        let flagged = ts_keys(
            "function g(node: any, source: string): void {\n    while (isAs(node)) node = node.expression;\n    for (const d of decls) replaced.add(d);\n    let end = 0;\n    while (end < source.length && source[end] === \" \") end++;\n}\nfunction isAs(n: any): boolean { return false; }\nconst decls: any[] = []; const replaced = new Set();\n",
        );
        let lines: Vec<u32> = flagged
            .iter()
            .filter(|(key, _)| key == "typescript:S121")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(lines, vec![2, 3, 5]);

        // do-while, for, and for-in bodies are covered by the same rule.
        let loops = js_keys(
            "do x++; while (x < 3);\nfor (let i = 0; i < 3; i++) y(i);\nfor (const k in obj) use(k);\n",
        );
        assert_eq!(count_key(&loops, "javascript:S121"), 3);

        // Braced loop bodies stay silent.
        let braced = js_keys("while (x) {\n  y();\n}\nfor (;;) {\n  break;\n}\n");
        assert_eq!(count_key(&braced, "javascript:S121"), 0);
    }

    #[test]
    fn s2208_flags_export_star_reexports() {
        let flagged = ts_keys(
            "export { SyntaxKind } from \"#enums/syntaxKind\";\nexport * from \"./ast\";\nexport * from \"./astnav\";\n",
        );
        let lines: Vec<u32> = flagged
            .iter()
            .filter(|(key, _)| key == "typescript:S2208")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(lines, vec![2, 3]);

        // `export * as ns` is an export-all too; named re-exports stay silent.
        let named_ns = ts_keys("export * as ns from \"./ast\";\n");
        assert_eq!(count_key(&named_ns, "typescript:S2208"), 1);

        // Existing `import * as` behavior is unchanged.
        let import_ns = js_keys("import * as ns from 'm';\n");
        assert_eq!(count_key(&import_ns, "javascript:S2208"), 1);
    }

    #[test]
    fn s3504_honors_eslint_disable_no_var() {
        let suppressed = ts_keys(
            "function scan(textInitial: string): number {\n    // Why var? It avoids TDZ checks in the runtime which can be costly.\n    /* eslint-disable no-var */\n    var text = textInitial;\n    var pos: number;\n    var end: number;\n    return text.length;\n}\n",
        );
        assert_eq!(count_key(&suppressed, "typescript:S3504"), 0);

        // A var outside the disabled region still flags.
        let outside = js_keys(
            "/* eslint-disable no-var */\nvar a = 1;\n/* eslint-enable no-var */\nvar b = 2;\n",
        );
        assert_eq!(count_key(&outside, "javascript:S3504"), 1);

        // Line directives suppress only the annotated line.
        let next_line = js_keys("// eslint-disable-next-line no-var\nvar c = 3;\nvar d = 4;\n");
        assert_eq!(count_key(&next_line, "javascript:S3504"), 1);

        let disable_line = js_keys("var e = 5; // eslint-disable-line no-var\nvar f = 6;\n");
        assert_eq!(count_key(&disable_line, "javascript:S3504"), 1);

        // A disable naming a different rule does not suppress no-var.
        let other_rule = js_keys("/* eslint-disable no-alert */\nvar g = 7;\n");
        assert_eq!(count_key(&other_rule, "javascript:S3504"), 1);
    }

    #[test]
    fn s6836_flags_mid_case_lexical_declarations() {
        let flagged = ts_keys(
            "function f(x: number): number {\n    switch (x) {\n        case 1:\n            doThing();\n            const nextChar = x + 1;\n            let hasTrailingNewLine = false;\n            return nextChar;\n        default:\n            return 0;\n    }\n}\ndeclare function doThing(): void;\n",
        );
        let lines: Vec<u32> = flagged
            .iter()
            .filter(|(key, _)| key == "typescript:S6836")
            .map(|(_, line)| *line)
            .collect();
        assert_eq!(lines, vec![5, 6]);

        // Braced case blocks and `var` stay silent.
        let braced = js_keys("switch (x) {\n  case 1: {\n    const y = 1;\n    break;\n  }\n}\n");
        assert_eq!(count_key(&braced, "javascript:S6836"), 0);

        let var_decl =
            js_keys("switch (x) {\n  case 1:\n    f();\n    var y = 1;\n    break;\n}\n");
        assert_eq!(count_key(&var_decl, "javascript:S6836"), 0);
    }

    #[test]
    fn s1066_inner_if_with_else_is_not_mergeable() {
        let flagged = ts_keys(
            "function f(a: boolean, b: boolean): number {\n    if (!a) {\n        if (b) {\n            return 1;\n        }\n        else {\n            return 2;\n        }\n    }\n    return 3;\n}\n",
        );
        assert_eq!(count_key(&flagged, "typescript:S1066"), 0);

        let js_flagged = js_keys(
            "function f(options, releaseVscodeTypescript) {\n    let version = \"0.0.0\";\n    if (options.forRelease) {\n        if (releaseVscodeTypescript) {\n            version = getVersion();\n        }\n        else {\n            version = \"0.1.0\";\n        }\n    }\n    if (options.a) {\n        if (options.b) {\n            version = \"x\";\n        }\n    }\n    return version;\n}\n",
        );
        assert_eq!(count_key(&js_flagged, "javascript:S1066"), 1);

        // An inner if without else still merges.
        let mergeable = js_keys("if (a) {\n  if (b) {\n    f();\n  }\n}\n");
        assert_eq!(count_key(&mergeable, "javascript:S1066"), 1);
    }
}
