// Family walker for 'statement' (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{BlockStatement, CallExpression, ConditionalExpression, ContinueStatement, DebuggerStatement, EmptyStatement, Expression, ExpressionStatement, FunctionBody, IfStatement, ImportDeclaration, ImportDeclarationSpecifier, LabeledStatement, NewExpression, NumericLiteral, ReturnStatement, Statement, StaticBlock, StringLiteral, SwitchCase, TemplateLiteral, ThrowStatement, VariableDeclaration, VariableDeclarationKind, WithStatement};
use oxc_ast_visit::{Visit};
use oxc_ast_visit::walk::{walk_block_statement, walk_expression_statement, walk_function_body, walk_if_statement, walk_import_declaration, walk_labeled_statement, walk_return_statement, walk_static_block, walk_switch_case, walk_throw_statement, walk_variable_declaration};
use oxc_span::{GetSpan, Span};
use crate::{JstsLanguage, is_error_type_name};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, LineIndex, RuleScope, constructor_name, source_slice, static_property_name};


pub(crate) fn check_statement_rules(
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
        bare_block_depth: 0,
        last_import: None,
    };
    collector.visit_program(program);
    collector.sink.issues
}


/// Statement-level batch rules in one traversal: `S909`, `S1119`, `S1321`,
/// `S1525`, `S108`, `S1199`, `S121`, `S2681`, `S6660`, `S1066`, `S6836`,
/// `S1116`, `S3696`, `S3984`, `S1848`, `S1154`, `S2201`, `S1126`, `S3504`,
/// `S2208`, `S6859`, and `S3863`.
pub(crate) struct StatementCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'a str,
    /// Depth of `BlockStatement`s nested directly inside `BlockStatement`s;
    /// reset at function boundaries for `S1199`.
    pub(crate) bare_block_depth: u32,
    pub(crate) last_import: Option<(String, u32)>,
}


impl<'a> Visit<'a> for StatementCollector<'a, '_> {
    fn visit_continue_statement(&mut self, it: &ContinueStatement<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S909",
            "Remove this \"continue\" statement.",
            it.span(),
        );
    }

    fn visit_labeled_statement(&mut self, it: &LabeledStatement<'a>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1119",
            "Remove this labeled statement.",
            it.label.span(),
        );
        walk_labeled_statement(self, it);
    }

    fn visit_with_statement(&mut self, it: &WithStatement<'a>) {
        self.sink.emit_span(
            RuleScope::JsOnly,
            "S1321",
            "Remove this \"with\" statement.",
            it.span(),
        );
    }

    fn visit_debugger_statement(&mut self, it: &DebuggerStatement) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1525",
            "Remove this debugger statement.",
            it.span,
        );
    }

    fn visit_empty_statement(&mut self, it: &EmptyStatement) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1116",
            "Remove this empty statement.",
            it.span,
        );
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        if self.bare_block_depth > 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S1199",
                "Remove this nested block.",
                it.span(),
            );
        }
        if it.body.is_empty() {
            self.check_empty_block(it);
        }
        self.bare_block_depth += 1;
        walk_block_statement(self, it);
        self.bare_block_depth -= 1;
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        if it.body.is_empty() {
            self.check_empty_block_span(it.span());
        }
        let saved_depth = self.bare_block_depth;
        self.bare_block_depth = 0;
        walk_static_block(self, it);
        self.bare_block_depth = saved_depth;
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        let saved_depth = self.bare_block_depth;
        self.bare_block_depth = 0;
        walk_function_body(self, it);
        self.bare_block_depth = saved_depth;
    }

    fn visit_if_statement(&mut self, it: &IfStatement<'a>) {
        self.check_control_structure_body(&it.consequent);
        if let Some(alternate) = &it.alternate {
            self.check_control_structure_body(alternate);
        }
        self.check_collapsible_if(it);
        walk_if_statement(self, it);
    }

    fn visit_switch_case(&mut self, it: &SwitchCase<'a>) {
        if let Some(first) = it.consequent.first() {
            self.check_case_leading_declaration(first);
        }
        walk_switch_case(self, it);
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        match &it.expression {
            Expression::NewExpression(new) => {
                self.check_discarded_new(new);
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
                "Throw an Error object instead of this value.",
                it.argument.span(),
            );
        }
        walk_throw_statement(self, it);
    }

    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if let Some(Expression::ConditionalExpression(conditional)) = &it.argument
            && let (Expression::BooleanLiteral(consequent), Expression::BooleanLiteral(alternate)) =
                (&conditional.consequent, &conditional.alternate)
        {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S1126",
                "Return the condition directly instead of this ternary.",
                conditional.span(),
            );
            let _ = (consequent, alternate);
        }
        walk_return_statement(self, it);
    }

    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        if it.kind == VariableDeclarationKind::Var {
            self.sink.emit_span(
                RuleScope::Both,
                "S3504",
                "Replace \"var\" with \"let\" or \"const\".",
                it.span(),
            );
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
    /// `S108`: empty blocks are flagged unless their span interior still
    /// holds comments the parser dropped.
    pub(crate) fn check_empty_block(&mut self, block: &BlockStatement<'_>) {
        self.check_empty_block_span(block.span());
    }

    pub(crate) fn check_empty_block_span(&mut self, span: Span) {
        let interior = Span::new(span.start + 1, span.end.saturating_sub(1));
        let interior_text = source_slice(self.source, interior);
        if interior_text.trim().is_empty() {
            self.sink
                .emit_span(RuleScope::Both, "S108", "Remove this empty block.", span);
        }
    }

    /// `S121` (unbraced control-structure bodies) and `S2681` (the same
    /// bodies spanning several lines).
    pub(crate) fn check_control_structure_body(&mut self, body: &Statement<'_>) {
        if matches!(body, Statement::BlockStatement(_)) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S121",
            "Wrap this statement in curly braces.",
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
    pub(crate) fn check_collapsible_if(&mut self, it: &IfStatement<'_>) {
        if let Statement::BlockStatement(block) = &it.consequent
            && block.body.len() == 1
            && matches!(&block.body[0], Statement::IfStatement(_))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1066",
                "Merge this nested \"if\" into the enclosing condition.",
                block.body[0].span(),
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
    pub(crate) fn check_case_leading_declaration(&mut self, first: &Statement<'_>) {
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
    pub(crate) fn check_discarded_new(&mut self, new: &NewExpression<'_>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S1848",
            "Use this object instantiation or remove it.",
            new.span(),
        );
        if constructor_name(new).is_some_and(is_error_type_name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3984",
                "Throw this error instead of instantiating it.",
                new.callee.span(),
            );
        }
    }

    /// `S1154` and `S2201`: bare statements calling known side-effect-free
    /// APIs.
    pub(crate) fn check_discarded_pure_call(&mut self, call: &CallExpression<'_>) {
        let Some(member) = call.callee.as_member_expression() else {
            return;
        };
        let Some(property) = static_property_name(member) else {
            return;
        };
        if PURE_STRING_METHODS.contains(&property) {
            self.sink.emit_span(
                RuleScope::Both,
                "S1154",
                "Remove this useless statement; the result is discarded.",
                call.span(),
            );
        } else if SIDE_EFFECT_FREE_APIS.contains(&property) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2201",
                "Remove this useless statement; the result is discarded.",
                call.span(),
            );
        }
    }

    /// `S2208`: `import * as` namespace specifiers.
    pub(crate) fn check_namespace_import(&mut self, it: &ImportDeclaration<'_>) {
        if let Some(specifiers) = &it.specifiers {
            for specifier in specifiers {
                if matches!(
                    specifier,
                    ImportDeclarationSpecifier::ImportNamespaceSpecifier(_)
                ) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S2208",
                        "Import only the module members you use.",
                        specifier.span(),
                    );
                }
            }
        }
    }

    /// `S6859`: absolute import paths.
    pub(crate) fn check_absolute_import_path(&mut self, it: &ImportDeclaration<'_>) {
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
    pub(crate) fn check_duplicate_import(&mut self, it: &ImportDeclaration<'_>) {
        let module = it.source.value.to_string();
        let start_line = self.sink.index.pos(it.span().start).line;
        if let Some((last_module, last_end_line)) = &self.last_import
            && *last_module == module
            && start_line <= last_end_line + 1
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S3863",
                "Merge this import with the adjacent import of the same module.",
                it.span(),
            );
        }
        self.last_import = Some((module, self.sink.index.pos(it.span().end).line));
    }
}


/// Known side-effect-free array/string APIs whose bare statement call `S2201`
/// flags (callbacks are assumed pure in this subset).
pub(crate) const SIDE_EFFECT_FREE_APIS: [&str; 20] = [
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
pub(crate) const PURE_STRING_METHODS: [&str; 15] = [
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
    )
}
