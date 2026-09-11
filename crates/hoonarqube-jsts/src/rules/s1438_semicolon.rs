use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, to_u32};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AccessorProperty, BreakStatement, ContinueStatement, DebuggerStatement, Directive,
    DoWhileStatement, ExportAllDeclaration, ExportDeclaration, ExportDefaultDeclaration,
    ExportDefaultDeclarationKind, ExportFromDeclaration, ExportNamedDeclaration,
    ExpressionStatement, ForInStatement, ForOfStatement, ForStatement, ForStatementInit,
    ForStatementLeft, Function, FunctionType, ImportDeclaration, PropertyDefinition,
    ReturnStatement, TSExportAssignment, TSImportEqualsDeclaration, TSTypeAliasDeclaration,
    ThrowStatement, VariableDeclaration,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_accessor_property, walk_break_statement, walk_continue_statement, walk_debugger_statement,
    walk_directive, walk_do_while_statement, walk_export_all_declaration, walk_export_declaration,
    walk_export_default_declaration, walk_export_from_declaration, walk_export_named_declaration,
    walk_expression_statement, walk_for_in_statement, walk_for_of_statement, walk_for_statement,
    walk_function, walk_import_declaration, walk_property_definition, walk_return_statement,
    walk_throw_statement, walk_ts_export_assignment, walk_ts_import_equals_declaration,
    walk_ts_type_alias_declaration, walk_variable_declaration,
};
use oxc_parser::{Kind, Token};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;

const MESSAGE: &str = "Missing semicolon.";

pub(crate) fn check(ctx: &AnalysisContext<'_>) -> Vec<Issue> {
    // Recovery may leave an AST node whose span does not correspond to a real
    // statement boundary. S1438 is a token-boundary rule, so leave recovery to
    // S2260 instead of manufacturing a finding from that partial tree.
    if ctx.has_parse_errors {
        return Vec::new();
    }

    let mut collector = SemicolonCollector {
        source: ctx.source,
        sink: IssueSink {
            index: ctx.index,
            language: ctx.language,
            issues: Vec::new(),
        },
        tokens: ctx.tokens,
        ignored_variables: Vec::new(),
    };
    collector.visit_program(ctx.program);
    collector.sink.issues
}

struct SemicolonCollector<'tokens, 'source, 'index> {
    source: &'source str,
    sink: IssueSink<'index>,
    tokens: &'tokens [Token],
    ignored_variables: Vec<Span>,
}

impl SemicolonCollector<'_, '_, '_> {
    fn check_span(&mut self, span: Span) {
        let Some(last_token) = last_token(self.tokens, span) else {
            return;
        };
        if last_token.kind() != Kind::Semicolon {
            self.sink.emit_span(
                RuleScope::Both,
                "S1438",
                MESSAGE,
                report_span(self.source, last_token.start(), last_token.end()),
            );
        }
    }

    fn check_variable(&mut self, declaration: &VariableDeclaration<'_>) {
        if !self
            .ignored_variables
            .iter()
            .any(|span| *span == declaration.span())
        {
            self.check_span(declaration.span());
        }
    }

    fn push_for_variable(&mut self, span: Option<Span>) -> bool {
        if let Some(span) = span {
            self.ignored_variables.push(span);
            true
        } else {
            false
        }
    }

    fn pop_for_variable(&mut self, pushed: bool) {
        if pushed {
            let _ = self.ignored_variables.pop();
        }
    }
}

fn report_span(source: &str, last_token_start: u32, last_token_end: u32) -> Span {
    let token_start = usize::try_from(last_token_start)
        .unwrap_or(source.len())
        .min(source.len());
    let line_start = source[..token_start]
        .char_indices()
        .filter_map(|(index, character)| {
            matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}')
                .then_some(index + character.len_utf8())
        })
        .next_back()
        .unwrap_or(0);
    let end = usize::try_from(last_token_end)
        .unwrap_or(source.len())
        .min(source.len());
    let line_end = source[end..]
        .char_indices()
        .find_map(|(index, character)| {
            matches!(character, '\n' | '\r' | '\u{2028}' | '\u{2029}').then_some(end + index)
        })
        .unwrap_or(source.len());
    Span::new(to_u32(line_start), to_u32(line_end))
}

fn last_token(tokens: &[Token], node: Span) -> Option<&Token> {
    let end = tokens.partition_point(|token| token.end() <= node.end);
    tokens[..end].iter().rev().find(|token| {
        token.kind() != Kind::Eof && token.start() >= node.start && token.end() <= node.end
    })
}

impl<'ast> Visit<'ast> for SemicolonCollector<'_, '_, '_> {
    fn visit_variable_declaration(&mut self, declaration: &VariableDeclaration<'ast>) {
        self.check_variable(declaration);
        walk_variable_declaration(self, declaration);
    }
    fn visit_directive(&mut self, directive: &Directive<'ast>) {
        self.check_span(directive.span);
        walk_directive(self, directive);
    }

    fn visit_expression_statement(&mut self, statement: &ExpressionStatement<'ast>) {
        self.check_span(statement.span());
        walk_expression_statement(self, statement);
    }

    fn visit_return_statement(&mut self, statement: &ReturnStatement<'ast>) {
        self.check_span(statement.span());
        walk_return_statement(self, statement);
    }

    fn visit_throw_statement(&mut self, statement: &ThrowStatement<'ast>) {
        self.check_span(statement.span());
        walk_throw_statement(self, statement);
    }

    fn visit_do_while_statement(&mut self, statement: &DoWhileStatement<'ast>) {
        self.check_span(statement.span());
        walk_do_while_statement(self, statement);
    }

    fn visit_debugger_statement(&mut self, statement: &DebuggerStatement) {
        self.check_span(statement.span);
        walk_debugger_statement(self, statement);
    }

    fn visit_break_statement(&mut self, statement: &BreakStatement<'ast>) {
        self.check_span(statement.span());
        walk_break_statement(self, statement);
    }

    fn visit_continue_statement(&mut self, statement: &ContinueStatement<'ast>) {
        self.check_span(statement.span());
        walk_continue_statement(self, statement);
    }

    fn visit_import_declaration(&mut self, declaration: &ImportDeclaration<'ast>) {
        self.check_span(declaration.span());
        walk_import_declaration(self, declaration);
    }

    fn visit_export_all_declaration(&mut self, declaration: &ExportAllDeclaration<'ast>) {
        self.check_span(declaration.span());
        walk_export_all_declaration(self, declaration);
    }
    fn visit_export_declaration(&mut self, declaration: &ExportDeclaration<'ast>) {
        walk_export_declaration(self, declaration);
    }

    fn visit_export_named_declaration(&mut self, declaration: &ExportNamedDeclaration<'ast>) {
        self.check_span(declaration.span());
        walk_export_named_declaration(self, declaration);
    }

    fn visit_export_from_declaration(&mut self, declaration: &ExportFromDeclaration<'ast>) {
        self.check_span(declaration.span());
        walk_export_from_declaration(self, declaration);
    }

    fn visit_export_default_declaration(&mut self, declaration: &ExportDefaultDeclaration<'ast>) {
        if !matches!(
            &declaration.declaration,
            ExportDefaultDeclarationKind::FunctionDeclaration(_)
                | ExportDefaultDeclarationKind::ClassDeclaration(_)
                | ExportDefaultDeclarationKind::TSInterfaceDeclaration(_)
        ) {
            self.check_span(declaration.span());
        }
        walk_export_default_declaration(self, declaration);
    }

    fn visit_property_definition(&mut self, definition: &PropertyDefinition<'ast>) {
        self.check_span(definition.span());
        walk_property_definition(self, definition);
    }

    fn visit_accessor_property(&mut self, property: &AccessorProperty<'ast>) {
        self.check_span(property.span());
        walk_accessor_property(self, property);
    }

    fn visit_function(&mut self, function: &Function<'ast>, flags: ScopeFlags) {
        if matches!(
            function.r#type,
            FunctionType::TSDeclareFunction | FunctionType::TSEmptyBodyFunctionExpression
        ) {
            self.check_span(function.span());
        }
        walk_function(self, function, flags);
    }

    // Keep SonarJS parity: its delegated @stylistic/eslint-plugin/semi
    // visitor intentionally does not include TSNamespaceExportDeclaration.
    // Do not broaden S1438 to a declaration that upstream leaves untouched.
    fn visit_ts_export_assignment(&mut self, assignment: &TSExportAssignment<'ast>) {
        self.check_span(assignment.span());
        walk_ts_export_assignment(self, assignment);
    }

    fn visit_ts_import_equals_declaration(
        &mut self,
        declaration: &TSImportEqualsDeclaration<'ast>,
    ) {
        self.check_span(declaration.span());
        walk_ts_import_equals_declaration(self, declaration);
    }

    fn visit_ts_type_alias_declaration(&mut self, declaration: &TSTypeAliasDeclaration<'ast>) {
        self.check_span(declaration.span());
        walk_ts_type_alias_declaration(self, declaration);
    }

    fn visit_for_statement(&mut self, statement: &ForStatement<'ast>) {
        let variable_span = match statement.init.as_ref() {
            Some(ForStatementInit::VariableDeclaration(declaration)) => Some(declaration.span()),
            _ => None,
        };
        let pushed = self.push_for_variable(variable_span);
        walk_for_statement(self, statement);
        self.pop_for_variable(pushed);
    }

    fn visit_for_in_statement(&mut self, statement: &ForInStatement<'ast>) {
        let variable_span = match &statement.left {
            ForStatementLeft::VariableDeclaration(declaration) => Some(declaration.span()),
            _ => None,
        };
        let pushed = self.push_for_variable(variable_span);
        walk_for_in_statement(self, statement);
        self.pop_for_variable(pushed);
    }

    fn visit_for_of_statement(&mut self, statement: &ForOfStatement<'ast>) {
        let variable_span = match &statement.left {
            ForStatementLeft::VariableDeclaration(declaration) => Some(declaration.span()),
            _ => None,
        };
        let pushed = self.push_for_variable(variable_span);
        walk_for_of_statement(self, statement);
        self.pop_for_variable(pushed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{AnalyzerOptions, JstsLanguage, PathBuf, analyze, issue, js, ts};

    fn s1438(report: hoonarqube_ir::FileReport) -> Vec<hoonarqube_ir::Issue> {
        report
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key.ends_with(":S1438"))
            .collect()
    }

    #[test]
    fn javascript_reports_asi_at_eof_but_not_explicit_or_empty_semicolons() {
        let report = js("const withSemi = 1;\nconst without = 2");
        assert_eq!(
            s1438(report),
            vec![issue("javascript:S1438", MESSAGE, (2, 0), (2, 17),)]
        );

        assert!(s1438(js("const value = 1;;\n")).is_empty());
        assert!(s1438(js("for (let i = 0; i < 1; i++) {}\n")).is_empty());
        assert_eq!(
            s1438(js("class C { value = 1 }\n")),
            vec![issue("javascript:S1438", MESSAGE, (1, 0), (1, 21))]
        );
        assert!(s1438(js("foo\n(bar);\n")).is_empty());
        assert!(s1438(js("foo\n[bar];\n")).is_empty());
        assert_eq!(
            s1438(js("export const value = 1\n")),
            vec![issue("javascript:S1438", MESSAGE, (1, 0), (1, 22))]
        );
        assert_eq!(
            s1438(js("\"use strict\"\n")),
            vec![issue("javascript:S1438", MESSAGE, (1, 0), (1, 12))]
        );
    }

    #[test]
    fn typescript_reports_type_alias_and_annotated_variable_boundaries() {
        let report = ts("type Name = string\nlet value: Name\n");
        assert_eq!(
            s1438(report),
            vec![
                issue("typescript:S1438", MESSAGE, (1, 0), (1, 18)),
                issue("typescript:S1438", MESSAGE, (2, 0), (2, 15)),
            ]
        );
        assert!(s1438(ts("type Name = string;\nlet value: Name;\n")).is_empty());
        assert!(s1438(ts("export as namespace React;\n")).is_empty());
    }

    #[test]
    fn javascript_handles_return_postfix_and_comments_without_merging_statements() {
        let report = js(concat!(
            "function f() {\n",
            "  return\n",
            "  value()\n",
            "}\n",
            "let n = 0\n",
            "n++\n",
            "n--\n",
            "const first = 1 /* comment */\n",
            "const second = 2 // comment\n",
        ));
        assert_eq!(
            s1438(report),
            vec![
                issue("javascript:S1438", MESSAGE, (2, 0), (2, 8)),
                issue("javascript:S1438", MESSAGE, (3, 0), (3, 9)),
                issue("javascript:S1438", MESSAGE, (5, 0), (5, 9)),
                issue("javascript:S1438", MESSAGE, (6, 0), (6, 3)),
                issue("javascript:S1438", MESSAGE, (7, 0), (7, 3)),
                issue("javascript:S1438", MESSAGE, (8, 0), (8, 29)),
                issue("javascript:S1438", MESSAGE, (9, 0), (9, 27)),
            ]
        );
    }

    #[test]
    fn invalid_throw_recovery_does_not_emit_s1438() {
        let report = js("function f() {\n  throw\n  new Error()\n}\n");
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.rule_key != "javascript:S1438")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "javascript:S2260")
        );
    }

    #[test]
    fn unicode_crlf_positions_are_character_columns() {
        let report = js("const café = \"é\"\r\nconst 漢 = 1\r\n");
        assert_eq!(
            s1438(report),
            vec![
                issue("javascript:S1438", MESSAGE, (1, 0), (1, 16)),
                issue("javascript:S1438", MESSAGE, (2, 0), (2, 11)),
            ]
        );
    }

    #[test]
    fn jsx_and_tsx_use_the_same_token_boundary_rule() {
        let jsx = analyze(
            PathBuf::from("component.jsx"),
            "const el = <div />",
            JstsLanguage::JavaScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            s1438(jsx),
            vec![issue("javascript:S1438", MESSAGE, (1, 0), (1, 18))]
        );

        let tsx = analyze(
            PathBuf::from("component.tsx"),
            "const el = <div />",
            JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            s1438(tsx),
            vec![issue("typescript:S1438", MESSAGE, (1, 0), (1, 18))]
        );
    }
}
