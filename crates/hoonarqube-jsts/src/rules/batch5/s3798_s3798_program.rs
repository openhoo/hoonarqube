use super::collectors_hotspots::MiscCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Statement;
use oxc_ast::ast::VariableDeclarationKind;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl MiscCollector<'_> {
    /// `S3798` logic extracted from `visit_program`.
    pub(crate) fn check_s3798_program(&mut self, it: &oxc_ast::ast::Program<'_>) {
        // `S3798` (JavaScript-only): global `var` / function declarations.
        for statement in &it.body {
            match statement {
                Statement::VariableDeclaration(declaration)
                    if declaration.kind == VariableDeclarationKind::Var =>
                {
                    for declarator in &declaration.declarations {
                        self.sink.emit_span(
                            RuleScope::JsOnly,
                            "S3798",
                            "Declare this symbol in a narrower scope instead of globally.",
                            declarator.span(),
                        );
                    }
                }
                Statement::FunctionDeclaration(function) => {
                    self.sink.emit_span(
                        RuleScope::JsOnly,
                        "S3798",
                        "Declare this function in a narrower scope instead of globally.",
                        function.span(),
                    );
                }
                _ => {}
            }
        }
    }
}
