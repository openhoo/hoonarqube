use super::collectors::DuplicationCollector;
use crate::support::RuleScope;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    Declaration, ExportDeclaration, ExportDefaultDeclaration, ExportNamedDeclaration, Expression,
    IdentifierReference, ImportOrExportKind, ModuleExportName, VariableDeclaration,
    VariableDeclarationKind,
};
use oxc_span::GetSpan;

impl DuplicationCollector<'_> {
    pub(super) fn check_s6861_export_declaration(&mut self, export: &ExportDeclaration<'_>) {
        if let Declaration::VariableDeclaration(variable) = &export.declaration
            && is_mutable(variable)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6861",
                "Do not export mutable bindings.",
                variable.span(),
            );
        }
    }

    pub(super) fn check_s6861_named_export(&mut self, export: &ExportNamedDeclaration<'_>) {
        if export.export_kind == ImportOrExportKind::Type {
            return;
        }
        for specifier in &export.specifiers {
            if specifier.export_kind == ImportOrExportKind::Value
                && let ModuleExportName::IdentifierReference(local) = &specifier.local
            {
                self.check_s6861_exported_binding(local, specifier.exported.name().as_str());
            }
        }
    }

    pub(super) fn check_s6861_default_export(&mut self, export: &ExportDefaultDeclaration<'_>) {
        if let Some(expression) = export.declaration.as_expression()
            && let Expression::Identifier(local) = expression.without_parentheses()
        {
            self.check_s6861_exported_binding(local, "default");
        }
    }

    fn check_s6861_exported_binding(&mut self, local: &IdentifierReference<'_>, exported: &str) {
        let Some(semantic) = self.semantic else {
            return;
        };
        let scoping = semantic.scoping();
        let Some(symbol) = local
            .reference_id
            .get()
            .and_then(|reference| scoping.get_reference(reference).symbol_id())
        else {
            return;
        };

        let nodes = semantic.nodes();
        for declaration in scoping.symbol_declarations(symbol) {
            if matches!(nodes.kind(declaration), AstKind::VariableDeclarator(_))
                && let AstKind::VariableDeclaration(variable) = nodes.parent_kind(declaration)
                && is_mutable(variable)
            {
                // Distinguish aliases that share a declaration span during issue deduplication.
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6861",
                    &format!("Do not export mutable binding as {exported:?}."),
                    variable.span(),
                );
            }
        }
    }
}

fn is_mutable(variable: &VariableDeclaration<'_>) -> bool {
    matches!(
        variable.kind,
        VariableDeclarationKind::Let | VariableDeclarationKind::Var
    )
}
