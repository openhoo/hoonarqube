// Rule module s7763_prefer_export_from (generated).
//
// `javascript:S7763` + `typescript:S7763` — `export ... from` should be
// used to re-export imported bindings. Reference semantics:
// eslint-plugin-unicorn `prefer-export-from` at the version pinned by
// SonarJS 13.x (v65.0.1) plus the SonarJS S7763 decorator:
//
// - `import { A } from "./a"; export { A };` reports the `A` export
//   specifier with "Use `export…from` to re-export `A`.";
// - `export { A as B };`, `export { A as "b-c" };`, and
//   `export { A as default };` report the specifier and name the
//   exported text;
// - `import { A } from "./a"; export default A;` reports the default
//   export declaration;
// - `import { A } from "./a"; export const B = A;` reports the whole
//   export declaration when `B` is otherwise unused;
// - `import * as ns from "./a";` re-exports report the same way, except
//   `export default ns`, which has no `export…from` equivalent.
//
// The unicorn gate only reports bindings whose every resolved reference
// is an export position; a binding that is also read locally keeps the
// whole import declaration silent. The SonarJS decorator additionally
// suppresses every re-export of a default import (`import d from "./a"`
// or `import { default as d } from "./a"`), reports whose exported name
// is not imported at all, and specifier/default reports for names that
// still have non-export references. Side-effect imports, `export *`,
// and `export { A } from "./a"` re-exports stay silent. The reference is
// fixable but no auto-fix is offered here.

use crate::context::AnalysisContext;
use crate::support::{IssueSink, RuleScope, span_text, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_ast::AstKind;
use oxc_ast::ast::{
    BindingPattern, Expression, ImportDeclaration, ImportDeclarationSpecifier, ModuleExportName,
    VariableDeclarationKind, VariableDeclarator,
};
use oxc_semantic::{AstNode, NodeId, Semantic, SymbolId};
use oxc_span::{GetSpan, Span};

/// Entry point: `javascript:S7763` + `typescript:S7763`
/// prefer-export-from check over the parsed program. Requires the
/// semantic model for binding resolution, so recoverable-parse files
/// stay silent.
pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut sink = IssueSink {
        index: ctx.index,
        language: ctx.language,
        issues: Vec::new(),
    };
    let Some(semantic) = ctx.semantic else {
        return sink.issues;
    };
    for node in semantic.nodes().iter() {
        if let AstKind::ImportDeclaration(declaration) = node.kind() {
            check_import(&mut sink, ctx, semantic, node, declaration);
        }
    }
    sink.issues
}

/// How the imported binding reaches the module: named and namespace
/// imports can be rewritten as `export…from`; default imports cannot
/// under the `SonarJS` decorator.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ImportKind {
    Named,
    Namespace,
    Default,
}

/// One export position that references an imported binding, mirroring
/// the reference `getExported` shapes.
enum ExportSite {
    /// `export { A }` / `export { A as B }` — reports the specifier and
    /// names the `exported` text.
    Specifier { specifier: Span, exported: Span },
    /// `export default A` — reports the whole declaration and names
    /// `default`.
    Default(Span),
    /// `export const B = A` — reports the whole declaration, names the
    /// declared identifier `B`, and requires `B` to be unused.
    ConstAlias { declaration: Span, name: Span },
}

/// One import specifier's binding plus its import kind.
struct BoundImport {
    symbol: SymbolId,
    kind: ImportKind,
}

fn check_import(
    sink: &mut IssueSink<'_>,
    ctx: &AnalysisContext,
    semantic: &Semantic<'_>,
    node: &AstNode<'_>,
    declaration: &ImportDeclaration<'_>,
) {
    let Some(specifiers) = &declaration.specifiers else {
        return;
    };
    if specifiers.is_empty() {
        return;
    }
    let mut bound = Vec::with_capacity(specifiers.len());
    for specifier in specifiers {
        let Some(import) = import_binding(semantic, node, specifier) else {
            // The reference `defs.length !== 1 || defs[0].parent !==
            // importDeclaration` guard: redeclared or foreign bindings
            // silence the whole declaration.
            return;
        };
        bound.push(import);
    }
    let mut exports = Vec::with_capacity(bound.len());
    for import in &bound {
        let Some(sites) = export_sites(semantic, import) else {
            // A reference outside an export position means the binding
            // is also used locally; the declaration stays silent.
            return;
        };
        exports.push((import, sites));
    }
    for (import, sites) in &exports {
        emit_exports(sink, ctx, semantic, import, sites);
    }
}

/// Resolves one import specifier to its bound symbol, or `None` when the
/// binding is redeclared or its declaration is not this specifier.
fn import_binding(
    semantic: &Semantic<'_>,
    declaration: &AstNode<'_>,
    specifier: &ImportDeclarationSpecifier<'_>,
) -> Option<BoundImport> {
    let (local, kind, specifier_node) = match specifier {
        ImportDeclarationSpecifier::ImportSpecifier(specifier) => (
            &specifier.local,
            if module_export_name_is_default(&specifier.imported) {
                ImportKind::Default
            } else {
                ImportKind::Named
            },
            specifier.node_id.get(),
        ),
        ImportDeclarationSpecifier::ImportDefaultSpecifier(specifier) => (
            &specifier.local,
            ImportKind::Default,
            specifier.node_id.get(),
        ),
        ImportDeclarationSpecifier::ImportNamespaceSpecifier(specifier) => (
            &specifier.local,
            ImportKind::Namespace,
            specifier.node_id.get(),
        ),
    };
    let symbol = local.symbol_id.get()?;
    if !semantic.scoping().symbol_redeclarations(symbol).is_empty() {
        return None;
    }
    let declared = semantic.symbol_declaration(symbol);
    if declared.id() != specifier_node
        || semantic.nodes().parent_id(declared.id()) != declaration.id()
    {
        return None;
    }
    Some(BoundImport { symbol, kind })
}

/// `import { default as d }` imports the default under a named
/// specifier; the decorator treats it like a default import.
fn module_export_name_is_default(name: &ModuleExportName<'_>) -> bool {
    match name {
        ModuleExportName::IdentifierName(identifier) => identifier.name.as_str() == "default",
        ModuleExportName::IdentifierReference(identifier) => identifier.name.as_str() == "default",
        ModuleExportName::StringLiteral(literal) => literal.value.as_str() == "default",
    }
}

/// Collects the export positions for one imported binding. Returns
/// `None` when any resolved reference is not an export position — the
/// reference `references.length !== exports.length` gate.
fn export_sites(semantic: &Semantic<'_>, import: &BoundImport) -> Option<Vec<ExportSite>> {
    let mut sites = Vec::new();
    for &reference_id in semantic.scoping().get_resolved_reference_ids(import.symbol) {
        let reference = semantic.scoping().get_reference(reference_id);
        sites.push(export_site(semantic, reference.node_id())?);
    }
    // `import * as ns` re-exported as `export default ns` has no
    // `export…from` equivalent; the reference drops the pair.
    sites.retain(|site| {
        !(import.kind == ImportKind::Namespace && matches!(site, ExportSite::Default(_)))
    });
    Some(sites)
}

/// Classifies the export position a reference sits in by climbing past
/// parenthesized wrappers, mirroring the reference `getExported` shapes.
fn export_site(semantic: &Semantic<'_>, reference_node: NodeId) -> Option<ExportSite> {
    let nodes = semantic.nodes();
    let mut current = reference_node;
    while matches!(
        nodes.parent_kind(current),
        AstKind::ParenthesizedExpression(_)
    ) {
        current = nodes.parent_id(current);
    }
    match nodes.parent_kind(current) {
        AstKind::ExportSpecifier(specifier) => Some(ExportSite::Specifier {
            specifier: specifier.span,
            exported: specifier.exported.span(),
        }),
        AstKind::ExportDefaultDeclaration(declaration) => {
            Some(ExportSite::Default(declaration.span))
        }
        AstKind::VariableDeclarator(declarator) => {
            const_alias_site(semantic, declarator, nodes.parent_id(current))
        }
        _ => None,
    }
}

/// The `export const B = A` shape: a `const` declaration with a single
/// declarator whose identifier `B` carries no type annotation, whose
/// initializer is exactly the referenced identifier, and whose symbol is
/// otherwise unused, inside an `ExportDeclaration`.
fn const_alias_site(
    semantic: &Semantic<'_>,
    declarator: &VariableDeclarator<'_>,
    declarator_node: NodeId,
) -> Option<ExportSite> {
    let init = declarator.init.as_ref()?;
    if !matches!(unparenthesized(init), Expression::Identifier(_)) {
        return None;
    }
    let BindingPattern::BindingIdentifier(identifier) = &declarator.id else {
        return None;
    };
    if declarator.type_annotation.is_some() {
        return None;
    }
    let symbol = identifier.symbol_id.get()?;
    if !semantic
        .scoping()
        .get_resolved_reference_ids(symbol)
        .is_empty()
    {
        return None;
    }
    let nodes = semantic.nodes();
    let AstKind::VariableDeclaration(declaration) = nodes.parent_kind(declarator_node) else {
        return None;
    };
    if declaration.kind != VariableDeclarationKind::Const || declaration.declarations.len() != 1 {
        return None;
    }
    let declaration_node = nodes.parent_id(declarator_node);
    let AstKind::ExportDeclaration(export) = nodes.parent_kind(declaration_node) else {
        return None;
    };
    Some(ExportSite::ConstAlias {
        declaration: export.span,
        name: identifier.span,
    })
}

/// Whether the binding still has a reference outside `ExportSpecifier`
/// and `ExportDefaultDeclaration` positions — the decorator's
/// `hasLocalUsage` suppression for specifier and default reports. A
/// `const` alias initializer counts as local usage there even though it
/// is itself a reportable export.
fn has_local_usage(semantic: &Semantic<'_>, symbol: SymbolId) -> bool {
    let nodes = semantic.nodes();
    semantic
        .scoping()
        .get_resolved_reference_ids(symbol)
        .iter()
        .any(|&reference_id| {
            let reference = semantic.scoping().get_reference(reference_id);
            let mut current = reference.node_id();
            while matches!(
                nodes.parent_kind(current),
                AstKind::ParenthesizedExpression(_)
            ) {
                current = nodes.parent_id(current);
            }
            !matches!(
                nodes.parent_kind(current),
                AstKind::ExportSpecifier(_) | AstKind::ExportDefaultDeclaration(_)
            )
        })
}

fn emit_exports(
    sink: &mut IssueSink<'_>,
    ctx: &AnalysisContext,
    semantic: &Semantic<'_>,
    import: &BoundImport,
    sites: &[ExportSite],
) {
    for site in sites {
        match site {
            ExportSite::Specifier {
                specifier,
                exported,
            } => {
                // The decorator suppresses reports for names that
                // resolve to a default import or still have non-export
                // references.
                if import.kind == ImportKind::Default || has_local_usage(semantic, import.symbol) {
                    continue;
                }
                emit(sink, *specifier, span_text(ctx.source, *exported));
            }
            ExportSite::Default(span) => {
                if import.kind == ImportKind::Default || has_local_usage(semantic, import.symbol) {
                    continue;
                }
                emit(sink, *span, "default");
            }
            ExportSite::ConstAlias { declaration, name } => {
                if import.kind == ImportKind::Default {
                    continue;
                }
                emit(sink, *declaration, span_text(ctx.source, *name));
            }
        }
    }
}

fn emit(sink: &mut IssueSink<'_>, span: Span, exported: &str) {
    sink.emit_span(
        RuleScope::Both,
        "S7763",
        &format!("Use `export…from` to re-export `{exported}`."),
        span,
    );
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s7763_flags_named_reexport() {
        let source = "import { A } from \"./a\";\nexport { A };\n";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 1);
    }

    #[test]
    fn s7763_flags_javascript_too() {
        let source = "import { A } from \"./a\";\nexport { A };\n";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S7763"), 1);
    }

    #[test]
    fn s7763_flags_aliased_and_default_reexports() {
        let source = "\
import { A } from \"./a\";
import { B } from \"./b\";
import { C } from \"./c\";
export { A as Renamed };
export { B as default };
export default C;
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 3);
    }

    #[test]
    fn s7763_flags_namespace_and_const_alias_reexports() {
        let source = "\
import * as ns from \"./a\";
import { B } from \"./b\";
export { ns };
export const Alias = B;
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 2);
    }

    #[test]
    fn s7763_suppresses_default_import_reexports() {
        let source = "\
import d from \"./a\";
import { default as e } from \"./b\";
export { d };
export default e;
export const Alias = d;
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 0);
    }

    #[test]
    fn s7763_suppresses_locally_used_bindings() {
        let source = "\
import { A } from \"./a\";
import { B } from \"./b\";
export { A };
export const Alias = B;
use(A);
use(B);
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 0);
    }

    #[test]
    fn s7763_suppresses_specifier_when_binding_has_other_uses() {
        // `export const Alias = A` is itself a reportable export, but the
        // decorator counts its initializer as local usage of `A`, so the
        // `export { A }` specifier stays silent while the alias reports.
        let source = "import { A } from \"./a\";\nexport { A };\nexport const Alias = A;\n";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 1);
    }

    #[test]
    fn s7763_ignores_non_reexport_forms() {
        let source = "\
import \"./side-effect\";
import {} from \"./empty\";
import { A } from \"./a\";
const local = 1;
export { local };
export { A } from \"./a\";
export * from \"./a\";
export * as ns from \"./a\";
export function f() {}
export const value = 42;
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 0);
    }

    #[test]
    fn s7763_ignores_namespace_default_and_used_alias_names() {
        let source = "\
import * as ns from \"./a\";
import { B } from \"./b\";
export default ns;
export const Alias = B;
use(Alias);
";
        let keys = ts_keys(source);
        assert_eq!(count_key(&keys, "typescript:S7763"), 0);
    }
}
