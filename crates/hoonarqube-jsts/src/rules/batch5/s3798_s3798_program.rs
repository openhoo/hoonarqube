use super::collectors_hotspots::MiscCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Statement;
use oxc_ast::ast::VariableDeclarationKind;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl MiscCollector<'_> {
    /// `S3798` (JavaScript-only): global `var` / function declarations.
    ///
    /// Files that participate in the module system (`import`/`export`,
    /// `require`, `module`, `exports`) scope their top-level declarations
    /// locally, so the documented "should not be activated when modules are
    /// used" exclusion applies to the whole file.
    pub(crate) fn check_s3798_program(&mut self, it: &oxc_ast::ast::Program<'_>) {
        if program_participates_in_modules(it) {
            return;
        }
        for statement in &it.body {
            match statement {
                Statement::VariableDeclaration(declaration)
                    if declaration.kind == VariableDeclarationKind::Var =>
                {
                    for declarator in &declaration.declarations {
                        self.sink.emit_span(
                            RuleScope::JsOnly,
                            "S3798",
                            "Define this declaration in a local scope or bind explicitly the property to the global object.",
                            declarator.span(),
                        );
                    }
                }
                Statement::FunctionDeclaration(function) => {
                    self.sink.emit_span(
                        RuleScope::JsOnly,
                        "S3798",
                        "Define this declaration in a local scope or bind explicitly the property to the global object.",
                        function.span(),
                    );
                }
                _ => {}
            }
        }
    }
}

/// Whether the file takes part in the CommonJS/ESM module system: any
/// `import`/`export` declaration, or any reference to the module-scope
/// bindings `require`, `module`, or `exports`.
fn program_participates_in_modules(program: &oxc_ast::ast::Program<'_>) -> bool {
    let mut detector = ModuleMarkerDetector::default();
    detector.visit_program(program);
    detector.esm || detector.cjs_reference
}

/// Whether the file is a `CommonJS` module: `require`/`module`/`exports` module
/// markers (references or bindings — compiled TypeScript helpers reference
/// `exports` only as a parameter name) and no `import`/`export` declarations.
/// In `CommonJS`, top-level `this` is `module.exports`, not the global object.
pub(crate) fn program_is_commonjs(program: &oxc_ast::ast::Program<'_>) -> bool {
    let mut detector = ModuleMarkerDetector::default();
    detector.visit_program(program);
    !detector.esm && (detector.cjs_reference || detector.cjs_binding)
}

#[derive(Default)]
struct ModuleMarkerDetector {
    esm: bool,
    cjs_reference: bool,
    cjs_binding: bool,
}

impl Visit<'_> for ModuleMarkerDetector {
    fn visit_import_declaration(&mut self, _it: &oxc_ast::ast::ImportDeclaration<'_>) {
        self.esm = true;
    }

    fn visit_export_all_declaration(&mut self, _it: &oxc_ast::ast::ExportAllDeclaration<'_>) {
        self.esm = true;
    }

    fn visit_export_named_declaration(&mut self, _it: &oxc_ast::ast::ExportNamedDeclaration<'_>) {
        self.esm = true;
    }

    fn visit_export_from_declaration(&mut self, _it: &oxc_ast::ast::ExportFromDeclaration<'_>) {
        self.esm = true;
    }

    fn visit_export_default_declaration(
        &mut self,
        _it: &oxc_ast::ast::ExportDefaultDeclaration<'_>,
    ) {
        self.esm = true;
    }

    fn visit_identifier_reference(&mut self, it: &oxc_ast::ast::IdentifierReference<'_>) {
        if matches!(it.name.as_str(), "require" | "module" | "exports") {
            self.cjs_reference = true;
        }
    }

    fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'_>) {
        if matches!(it.name.as_str(), "require" | "module" | "exports") {
            self.cjs_binding = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn module_files_never_report_global_declarations() {
        let commonjs = js(
            "'use strict';\nvar express = require('express');\nvar path = require('path');\nfunction helper() { return 1; }\nmodule.exports = { express, path, helper };\n",
        );
        assert_eq!(count_key(&report_keys(&commonjs), "javascript:S3798"), 0);

        let esm = js(
            "import fs from 'node:fs';\nvar fallback = 'value';\nfunction load() { return fs; }\nexport { fallback, load };\n",
        );
        assert_eq!(count_key(&report_keys(&esm), "javascript:S3798"), 0);

        let exports_reference = js("var app = exports.app = {};\nfunction boot() {}\n");
        assert_eq!(
            count_key(&report_keys(&exports_reference), "javascript:S3798"),
            0
        );
    }

    #[test]
    fn plain_script_globals_still_report() {
        let script = js("var counter = 0;\nfunction tick() {}\n");
        assert_eq!(count_key(&report_keys(&script), "javascript:S3798"), 2);

        let typescript = ts("var counter = 0;\nfunction tick() {}\n");
        assert_eq!(count_key(&report_keys(&typescript), "typescript:S3798"), 0);
    }
}
