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
    detector.esm || detector.reference_markers != 0
}

/// Whether the file is a `CommonJS` module: `require`/`module`/`exports` module
/// markers (references or bindings — compiled TypeScript helpers reference
/// `exports` only as a parameter name) and no `import`/`export` declarations.
/// In `CommonJS`, top-level `this` is `module.exports`, not the global object.
pub(crate) fn program_is_commonjs(program: &oxc_ast::ast::Program<'_>) -> bool {
    let mut detector = ModuleMarkerDetector::default();
    detector.visit_program(program);
    !detector.esm && detector.reference_markers | detector.binding_markers != 0
}

/// Whether the file uses `CommonJS` output markers (`module`/`exports`
/// references or bindings) without `import`/`export` declarations. Unlike
/// [`program_is_commonjs`], a bare `require(...)` call alone does not mark
/// the file `CommonJS` — `S3533` still flags a lone `require` in a plain
/// `.js` source, while compiled `CommonJS` output always writes `exports`.
pub(crate) fn program_has_commonjs_markers(program: &oxc_ast::ast::Program<'_>) -> bool {
    let mut detector = ModuleMarkerDetector::default();
    detector.visit_program(program);
    !detector.esm
        && (detector.reference_markers | detector.binding_markers)
            & (MARKER_MODULE | MARKER_EXPORTS)
            != 0
}

const MARKER_REQUIRE: u8 = 1;
const MARKER_MODULE: u8 = 2;
const MARKER_EXPORTS: u8 = 4;

#[derive(Default)]
struct ModuleMarkerDetector {
    /// `import`/`export` declaration seen — the file is an ES module.
    esm: bool,
    /// Bitmask of `require`/`module`/`exports` identifier references.
    reference_markers: u8,
    /// Bitmask of `require`/`module`/`exports` bindings (compiled
    /// TypeScript helpers bind `exports` as a parameter name).
    binding_markers: u8,
}

impl ModuleMarkerDetector {
    fn note_identifier(&mut self, name: &str, binding: bool) {
        let marker = match name {
            "require" => MARKER_REQUIRE,
            "module" => MARKER_MODULE,
            "exports" => MARKER_EXPORTS,
            _ => 0,
        };
        if binding {
            self.binding_markers |= marker;
        } else {
            self.reference_markers |= marker;
        }
    }
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
        self.note_identifier(it.name.as_str(), false);
    }

    fn visit_binding_identifier(&mut self, it: &oxc_ast::ast::BindingIdentifier<'_>) {
        self.note_identifier(it.name.as_str(), true);
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
