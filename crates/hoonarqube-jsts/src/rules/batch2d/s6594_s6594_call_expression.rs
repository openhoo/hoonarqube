// Rule module s6594_s6594_call_expression (generated).
use crate::JstsLanguage;
use crate::rules::shared::{argument_expression, call_property};
use crate::support::{IssueSink, LineIndex, RuleScope, unparenthesized};
use hoonarqube_ir::Issue;
use oxc_allocator::Allocator;
use oxc_ast::ast::{
    BindingIdentifier, CallExpression, Declaration, Expression, ImportDeclaration,
    ImportDeclarationSpecifier, MemberExpression, ModuleExportName, RegExpFlags, Statement,
    VariableDeclaration, VariableDeclarationKind, VariableDeclarator,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_call_expression, walk_variable_declaration};
use oxc_parser::Parser;
use oxc_semantic::{Semantic, SymbolId};
use oxc_span::{SourceType, Span};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

/// `S6594`: `.match(…)` prefers `RegExp.exec()` unless the argument carries
/// the global flag.
///
/// The native detector deliberately keeps the upstream syntax gate broad:
/// type information is unavailable here, so the semantic String receiver
/// proof belongs to the quick-fix collector. This preserves findings for
/// unresolved receivers while never attaching an unsafe edit.
///
/// The argument resolves one conservative step past the direct literal: a
/// same-file `const` binding of a regex literal, or an import specifier
/// whose module exports a const regex literal (`#199`). Symbol-keyed
/// resolution keeps shadowed names out, `let`/`var` bindings and arbitrary
/// dynamic values stay untracked, and the `g` exclusion carries over to
/// aliases.
pub(crate) fn check_s6594_match_calls<'a>(
    program: &'a oxc_ast::ast::Program<'a>,
    index: &LineIndex<'_>,
    language: JstsLanguage,
    path: &Path,
    semantic: Option<&'a Semantic<'a>>,
) -> Vec<Issue> {
    let constants = S6594RegexConstants::collect(program, semantic, path);
    let mut collector = S6594Collector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        semantic,
        constants,
    };
    collector.visit_program(program);
    collector.sink.issues
}

struct S6594Collector<'index, 'a> {
    sink: IssueSink<'index>,
    semantic: Option<&'index Semantic<'a>>,
    constants: S6594RegexConstants,
}

impl<'a> Visit<'a> for S6594Collector<'_, 'a> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_match_call(it);
        walk_call_expression(self, it);
    }
}

impl S6594Collector<'_, '_> {
    fn check_match_call(&mut self, it: &CallExpression<'_>) {
        let Some((property, member)) = call_property(it) else {
            return;
        };
        if property != "match" || it.arguments.len() != 1 {
            return;
        }
        let Some(argument) = it.arguments.first().and_then(argument_expression) else {
            return;
        };
        // Direct literal: unchanged behavior including the global exclusion.
        if let Expression::RegExpLiteral(literal) = unparenthesized(argument) {
            if !literal.regex.flags.contains(RegExpFlags::G) {
                self.emit_match(member);
            }
            return;
        }
        let Expression::Identifier(reference) = unparenthesized(argument) else {
            return;
        };
        if self
            .constants
            .argument_is_non_global_regex(reference, self.semantic)
        {
            self.emit_match(member);
        }
    }

    /// Same anchor as the direct-literal finding: the `match` property.
    fn emit_match(&mut self, member: &MemberExpression<'_>) {
        self.sink.emit_span(
            RuleScope::Both,
            "S6594",
            "Use the \"RegExp.exec()\" method instead.",
            member_property_span(member),
        );
    }
}

fn member_property_span(member: &MemberExpression<'_>) -> Span {
    match member {
        MemberExpression::StaticMemberExpression(member) => member.property.span,
        _ => Span::sized(0, 0),
    }
}

/// Same-file and imported regex-constant provenance behind `#199`.
#[derive(Default)]
struct S6594RegexConstants {
    /// Const bindings initialized to a non-global regex literal.
    non_global: HashSet<SymbolId>,
    /// Import bindings awaiting resolution against their module's exports.
    imported: HashMap<SymbolId, ImportedRegexBinding>,
    /// Lazily loaded export tables (exported name → `Some(global)` for a
    /// literal regex, `None` for any other value) per resolved module path.
    module_exports: HashMap<PathBuf, Option<HashMap<String, Option<bool>>>>,
    /// Directory of the analyzed file; import specifiers resolve against it.
    base: Option<PathBuf>,
}

/// One `import { name } from "specifier"` binding awaiting module lookup.
struct ImportedRegexBinding {
    specifier: String,
    imported: String,
}

#[derive(Default)]
struct ConstRegexCollector {
    non_global: HashSet<SymbolId>,
    imported: HashMap<SymbolId, ImportedRegexBinding>,
}

impl<'a> Visit<'a> for ConstRegexCollector {
    fn visit_variable_declaration(&mut self, it: &VariableDeclaration<'a>) {
        // Only `const` bindings keep their initializer's identity; a
        // rebindable `let`/`var` alias would be a guess.
        if it.kind == VariableDeclarationKind::Const {
            for declarator in &it.declarations {
                self.collect_declarator(declarator);
            }
        }
        walk_variable_declaration(self, it);
    }

    fn visit_import_declaration(&mut self, it: &ImportDeclaration<'a>) {
        if !it.import_kind.is_type()
            && let Some(specifiers) = &it.specifiers
        {
            let specifier = it.source.value.to_string();
            for entry in specifiers {
                self.collect_specifier(&specifier, entry);
            }
        }
    }
}

impl ConstRegexCollector {
    fn collect_declarator(&mut self, declarator: &VariableDeclarator<'_>) {
        let Some(init) = declarator.init.as_ref() else {
            return;
        };
        let Expression::RegExpLiteral(literal) = unparenthesized(init) else {
            return;
        };
        if literal.regex.flags.contains(RegExpFlags::G) {
            return; // the global exclusion carries over to aliases
        }
        if let Some(symbol) = declarator
            .id
            .get_binding_identifier()
            .map(BindingIdentifier::symbol_id)
        {
            self.non_global.insert(symbol);
        }
    }

    fn collect_specifier(&mut self, specifier: &str, entry: &ImportDeclarationSpecifier<'_>) {
        let (local, binding) = match entry {
            ImportDeclarationSpecifier::ImportSpecifier(entry) => {
                if entry.import_kind.is_type() {
                    return;
                }
                (
                    entry.local.symbol_id(),
                    ImportedRegexBinding {
                        specifier: specifier.to_string(),
                        imported: module_export_name(&entry.imported),
                    },
                )
            }
            ImportDeclarationSpecifier::ImportDefaultSpecifier(entry) => (
                entry.local.symbol_id(),
                ImportedRegexBinding {
                    specifier: specifier.to_string(),
                    imported: "default".to_string(),
                },
            ),
            // `import * as ns` has no single constant value to resolve.
            ImportDeclarationSpecifier::ImportNamespaceSpecifier(_) => return,
        };
        self.imported.insert(local, binding);
    }
}

/// The exported name an import specifier refers to.
fn module_export_name(name: &ModuleExportName<'_>) -> String {
    match name {
        ModuleExportName::IdentifierName(name) => name.name.to_string(),
        ModuleExportName::IdentifierReference(reference) => reference.name.to_string(),
        ModuleExportName::StringLiteral(literal) => literal.value.to_string(),
    }
}

impl S6594RegexConstants {
    fn collect(
        program: &oxc_ast::ast::Program<'_>,
        semantic: Option<&Semantic<'_>>,
        path: &Path,
    ) -> Self {
        if semantic.is_none() {
            // Without symbol provenance the pass stays silent rather than
            // guessing from names alone.
            return Self::default();
        }
        let mut collector = ConstRegexCollector::default();
        collector.visit_program(program);
        Self {
            non_global: collector.non_global,
            imported: collector.imported,
            module_exports: HashMap::new(),
            base: path.parent().map(Path::to_path_buf),
        }
    }

    /// Whether the `.match(name)` argument resolves to a tracked non-global
    /// regex literal, same file or imported.
    fn argument_is_non_global_regex(
        &mut self,
        reference: &oxc_ast::ast::IdentifierReference<'_>,
        semantic: Option<&Semantic<'_>>,
    ) -> bool {
        let Some(symbol) = semantic.and_then(|semantic| {
            semantic
                .scoping()
                .get_reference(reference.reference_id())
                .symbol_id()
        }) else {
            return false;
        };
        if self.non_global.contains(&symbol) {
            return true;
        }
        let Some((specifier, imported)) = self
            .imported
            .get(&symbol)
            .map(|binding| (binding.specifier.clone(), binding.imported.clone()))
        else {
            return false;
        };
        self.imported_is_non_global_regex(&specifier, &imported)
    }

    /// Resolves an imported binding against its module's export table; each
    /// module file is read and parsed at most once per analyzed file.
    fn imported_is_non_global_regex(&mut self, specifier: &str, imported: &str) -> bool {
        let Some(base) = &self.base else {
            return false;
        };
        let Some(module_path) = resolve_module_path(base, specifier) else {
            return false;
        };
        if !self.module_exports.contains_key(&module_path) {
            let table = load_module_export_table(&module_path);
            self.module_exports.insert(module_path.clone(), table);
        }
        self.module_exports
            .get(&module_path)
            .and_then(|table| {
                table
                    .as_ref()
                    .and_then(|table| table.get(imported))
                    .copied()
            })
            .flatten()
            == Some(false)
    }
}

/// Relative specifiers only; bare and absolute imports stay opaque.
fn resolve_module_path(base: &Path, specifier: &str) -> Option<PathBuf> {
    if !(specifier.starts_with("./") || specifier.starts_with("../")) || specifier.contains('\0') {
        return None;
    }
    let joined = base.join(specifier);
    const EXTENSIONS: [&str; 6] = ["ts", "tsx", "mts", "cts", "js", "mjs"];
    let mut candidates = vec![joined.clone()];
    for extension in EXTENSIONS {
        candidates.push(joined.with_extension(extension));
    }
    for extension in EXTENSIONS {
        candidates.push(joined.join(format!("index.{extension}")));
    }
    candidates.into_iter().find(|candidate| candidate.is_file())
}

/// Upper bound on an imported module's source size before it is parsed.
const MODULE_SOURCE_LIMIT: u64 = 1 << 20;

/// Exported const regex literals of one module, keyed by exported name.
fn load_module_export_table(path: &Path) -> Option<HashMap<String, Option<bool>>> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() || metadata.len() > MODULE_SOURCE_LIMIT {
        return None;
    }
    let source = std::fs::read_to_string(path).ok()?;
    let source_type = SourceType::from_path(path).ok()?;
    let allocator = Allocator::default();
    let parsed = Parser::new(&allocator, &source, source_type).parse();
    if parsed.diagnostics.errors().next().is_some() {
        return None;
    }
    let mut table = HashMap::new();
    collect_module_regex_exports(parsed.program.body.as_slice(), &mut table);
    Some(table)
}

/// Records `export const NAME = /regex/` and `export { NAME }` pairs from
/// the module's top level.
fn collect_module_regex_exports(
    statements: &[Statement<'_>],
    table: &mut HashMap<String, Option<bool>>,
) {
    let mut locals: HashMap<String, Option<bool>> = HashMap::new();
    for statement in statements {
        if let Statement::VariableDeclaration(declaration) = statement {
            collect_const_regex_declarators(declaration, &mut locals);
        }
    }
    for statement in statements {
        match statement {
            // `export const NAME = /regex/`
            Statement::ExportDeclaration(export) => {
                if let Declaration::VariableDeclaration(declaration) = &export.declaration {
                    collect_const_regex_declarators(declaration, table);
                }
            }
            // `export { NAME }` / `export { NAME as ALIAS }`
            Statement::ExportNamedDeclaration(export) => {
                if export.export_kind.is_type() {
                    continue;
                }
                for specifier in &export.specifiers {
                    if specifier.export_kind.is_type() {
                        continue;
                    }
                    let local = module_export_name(&specifier.local);
                    let exported = module_export_name(&specifier.exported);
                    table.insert(exported, locals.get(&local).copied().flatten());
                }
            }
            _ => {}
        }
    }
}

/// Records one entry per top-level `const` declarator of a module.
fn collect_const_regex_declarators(
    declaration: &VariableDeclaration<'_>,
    table: &mut HashMap<String, Option<bool>>,
) {
    if declaration.kind != VariableDeclarationKind::Const {
        return;
    }
    for declarator in &declaration.declarations {
        let Some(init) = declarator.init.as_ref() else {
            continue;
        };
        let Some(name) = declarator
            .id
            .get_binding_identifier()
            .map(|identifier| identifier.name.to_string())
        else {
            continue;
        };
        table.insert(
            name,
            match unparenthesized(init) {
                Expression::RegExpLiteral(literal) => {
                    Some(literal.regex.flags.contains(RegExpFlags::G))
                }
                _ => None,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn s6594_flags_nonglobal_regex_constants() {
        // #199: the alias carries the same non-global regex value as the
        // direct literal, so both call shapes report while `/a/g` stays
        // excluded.
        let findings = js_keys(
            "const alias = /a/;\nconst direct = 'a'.match(/a/);\nconst viaAlias = 'a'.match(alias);\nconst global = 'a'.match(/a/g);\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6594"), 2);
    }

    #[test]
    fn s6594_keeps_shadowed_rebindable_and_dynamic_arguments_clean() {
        // A shadowing parameter resolves to a different, untracked binding.
        let shadowed =
            js_keys("const alias = /a/;\nfunction parse(alias) {\n  return 'x'.match(alias);\n}\n");
        assert_eq!(count_key(&shadowed, "javascript:S6594"), 0);

        // `let` bindings can be reassigned, so they stay untracked.
        let rebindable = js_keys("let alias = /a/;\nconst found = 'a'.match(alias);\n");
        assert_eq!(count_key(&rebindable, "javascript:S6594"), 0);

        // A global-flag alias keeps its existing exclusion.
        let global_alias = js_keys("const alias = /a/g;\nconst found = 'a'.match(alias);\n");
        assert_eq!(count_key(&global_alias, "javascript:S6594"), 0);

        // Non-regex and dynamic arguments are not inferred.
        let string_alias = js_keys("const alias = 'a';\nconst found = 'a'.match(alias);\n");
        assert_eq!(count_key(&string_alias, "javascript:S6594"), 0);
        let dynamic = js_keys("const found = 'a'.match(makeRegex());\n");
        assert_eq!(count_key(&dynamic, "javascript:S6594"), 0);
    }

    #[test]
    fn s6594_resolves_imported_regex_constants() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let workspace =
            std::env::temp_dir().join(format!("hoonarqube-s6594-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&workspace).expect("temp workspace");
        std::fs::write(
            workspace.join("html_re.ts"),
            "export const TAG_RE = /<a>/;\nexport const GLOBAL_TAG_RE = /<a>/g;\n",
        )
        .expect("module fixture");
        let importer_path = workspace.join("html_inline.ts");
        let importer = "import { TAG_RE, GLOBAL_TAG_RE } from './html_re.ts';\nconst first = 'x'.match(TAG_RE);\nconst second = 'x'.match(GLOBAL_TAG_RE);\n";
        std::fs::write(&importer_path, importer).expect("importer fixture");

        let report = crate::analyze(
            importer_path.clone(),
            importer,
            crate::JstsLanguage::TypeScript,
            &crate::AnalyzerOptions::default(),
        );
        let flagged = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "typescript:S6594")
            .count();
        assert_eq!(flagged, 1);

        let _ = std::fs::remove_dir_all(&workspace);
    }
}
