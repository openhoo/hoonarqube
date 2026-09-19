// ---------------------------------------------------------------------------
// Shared Pydantic provenance helpers for the python:S8396, python:S8953,
// python:S8963, python:S8966, python:S8971, and python:S8973 detectors.
//
// The reference checks lean on SonarPython's type system: imported names
// resolve to fully-qualified names (FQNs), `isOrExtendsType` walks the C3
// MRO, and `Expressions.singleAssignedValue` resolves a name to the
// expression its single assignment bound. Hoonarqube has no third-party
// stubs, so this module approximates the same facts from the file's own
// import statements, class definitions, and symbol table:
//
// * [`ImportFqns`] maps each locally bound name to its import FQN, so a
//   dotted expression resolves the same way the reference's `isType` /
//   `withFQN` matchers do — by the path it was imported under, not the
//   definition site inside the package.
// * [`ClassIndex`] resolves in-file class bases transitively, which stands
//   in for the MRO walk: a class is a Pydantic model when any ancestor
//   resolves to `pydantic.BaseModel` (or a known BaseModel subclass such
//   as `RootModel`/`BaseSettings`), and `model_config` definers are the
//   in-file ancestors that assign `model_config` plus the synthetic
//   Pydantic root (whose own `model_config` member the reference sees).
// * [`NameResolver`] mirrors `singleAssignedValue`: a name resolves to its
//   bound expression only when the resolved scope holds exactly one
//   assignment binding for it; every other shape (parameters, imports,
//   multiple writes, tuple/loop/with/except/walrus bindings, unbound
//   names) stays ambiguous. Files using `eval`/`exec`/`locals`/`globals`
//   disable resolution entirely, matching the symbol layer's own veto.
// ---------------------------------------------------------------------------

use std::collections::{HashMap, HashSet};

use ruff_python_ast::{Expr, ModModule, Stmt, StmtClassDef, StmtImportFrom};
use ruff_python_parser::Parsed;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::{AnyImport, FileContext};
use crate::engine::scope::{BindingKind, SymbolTable, build_symbol_table, collect_file_facts};
use crate::support::dotted_segments;

/// FQNs the reference's `isOrExtendsType("pydantic.BaseModel")` accepts as
/// the model root, plus the known `BaseModel` subclasses whose own FQN the
/// import path can surface (`RootModel`, v1 `BaseSettings`, and the
/// `pydantic-settings` package).
const BASE_MODEL_FQNS: &[&str] = &[
    "pydantic.BaseModel",
    "pydantic.main.BaseModel",
    "pydantic.RootModel",
    "pydantic.root_model.RootModel",
    "pydantic.BaseSettings",
    "pydantic_settings.BaseSettings",
];

/// Local-name → import-FQN bindings collected from the file's import
/// statements. Wildcard from-imports bind nothing (their names are
/// unknowable without the target module).
pub(crate) struct ImportFqns {
    bindings: HashMap<String, String>,
}

impl ImportFqns {
    pub(crate) fn build(file_ctx: &FileContext) -> Self {
        let mut bindings = HashMap::new();
        for import in &file_ctx.imports {
            match import {
                AnyImport::Plain(import) => {
                    for alias in &import.names {
                        let bound = bound_name(alias);
                        bindings.insert(bound, alias.name.as_str().to_string());
                    }
                }
                AnyImport::From(import) => collect_from_imports(import, &mut bindings),
            }
        }
        Self { bindings }
    }

    /// The FQN of a `Name`/`Attribute` chain: the root segment's import
    /// binding when present, otherwise the dotted path as written (which
    /// covers `import pydantic` module roots and unresolvable names).
    pub(crate) fn resolve(&self, expr: &Expr) -> Option<String> {
        let segments = dotted_segments(expr)?;
        let (root, rest) = segments.split_first()?;
        match self.bindings.get(*root) {
            Some(fqn) if rest.is_empty() => Some(fqn.clone()),
            Some(fqn) => Some(format!("{}.{}", fqn, rest.join("."))),
            None => Some(segments.join(".")),
        }
    }

    /// Whether `expr` is a name/attribute chain whose FQN is `expected`.
    pub(crate) fn is_fqn(&self, expr: &Expr, expected: &str) -> bool {
        self.resolve(expr).as_deref() == Some(expected)
    }

    /// Whether `expr` resolves to one of `candidates`.
    pub(crate) fn is_fqn_in(&self, expr: &Expr, candidates: &[&str]) -> bool {
        self.resolve(expr)
            .is_some_and(|fqn| candidates.contains(&fqn.as_str()))
    }
}

/// The name an import alias binds: `asname` when present, else the
/// imported name itself.
fn bound_name(alias: &ruff_python_ast::Alias) -> String {
    alias.asname.as_ref().map_or_else(
        || alias.name.as_str().to_string(),
        |a| a.as_str().to_string(),
    )
}

/// Binds `from <module> import <name> [as <asname>]` entries to their
/// `<module>.<name>` FQNs. Relative imports and wildcard names bind
/// nothing.
fn collect_from_imports(import: &StmtImportFrom, bindings: &mut HashMap<String, String>) {
    if import.level != 0 {
        return;
    }
    let Some(module) = import
        .module
        .as_ref()
        .map(ruff_python_ast::Identifier::as_str)
    else {
        return;
    };
    for alias in &import.names {
        if alias.name.as_str() == "*" {
            continue;
        }
        let bound = bound_name(alias);
        bindings.insert(bound, format!("{}.{}", module, alias.name.as_str()));
    }
}

/// In-file class definitions keyed by class name, used to resolve base
/// classes transitively. Later definitions of the same name win, matching
/// module-level rebinding semantics.
pub(crate) struct ClassIndex<'a> {
    classes: HashMap<String, &'a StmtClassDef>,
}

impl<'a> ClassIndex<'a> {
    pub(crate) fn build(file_ctx: &FileContext<'a>) -> Self {
        let mut classes = HashMap::new();
        for class in &file_ctx.classes {
            classes.insert(class.name.as_str().to_string(), *class);
        }
        Self { classes }
    }

    /// The in-file class bound to `name`, if any.
    pub(crate) fn local_class(&self, name: &str) -> Option<&'a StmtClassDef> {
        self.classes.get(name).copied()
    }

    /// The in-file class a base expression refers to: a bare `Name`, or a
    /// subscripted generic like `LocalModel[int]`.
    fn base_class(&self, base: &Expr) -> Option<&'a StmtClassDef> {
        let head = match base {
            Expr::Subscript(subscript) => subscript.value.as_ref(),
            other => other,
        };
        let Expr::Name(name) = head else {
            return None;
        };
        self.local_class(name.id.as_str())
    }

    /// Whether `class` is a Pydantic model: any base — its own or an
    /// in-file ancestor's — resolves to a `pydantic.BaseModel` FQN.
    /// Unresolvable bases are treated as non-models (the reference only
    /// reports what its type system can prove).
    pub(crate) fn is_pydantic_model(&self, class: &StmtClassDef, fqns: &ImportFqns) -> bool {
        let mut visited = HashSet::new();
        self.any_base_matches(class, fqns, &mut visited, |fqn| {
            BASE_MODEL_FQNS.contains(&fqn)
        })
    }

    /// Depth-first walk over the transitive in-file base closure; `matches`
    /// decides whether a resolved base FQN ends the search. Cycle-safe.
    fn any_base_matches(
        &self,
        class: &StmtClassDef,
        fqns: &ImportFqns,
        visited: &mut HashSet<TextRange>,
        matches: impl Fn(&str) -> bool + Copy,
    ) -> bool {
        if !visited.insert(class.name.range()) {
            return false;
        }
        let Some(arguments) = &class.arguments else {
            return false;
        };
        for base in &arguments.args {
            if let Some(fqn) = fqns.resolve(base)
                && matches(&fqn)
            {
                return true;
            }
            if let Some(parent) = self.base_class(base)
                && self.any_base_matches(parent, fqns, visited, matches)
            {
                return true;
            }
        }
        false
    }

    /// The classes in `base`'s MRO that define `model_config` locally:
    /// every in-file ancestor assigning `model_config`, plus the synthetic
    /// root when the chain reaches a `pydantic.BaseModel` FQN (the
    /// reference sees `BaseModel.model_config` as a member). Bases that
    /// resolve to nothing contribute no definers.
    pub(crate) fn model_config_definers(
        &self,
        base: &Expr,
        fqns: &ImportFqns,
    ) -> HashSet<ConfigDefiner> {
        let mut definers = HashSet::new();
        if fqns
            .resolve(base)
            .is_some_and(|fqn| BASE_MODEL_FQNS.contains(&fqn.as_str()))
        {
            definers.insert(ConfigDefiner::PydanticRoot);
        }
        let mut visited = HashSet::new();
        if let Some(class) = self.base_class(base) {
            self.collect_config_definers(class, fqns, &mut visited, &mut definers);
        }
        definers
    }

    fn collect_config_definers(
        &self,
        class: &StmtClassDef,
        fqns: &ImportFqns,
        visited: &mut HashSet<TextRange>,
        definers: &mut HashSet<ConfigDefiner>,
    ) {
        if !visited.insert(class.name.range()) {
            return;
        }
        if defines_model_config_locally(class) {
            definers.insert(ConfigDefiner::Class(class.name.range()));
        }
        let Some(arguments) = &class.arguments else {
            return;
        };
        for base in &arguments.args {
            if fqns
                .resolve(base)
                .is_some_and(|fqn| BASE_MODEL_FQNS.contains(&fqn.as_str()))
            {
                definers.insert(ConfigDefiner::PydanticRoot);
            }
            if let Some(parent) = self.base_class(base) {
                self.collect_config_definers(parent, fqns, visited, definers);
            }
        }
    }
}

/// Identity of a `model_config` definer in a base's MRO: an in-file
/// class keyed by its name range, or the synthetic Pydantic root that
/// carries `BaseModel`'s own `model_config` member.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ConfigDefiner {
    Class(TextRange),
    PydanticRoot,
}

/// Whether the class body assigns `model_config` directly (`model_config =
/// …`, `model_config: … = …`, or a bare `model_config: …` declaration), or
/// binds the name through a nested `def`/`class` — the member-presence test
/// the reference's `ClassType.members()` performs.
pub(crate) fn defines_model_config_locally(class: &StmtClassDef) -> bool {
    class.body.iter().any(|stmt| match stmt {
        Stmt::Assign(assign) => assign
            .targets
            .iter()
            .any(|target| is_named(target, "model_config")),
        Stmt::AnnAssign(assign) => is_named(&assign.target, "model_config"),
        Stmt::FunctionDef(function) => function.name.as_str() == "model_config",
        Stmt::ClassDef(nested) => nested.name.as_str() == "model_config",
        _ => false,
    })
}

fn is_named(expr: &Expr, expected: &str) -> bool {
    matches!(expr, Expr::Name(name) if name.id.as_str() == expected)
}

/// The outcome of resolving a `Name` to the expression it was bound to.
#[derive(Clone, Copy)]
pub(crate) enum NameValue<'a> {
    /// No binding in the resolved scope (builtin or external name).
    Unbound,
    /// Bound, but not by exactly one plain assignment (parameter, import,
    /// multiple writes, tuple/loop/with/except/walrus/def/class binding).
    Ambiguous,
    /// Exactly one `name = expr` or `name: T = expr` binding in scope.
    Single(&'a Expr),
}

/// `Expressions.singleAssignedValue` approximation: resolves a `Name` load
/// through the symbol table to the expression its single assignment bound.
/// Built once per file; `resolve` is O(1) per name.
pub(crate) struct NameResolver<'a> {
    values: HashMap<TextRange, &'a Expr>,
    loads: HashMap<TextRange, (usize, String)>,
    table: SymbolTable,
    dynamic: bool,
}

impl<'a> NameResolver<'a> {
    pub(crate) fn build(parsed: &'a Parsed<ModModule>, source: &str) -> Self {
        let table = build_symbol_table(parsed);
        let facts = collect_file_facts(parsed, source);
        let mut values: HashMap<TextRange, &'a Expr> = HashMap::new();
        collect_assigned_values(parsed.syntax().body.as_slice(), &mut values);
        let mut loads = HashMap::new();
        for load in &table.resolved_loads {
            if let Some(target) = load.target {
                loads.insert(load.range, (target, load.name.clone()));
            }
        }
        Self {
            values,
            loads,
            table,
            dynamic: facts.dynamic_names,
        }
    }

    /// Resolves `expr` (a `Name`) to its single assigned value. Names the
    /// load table did not record — or names in `eval`/`exec` files — stay
    /// ambiguous.
    pub(crate) fn resolve(&self, expr: &'a Expr) -> NameValue<'a> {
        let Expr::Name(name) = expr else {
            return NameValue::Ambiguous;
        };
        if self.dynamic {
            return NameValue::Ambiguous;
        }
        let Some((scope, _)) = self.loads.get(&name.range()) else {
            return NameValue::Unbound;
        };
        let Some(bindings) = self.table.scopes[*scope].bindings.get(name.id.as_str()) else {
            return NameValue::Unbound;
        };
        let [binding] = bindings.as_slice() else {
            return NameValue::Ambiguous;
        };
        if binding.kind != BindingKind::Assignment {
            return NameValue::Ambiguous;
        }
        self.values
            .get(&binding.range)
            .map_or(NameValue::Ambiguous, |value| NameValue::Single(value))
    }

    /// Resolves `expr` (a `Name`) to every expression its assignment
    /// bindings recorded — the `valuesAtLocation` shape the reference's
    /// reaching-definitions analysis produces for names with several
    /// candidate values (for example both branches of a conditional).
    /// Empty when the name is unbound, dynamically bound, or bound by
    /// anything but plain assignments; callers treat an empty result as
    /// "no provable values", never as "provably none".
    pub(crate) fn resolve_all(&self, expr: &'a Expr) -> Vec<&'a Expr> {
        let Expr::Name(name) = expr else {
            return Vec::new();
        };
        if self.dynamic {
            return Vec::new();
        }
        let Some((scope, _)) = self.loads.get(&name.range()) else {
            return Vec::new();
        };
        let Some(bindings) = self.table.scopes[*scope].bindings.get(name.id.as_str()) else {
            return Vec::new();
        };
        if bindings
            .iter()
            .any(|binding| binding.kind != BindingKind::Assignment)
        {
            return Vec::new();
        }
        // A binding without a recorded value (tuple/loop targets, bare
        // annotations) means the name's values are not fully provable —
        // the `Option` collect vetoes the whole resolution.
        bindings
            .iter()
            .map(|binding| self.values.get(&binding.range).copied())
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default()
    }
}

/// Maps each single-`Name` assignment target range to its value expression.
/// Chained targets (`x = y = v`) each record the same value, matching the
/// reference's single-write counting; tuple targets, annotated targets
/// without a value, and non-`Name` targets record nothing (their bindings
/// resolve as ambiguous).
fn collect_assigned_values<'a>(stmts: &'a [Stmt], values: &mut HashMap<TextRange, &'a Expr>) {
    crate::support::for_each_stmt(stmts, &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                if let Expr::Name(name) = target {
                    values.insert(name.range(), &assign.value);
                }
            }
        }
        Stmt::AnnAssign(assign) => {
            if let (Expr::Name(name), Some(value)) =
                (assign.target.as_ref(), assign.value.as_deref())
            {
                values.insert(name.range(), value);
            }
        }
        _ => {}
    });
}
