use super::Span;
use std::collections::HashMap;

// ===========================================================================
// Tier B — file-local scope/symbol table
//
// One traversal records declarations plus every identifier event together
// with its innermost scope. Resolution follows parent links after the walk
// finishes: lexical scoping ignores textual order, so a reference that
// precedes its declaration must still resolve to it (use-before-definition
// rules depend on exactly that).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TbKind {
    Var,
    Let,
    Const,
    Function,
    Class,
    Param,
    CatchParam,
    Import,
}

impl TbKind {
    /// Bindings `javascript:S1481` may flag as unused locals.
    pub(crate) fn is_local_value(self) -> bool {
        matches!(
            self,
            Self::Var | Self::Let | Self::Const | Self::Function | Self::Class
        )
    }
}

pub(crate) struct TbBinding<'a> {
    pub(crate) name: &'a str,
    pub(crate) kind: TbKind,
    /// Span of the declared name (declarator id, parameter, import local).
    pub(crate) decl: Span,
    pub(crate) reads: Vec<Span>,
    pub(crate) writes: Vec<Span>,
    /// For `var` declared inside a nested block: the innermost enclosing
    /// block span (`javascript:S2392`).
    pub(crate) home_block: Option<Span>,
    /// Signature shape when this binding names a function declaration
    /// (`javascript:S930` / `S4623`).
    pub(crate) arity: Option<TbSignature>,
    /// Declared at program/module top level (`S1481` exempts globals).
    pub(crate) global: bool,
    /// Initialized from an array literal (`javascript:S2870`).
    pub(crate) array_like: bool,
}

/// Aggregated shape of one function signature.
pub(crate) struct TbSignature {
    pub(crate) minimum: usize,
    pub(crate) maximum: Option<usize>,
    pub(crate) optional: Vec<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TbScopeKind {
    Program,
    Function,
    Block,
}

pub(crate) struct TbScope {
    pub(crate) parent: Option<usize>,
    pub(crate) kind: TbScopeKind,
    pub(crate) span: Span,
    pub(crate) bindings: Vec<usize>,
}

/// One identifier occurrence awaiting resolution.
pub(crate) struct TbEvent<'a> {
    pub(crate) name: &'a str,
    pub(crate) span: Span,
    pub(crate) write: bool,
    /// Compound assignments (`+=`) and updates read as well as write.
    pub(crate) compound: bool,
    /// Innermost scope at the occurrence; parents preserve lexical lookup.
    pub(crate) scope: usize,
}

/// A resolved callee position (`call`/`new` of a file-local binding).
pub(crate) struct TbCallee<'a> {
    pub(crate) name: &'a str,
    pub(crate) span: Span,
    pub(crate) arity: usize,
    pub(crate) constructor: bool,
    /// Innermost scope at the occurrence; parents preserve lexical lookup.
    pub(crate) scope: usize,
    /// Argument positions spelled as bare `undefined` (`S4623`).
    pub(crate) explicit_undefined: Vec<(usize, Span)>,
    /// Any spread argument disables positional matching.
    pub(crate) spread: bool,
}

/// A name occurrence awaiting lexical resolution (`delete X…`, `S2870`).
pub(crate) struct TbSite<'a> {
    pub(crate) name: &'a str,
    pub(crate) span: Span,
    /// Innermost scope at the occurrence; parents preserve lexical lookup.
    pub(crate) scope: usize,
}

pub(crate) struct TbCallSite {
    pub(crate) binding: usize,
    pub(crate) span: Span,
    pub(crate) arity: usize,
    pub(crate) explicit_undefined: Vec<(usize, Span)>,
    pub(crate) spread: bool,
}

/// Model produced by [`build_tb_model`]; indexes are stable for the run.
pub(crate) struct TbModel<'a> {
    pub(crate) scopes: Vec<TbScope>,
    pub(crate) bindings: Vec<TbBinding<'a>>,
    pub(crate) events: Vec<TbEvent<'a>>,
    pub(crate) callees: Vec<TbCallee<'a>>,
    pub(crate) delete_sites: Vec<TbSite<'a>>,
    /// `(outer binding, inner declaration)` shadow chains (`S1117`).
    pub(crate) shadows: Vec<(usize, usize)>,
    /// `(first declaration, second declaration, name)` same-scope
    /// `var`/function duplicates (`S2814`, JS only).
    pub(crate) duplicates: Vec<(Span, Span, &'a str)>,
    /// Writes to names never declared anywhere (`S2703`, JS only).
    pub(crate) implicit_globals: Vec<(&'a str, Span)>,
    pub(crate) calls: Vec<TbCallSite>,
    /// `(binding, span)` of `new` sites resolving file-locally (`S3686`).
    pub(crate) news: Vec<(usize, Span)>,
    /// Resolved `delete` targets whose base is array-like.
    pub(crate) array_deletes: Vec<(usize, Span)>,
}

impl TbModel<'_> {
    pub(crate) fn shallow(&self, scope: usize, name: &str) -> Option<usize> {
        self.scopes[scope]
            .bindings
            .iter()
            .copied()
            .find(|id| self.bindings[*id].name == name)
    }

    /// Resolves from the occurrence's scope through its lexical parents.
    /// Storing only the innermost scope avoids cloning the whole scope chain
    /// into every identifier, call, and delete event.
    pub(crate) fn resolve_scope(&self, mut scope: usize, name: &str) -> Option<usize> {
        loop {
            if let Some(id) = self.shallow(scope, name) {
                return Some(id);
            }
            scope = self.scopes[scope].parent?;
        }
    }
}

/// Distributes recorded events onto bindings once all declarations exist,
/// then derives shadow chains and same-scope duplicates.
pub(crate) fn finish_model(mut model: TbModel<'_>) -> TbModel<'_> {
    resolve_events(&mut model);
    resolve_callees(&mut model);
    resolve_delete_sites(&mut model);
    derive_scope_relationships(&mut model);
    model
}

fn resolve_events(model: &mut TbModel<'_>) {
    for event in std::mem::take(&mut model.events) {
        if let Some(id) = model.resolve_scope(event.scope, event.name) {
            let binding = &mut model.bindings[id];
            if event.write {
                binding.writes.push(event.span);
            }
            if !event.write || event.compound {
                binding.reads.push(event.span);
            }
            continue;
        }
        if event.write {
            model.implicit_globals.push((event.name, event.span));
        }
    }
}

fn resolve_callees(model: &mut TbModel<'_>) {
    for callee in std::mem::take(&mut model.callees) {
        if let Some(id) = model.resolve_scope(callee.scope, callee.name) {
            let site = TbCallSite {
                binding: id,
                span: callee.span,
                arity: callee.arity,
                explicit_undefined: callee.explicit_undefined,
                spread: callee.spread,
            };
            if callee.constructor {
                model.news.push((id, callee.span));
            } else {
                model.calls.push(site);
            }
        }
    }
}

fn resolve_delete_sites(model: &mut TbModel<'_>) {
    for site in std::mem::take(&mut model.delete_sites) {
        if let Some(id) = model.resolve_scope(site.scope, site.name)
            && model.bindings[id].array_like
        {
            model.array_deletes.push((id, site.span));
        }
    }
}

fn derive_scope_relationships(model: &mut TbModel<'_>) {
    for scope in 0..model.scopes.len() {
        // Move the IDs out instead of cloning each scope's binding list.
        // Shadow lookup only walks parents, and duplicate detection consumes
        // this local slice, so restoring it preserves the model exactly.
        let ids = std::mem::take(&mut model.scopes[scope].bindings);
        record_shadows(model, scope, &ids);
        record_duplicates(model, &ids);
        model.scopes[scope].bindings = ids;
    }
}

fn record_shadows(model: &mut TbModel<'_>, scope: usize, ids: &[usize]) {
    for &id in ids {
        let mut cursor = model.scopes[scope].parent;
        while let Some(ancestor) = cursor {
            if let Some(outer) = model.shallow(ancestor, model.bindings[id].name) {
                model.shadows.push((outer, id));
                break;
            }
            cursor = model.scopes[ancestor].parent;
        }
    }
}

fn record_duplicates(model: &mut TbModel<'_>, ids: &[usize]) {
    let duplicate_kind = |kind| matches!(kind, TbKind::Var | TbKind::Function);
    let mut first_by_name: HashMap<&str, usize> = HashMap::new();
    for &id in ids {
        let binding = &model.bindings[id];
        if !duplicate_kind(binding.kind) {
            continue;
        }
        if let Some(&first) = first_by_name.get(binding.name) {
            model
                .duplicates
                .push((model.bindings[first].decl, binding.decl, binding.name));
        } else {
            first_by_name.insert(binding.name, id);
        }
    }
}
