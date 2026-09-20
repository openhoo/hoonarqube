use std::collections::{HashMap, HashSet, VecDeque};

use hoonarqube_ir::{Issue, IssueFlow};
use ruff_python_ast::{Expr, ModModule, StmtClassDef};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::{NameResolution, WebFrameworkFacts, flow_location};

const RULE_KEY: &str = "python:S8511";
const MESSAGE: &str = "Reorder or remove base classes to fix this MRO conflict.";
const SECONDARY_MESSAGE: &str =
    "This base class is an ancestor of another listed base class appearing after it.";

/// Builtin classes usable as bases, with their runtime parent. Typeshed
/// lists extra `collections.abc` parents for containers that are only
/// virtual-subclass registrations at runtime; like the reference's
/// runtime-faithful view, every builtin not listed here has `object` as its
/// only parent.
const BUILTIN_PARENTS: &[(&str, &str)] = &[
    ("bool", "int"),
    ("BaseException", "object"),
    ("Exception", "BaseException"),
    ("ArithmeticError", "Exception"),
    ("AssertionError", "Exception"),
    ("AttributeError", "Exception"),
    ("BufferError", "Exception"),
    ("EOFError", "Exception"),
    ("ImportError", "Exception"),
    ("LookupError", "Exception"),
    ("MemoryError", "Exception"),
    ("NameError", "Exception"),
    ("OSError", "Exception"),
    ("ReferenceError", "Exception"),
    ("RuntimeError", "Exception"),
    ("StopAsyncIteration", "Exception"),
    ("StopIteration", "Exception"),
    ("SyntaxError", "Exception"),
    ("SystemError", "Exception"),
    ("TypeError", "Exception"),
    ("ValueError", "Exception"),
    ("ZeroDivisionError", "ArithmeticError"),
    ("IndexError", "LookupError"),
    ("KeyError", "LookupError"),
    ("NotImplementedError", "RuntimeError"),
    ("ModuleNotFoundError", "ImportError"),
    ("FileNotFoundError", "OSError"),
    ("GeneratorExit", "BaseException"),
    ("KeyboardInterrupt", "BaseException"),
    ("SystemExit", "BaseException"),
];

/// Builtin names treated as resolvable leaf classes. Unresolved names and
/// imports stay opaque, matching the reference's unresolved-hierarchy path.
const KNOWN_BUILTIN_BASES: &[&str] = &[
    "object",
    "type",
    "bool",
    "int",
    "float",
    "complex",
    "str",
    "bytes",
    "bytearray",
    "list",
    "dict",
    "set",
    "frozenset",
    "tuple",
    "range",
    "slice",
    "memoryview",
    "BaseException",
    "Exception",
    "ArithmeticError",
    "AssertionError",
    "AttributeError",
    "BufferError",
    "EOFError",
    "ImportError",
    "LookupError",
    "MemoryError",
    "NameError",
    "OSError",
    "ReferenceError",
    "RuntimeError",
    "StopAsyncIteration",
    "StopIteration",
    "SyntaxError",
    "SystemError",
    "TypeError",
    "ValueError",
    "ZeroDivisionError",
    "IndexError",
    "KeyError",
    "NotImplementedError",
    "ModuleNotFoundError",
    "FileNotFoundError",
    "GeneratorExit",
    "KeyboardInterrupt",
    "SystemExit",
];

/// A base class as the lexical model sees it: a same-file class
/// definition, a known builtin leaf, or an opaque unresolved reference
/// (imports, calls, subscripts of unresolved objects) keyed by a stable
/// identity string so two different unknowns never compare equal.
#[derive(Clone, PartialEq, Eq, Hash)]
enum BaseRef {
    Local(usize),
    Builtin(&'static str),
    Unknown(String),
}

/// One element of a computed linearization.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Elem {
    Local(usize),
    Builtin(&'static str),
    Object,
}

/// python:S8511 — a class whose base list Python's C3 linearization cannot
/// order raises `TypeError` at definition time. When every base resolves
/// (same-file classes and known builtins), the full C3 merge decides;
/// otherwise the reference's ancestor heuristic flags an earlier base that
/// a later base already inherits.
pub(crate) fn check_s8511_mro_conflict(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let _ = parsed;
    let mut graph = ClassGraph::build(file_ctx);
    let mut issues = Vec::new();
    for class in graph.classes.clone() {
        let Some(bases) = positional_bases(class) else {
            continue;
        };
        if bases.len() < 2 {
            continue;
        }
        let refs: Vec<BaseRef> = bases.iter().map(|base| graph.resolve_base(base)).collect();
        let conflict_index = ancestor_conflict_index(&graph, &refs);
        let fully_resolved = refs.iter().all(|base| graph.base_fully_resolved(base));
        let conflict = if fully_resolved {
            graph.linearization(&refs).is_none()
        } else {
            conflict_index.is_some()
        };
        if conflict {
            issues.push(mro_issue(class, &bases, conflict_index, index, source));
        }
    }
    issues
}

/// The positional base expressions of a class definition (keyword arguments
/// such as `metaclass=` are not bases).
fn positional_bases(class: &StmtClassDef) -> Option<Vec<&Expr>> {
    let arguments = class.arguments.as_deref()?;
    Some(arguments.args.iter().collect())
}

/// The finding on the class name plus the secondary location on the
/// earlier base that a later base already inherits, when one exists.
fn mro_issue(
    class: &StmtClassDef,
    bases: &[&Expr],
    conflict_index: Option<usize>,
    index: &LineIndex,
    source: &str,
) -> Issue {
    let mut issue = issue_at(RULE_KEY, MESSAGE, class.name.range(), index, source);
    if let Some(conflict) = conflict_index {
        issue.flows.push(IssueFlow {
            locations: vec![flow_location(
                SECONDARY_MESSAGE,
                bases[conflict].range(),
                index,
                source,
            )],
        });
    }
    issue
}

/// The first base index `i` such that some later base `j > i` is or
/// extends base `i` — the reference's `findAncestorConflictIndex`.
fn ancestor_conflict_index(graph: &ClassGraph<'_>, refs: &[BaseRef]) -> Option<usize> {
    (0..refs.len().saturating_sub(1)).find(|&i| {
        refs[i + 1..]
            .iter()
            .any(|later| graph.is_or_extends(later, &refs[i]))
    })
}

/// Memoized per-class linearization: `Pending` until computed, then the
/// resolved result (`None` when the class's own MRO conflicts or cycles).
#[derive(Clone)]
enum MroMemo {
    Pending,
    Done(Option<Vec<Elem>>),
}

/// The in-file class graph plus memoized resolution state.
struct ClassGraph<'a> {
    facts: WebFrameworkFacts<'a>,
    classes: Vec<&'a StmtClassDef>,
    by_def: HashMap<*const StmtClassDef, usize>,
    bases: Vec<Vec<BaseRef>>,
    mro_memo: Vec<MroMemo>,
    mro_active: Vec<bool>,
}

impl<'a> ClassGraph<'a> {
    fn build(file_ctx: &FileContext<'a>) -> Self {
        let facts = WebFrameworkFacts::build(file_ctx);
        let classes = file_ctx.classes.clone();
        let by_def = classes
            .iter()
            .enumerate()
            .map(|(idx, class)| (std::ptr::from_ref(*class), idx))
            .collect();
        let count = classes.len();
        let mut graph = ClassGraph {
            facts,
            classes,
            by_def,
            bases: Vec::new(),
            mro_memo: vec![MroMemo::Pending; count],
            mro_active: vec![false; count],
        };
        graph.bases = graph
            .classes
            .iter()
            .map(|class| {
                positional_bases(class)
                    .unwrap_or_default()
                    .iter()
                    .map(|base| graph.resolve_base(base))
                    .collect()
            })
            .collect();
        graph
    }

    /// Resolves a base expression to a same-file class, a known builtin
    /// leaf, or an opaque unknown. Subscripts resolve through their object
    /// (`List[int]` → `list`); calls and other shapes stay unknown.
    fn resolve_base(&self, expr: &Expr) -> BaseRef {
        if let Some(class) = self.facts.resolve_class_def(expr, expr.range())
            && let Some(&idx) = self.by_def.get(&std::ptr::from_ref(class))
        {
            return BaseRef::Local(idx);
        }
        match expr {
            Expr::Subscript(subscript) => self.resolve_base(&subscript.value),
            Expr::Name(name) => match self.facts.resolve_name(name.id.as_str(), name.range()) {
                NameResolution::Import(fqn) => Self::leaf_for_fqn(&fqn, expr.range()),
                NameResolution::Value(value) => self.resolve_base(value),
                _ => Self::leaf_for_name(name.id.as_str(), expr.range()),
            },
            Expr::Attribute(_) => match self.facts.expr_fqn(expr) {
                Some(fqn) => Self::leaf_for_fqn(&fqn, expr.range()),
                None => BaseRef::Unknown(unknown_key(expr)),
            },
            _ => BaseRef::Unknown(unknown_key(expr)),
        }
    }

    /// A builtin leaf when the dotted path names a known builtin (with or
    /// without the `builtins.` qualifier); otherwise an opaque unknown.
    fn leaf_for_fqn(fqn: &str, range: TextRange) -> BaseRef {
        let bare = fqn.strip_prefix("builtins.").unwrap_or(fqn);
        KNOWN_BUILTIN_BASES
            .iter()
            .find(|name| **name == bare)
            .map_or_else(
                || BaseRef::Unknown(unknown_key_at(fqn, range)),
                |name| BaseRef::Builtin(name),
            )
    }

    /// A builtin leaf for an unbound name, or an opaque unknown.
    fn leaf_for_name(name: &str, range: TextRange) -> BaseRef {
        KNOWN_BUILTIN_BASES
            .iter()
            .find(|builtin| **builtin == name)
            .map_or_else(
                || BaseRef::Unknown(unknown_key_at(name, range)),
                |builtin| BaseRef::Builtin(builtin),
            )
    }

    /// The direct bases of a class reference for ancestor traversal:
    /// same-file classes expand to their own bases, builtin leaves to
    /// their runtime parent chain, and unknowns dead-end.
    fn direct_bases(&self, base: &BaseRef) -> Vec<BaseRef> {
        match base {
            BaseRef::Local(idx) => self.bases[*idx].clone(),
            BaseRef::Builtin(name) => builtin_parent(name)
                .into_iter()
                .map(BaseRef::Builtin)
                .collect(),
            BaseRef::Unknown(_) => Vec::new(),
        }
    }

    /// Whether `candidate` is `ancestor` or transitively extends it —
    /// the reference's `isOrExtendsClassAtRuntime` over the lexical graph.
    fn is_or_extends(&self, candidate: &BaseRef, ancestor: &BaseRef) -> bool {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::from([candidate.clone()]);
        while let Some(current) = queue.pop_front() {
            if !visited.insert(current.clone()) {
                continue;
            }
            if current == *ancestor {
                return true;
            }
            queue.extend(self.direct_bases(&current));
        }
        false
    }

    /// Whether a base's hierarchy is fully known and itself linearizable —
    /// the reference's `!type.hasUnresolvedHierarchy()`. A same-file class
    /// whose own MRO fails counts as unresolved, so its subclasses fall
    /// back to the ancestor heuristic instead of inheriting the failure.
    fn base_fully_resolved(&mut self, base: &BaseRef) -> bool {
        match base {
            BaseRef::Builtin(_) => true,
            BaseRef::Unknown(_) => false,
            BaseRef::Local(idx) => self.class_mro(*idx).is_some(),
        }
    }

    /// The class's own C3 linearization, memoized; `None` on conflict or
    /// inheritance cycles.
    fn class_mro(&mut self, idx: usize) -> Option<Vec<Elem>> {
        if let MroMemo::Done(memo) = &self.mro_memo[idx] {
            return memo.clone();
        }
        if self.mro_active[idx] {
            return None;
        }
        self.mro_active[idx] = true;
        let bases = self.bases[idx].clone();
        let result = self
            .linearization(&bases)
            .map(|tail| std::iter::once(Elem::Local(idx)).chain(tail).collect());
        self.mro_active[idx] = false;
        self.mro_memo[idx] = MroMemo::Done(result.clone());
        result
    }

    /// C3 merge of the base list: each base contributes its linearization
    /// (same-file class MRO or builtin leaf chain), followed by the base
    /// list itself. `None` when no candidate head is consistent — exactly
    /// the `TypeError` Python raises at class creation.
    fn linearization(&mut self, bases: &[BaseRef]) -> Option<Vec<Elem>> {
        let mut lists: Vec<VecDeque<Elem>> = Vec::new();
        for base in bases {
            lists.push(self.base_mro(base)?.into());
        }
        lists.push(bases.iter().map(base_elem).collect());
        c3_merge(&mut lists)
    }

    /// The linearization a single base contributes.
    fn base_mro(&mut self, base: &BaseRef) -> Option<Vec<Elem>> {
        match base {
            BaseRef::Local(idx) => self.class_mro(*idx),
            BaseRef::Builtin(name) => Some(builtin_mro(name)),
            BaseRef::Unknown(_) => None,
        }
    }
}

/// Identity key for an unresolved base expression: the source position so
/// two distinct opaque expressions (`f()`, `g()`) never compare equal.
fn unknown_key(expr: &Expr) -> String {
    format!(
        "@{}:{}",
        expr.range().start().to_u32(),
        expr.range().end().to_u32()
    )
}

/// Identity key for a named unresolved base: the resolved path alone, so
/// the same imported or unbound name listed twice still compares equal
/// (Python rejects duplicate bases with `TypeError`).
fn unknown_key_at(fqn: &str, _range: TextRange) -> String {
    fqn.to_string()
}

/// The element a base contributes to its own linearization list.
fn base_elem(base: &BaseRef) -> Elem {
    match base {
        BaseRef::Local(idx) => Elem::Local(*idx),
        BaseRef::Builtin(name) => Elem::Builtin(name),
        BaseRef::Unknown(_) => Elem::Object,
    }
}

/// The runtime parent of a builtin leaf (`object` when unlisted).
fn builtin_parent(name: &str) -> Option<&'static str> {
    if name == "object" {
        return None;
    }
    Some(
        BUILTIN_PARENTS
            .iter()
            .find(|(child, _)| *child == name)
            .map_or("object", |(_, parent)| parent),
    )
}

/// A builtin leaf's linearization: itself, its parent chain, `object`.
fn builtin_mro(name: &'static str) -> Vec<Elem> {
    let mut mro = vec![Elem::Builtin(name)];
    let mut current = name;
    while let Some(parent) = builtin_parent(current) {
        if parent == "object" {
            break;
        }
        mro.push(Elem::Builtin(parent));
        current = parent;
    }
    mro.push(Elem::Object);
    mro
}

/// The C3 merge: repeatedly take the first head that appears in no list's
/// tail; fail when every remaining head is blocked.
fn c3_merge(lists: &mut Vec<VecDeque<Elem>>) -> Option<Vec<Elem>> {
    let mut result = Vec::new();
    loop {
        lists.retain(|list| !list.is_empty());
        if lists.is_empty() {
            return Some(result);
        }
        let candidate = next_unblocked_head(lists)?;
        for list in lists.iter_mut() {
            while list.front() == Some(&candidate) {
                list.pop_front();
            }
        }
        result.push(candidate);
    }
}

/// The first list head that appears in no list's tail — the next element
/// C3 can take. `None` when every remaining head is blocked.
fn next_unblocked_head(lists: &[VecDeque<Elem>]) -> Option<Elem> {
    lists
        .iter()
        .filter_map(|list| list.front().copied())
        .find(|candidate| {
            !lists
                .iter()
                .any(|list| list.iter().skip(1).any(|elem| elem == candidate))
        })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    #[test]
    fn s8511_flags_diamond_conflict_on_sonar_example() {
        // The reference Noncompliant example, verbatim.
        let flagged = scan(concat!(
            "class A: pass\n",
            "class B(A): pass\n",
            "class C(A): pass\n",
            "class D(B, A, C):  # Noncompliant\n",
            "    pass\n",
        ));
        let found = findings(&flagged, "python:S8511");
        assert_eq!(found.len(), 1);
        // The anchor covers the class name; the secondary marks `A`.
        assert_eq!(found[0].range.start, pos(4, 6));
        assert_eq!(found[0].range.end, pos(4, 7));
        assert_eq!(
            found[0].message,
            "Reorder or remove base classes to fix this MRO conflict."
        );
        assert_eq!(found[0].flows.len(), 1);
        assert_eq!(found[0].flows[0].locations.len(), 1);
        assert_eq!(found[0].flows[0].locations[0].range.start, pos(4, 11));
    }

    #[test]
    fn s8511_accepts_reduced_bases_on_sonar_example() {
        // The reference Compliant solution, verbatim.
        let clean = scan(concat!(
            "class A: pass\n",
            "class B(A): pass\n",
            "class C(A): pass\n",
            "class D(B, C):  # Compliant\n",
            "    pass\n",
        ));
        assert!(findings(&clean, "python:S8511").is_empty());
    }

    #[test]
    fn s8511_flags_indirect_c3_conflict_without_secondary() {
        // LeftFirst/RightFirst are individually valid but cannot be merged.
        let flagged = scan(concat!(
            "class CommonRoot: pass\n",
            "class LeftChild(CommonRoot): pass\n",
            "class RightChild(CommonRoot): pass\n",
            "class LeftFirst(LeftChild, RightChild): pass\n",
            "class RightFirst(RightChild, LeftChild): pass\n",
            "class C3Conflict(LeftFirst, RightFirst):  # Noncompliant\n",
            "    pass\n",
        ));
        let found = findings(&flagged, "python:S8511");
        assert_eq!(found.len(), 1);
        assert!(found[0].flows.is_empty());
    }

    #[test]
    fn s8511_flags_ancestor_pair_when_hierarchy_unresolved() {
        // With an unresolved mixin in the graph the full C3 path is skipped,
        // but the earlier-base-ancestor-of-later-base heuristic still fires.
        let flagged = scan(concat!(
            "from unknown_module import ExternalMixin\n",
            "\n",
            "class Base: pass\n",
            "class MidWithUnresolvedMixin(Base, ExternalMixin): pass\n",
            "class ConflictMid(Base, MidWithUnresolvedMixin):  # Noncompliant\n",
            "    pass\n",
        ));
        let found = findings(&flagged, "python:S8511");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].flows.len(), 1);
    }

    #[test]
    fn s8511_accepts_unresolved_peers_and_builtin_mixins() {
        let clean = scan(concat!(
            "from unknown_module import ExternalMixin, ExternalOther\n",
            "from collections.abc import MutableMapping, Sequence\n",
            "\n",
            "class Base: pass\n",
            "def not_a_class(): pass\n",
            "\n",
            "class CompliantPartialResolution(not_a_class, Base): pass\n",
            "class MidWithUnresolvedMixin(Base, ExternalMixin): pass\n",
            "class CompliantTwoUnresolvedPeers(ExternalMixin, ExternalOther): pass\n",
            "class CompliantDictMixin(MutableMapping, dict): pass\n",
            "class CompliantStrMixin(Sequence, str): pass\n",
            "class OnlyMetaclass(metaclass=type): pass\n",
        ));
        assert!(findings(&clean, "python:S8511").is_empty());
    }

    #[test]
    fn s8511_flags_builtin_ancestor_of_user_subclass() {
        let flagged = scan(concat!(
            "class _UserDictSubclass(dict): pass\n",
            "class StillBrokenWithUserDict(dict, _UserDictSubclass):  # Noncompliant\n",
            "    pass\n",
            "class CompliantUserDictThenDict(_UserDictSubclass, dict): pass\n",
        ));
        let found = findings(&flagged, "python:S8511");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start, pos(2, 6));
    }

    #[test]
    fn s8511_flags_exception_ordering_conflict() {
        // `ValueError` must precede its parent `Exception` in the base list.
        let flagged = scan(concat!(
            "class WrongOrder(Exception, ValueError):  # Noncompliant\n",
            "    pass\n",
            "class RightOrder(ValueError, Exception): pass\n",
        ));
        assert_eq!(findings(&flagged, "python:S8511").len(), 1);
    }

    #[test]
    fn s8511_accepts_single_and_unrelated_bases() {
        let clean = scan(concat!(
            "class A: pass\n",
            "class B(A): pass\n",
            "class C: pass\n",
            "class D(B, C): pass\n",
            "class E(B): pass\n",
        ));
        assert!(findings(&clean, "python:S8511").is_empty());
    }
}
