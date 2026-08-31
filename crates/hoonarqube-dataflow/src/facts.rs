//! Ready-made fact lattices for common dataflow problems:
//! [`ReachingFacts`], [`LivenessFacts`], and [`TaintFacts`].

use std::collections::{BTreeMap, BTreeSet};

/// Variable-to-origin taint facts for forward may-analysis.
///
/// Each variable can retain multiple source origins after control-flow joins.
/// Language adapters explicitly model sources with [`TaintFacts::taint`],
/// assignments with [`TaintFacts::propagate`], and sanitizers or overwrites with
/// [`TaintFacts::clear`]. Ordered maps and sets keep results deterministic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFacts<V: Ord, O: Ord> {
    variables: BTreeMap<V, BTreeSet<O>>,
}

impl<V: Ord, O: Ord> TaintFacts<V, O> {
    /// Creates an empty taint fact set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            variables: BTreeMap::new(),
        }
    }

    /// Returns `true` when no variable is tainted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// Returns `true` when `variable` has at least one taint origin.
    #[must_use]
    pub fn is_tainted(&self, variable: &V) -> bool {
        self.variables.contains_key(variable)
    }

    /// Adds `origin` to `variable`; returns whether the fact was new.
    pub fn taint(&mut self, variable: V, origin: O) -> bool {
        self.variables.entry(variable).or_default().insert(origin)
    }

    /// Removes every origin from `variable`; returns whether it was tainted.
    pub fn clear(&mut self, variable: &V) -> bool {
        self.variables.remove(variable).is_some()
    }

    /// Iterates all known origins for `variable`.
    pub fn origins(&self, variable: &V) -> impl Iterator<Item = &O> {
        self.variables.get(variable).into_iter().flatten()
    }
}

impl<V: Ord + Clone, O: Ord + Clone> TaintFacts<V, O> {
    /// Replaces `target` with the origins currently attached to `source`.
    /// Returns whether `target` changed.
    pub fn propagate(&mut self, source: &V, target: V) -> bool {
        let origins = self.variables.get(source).cloned();
        match origins {
            Some(origins) => {
                if self.variables.get(&target) == Some(&origins) {
                    false
                } else {
                    self.variables.insert(target, origins);
                    true
                }
            }
            None => self.variables.remove(&target).is_some(),
        }
    }

    /// Union of both fact sets, preserving every possible origin.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        for (variable, origins) in &other.variables {
            merged
                .variables
                .entry(variable.clone())
                .or_default()
                .extend(origins.iter().cloned());
        }
        merged
    }

    /// [`TaintFacts::union`] shaped for [`crate::solve_dataflow`]'s meet slot.
    #[must_use]
    pub fn meet_union(left: &Self, right: &Self) -> Self {
        left.union(right)
    }
}

impl<V: Ord, O: Ord> Default for TaintFacts<V, O> {
    fn default() -> Self {
        Self::new()
    }
}

/// Reaching-definitions facts: the set of definition `(variable, site)` pairs
/// that may reach a program point.
///
/// Ordered sets keep solves deterministic. Use [`ReachingFacts::meet_union`]
/// as the meet for a forward may-solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReachingFacts<D: Ord> {
    defs: BTreeSet<D>,
}

impl<D: Ord> ReachingFacts<D> {
    /// Creates an empty fact set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            defs: BTreeSet::new(),
        }
    }

    /// Number of reaching definitions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.defs.len()
    }

    /// Returns `true` if no definition reaches this point.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.defs.is_empty()
    }

    /// Returns `true` if `definition` reaches this point.
    #[must_use]
    pub fn contains(&self, definition: &D) -> bool {
        self.defs.contains(definition)
    }

    /// Adds a definition; returns whether it was newly inserted.
    pub fn insert(&mut self, definition: D) -> bool {
        self.defs.insert(definition)
    }

    /// Adds every definition from `definitions`.
    pub fn extend<I>(&mut self, definitions: I)
    where
        I: IntoIterator<Item = D>,
    {
        self.defs.extend(definitions);
    }

    /// Removes every definition matching `predicate`, modelling a kill.
    pub fn kill_where<P>(&mut self, predicate: P)
    where
        P: Fn(&D) -> bool,
    {
        self.defs.retain(|definition| !predicate(definition));
    }

    /// Iterates the reaching definitions.
    pub fn defs(&self) -> impl Iterator<Item = &D> {
        self.defs.iter()
    }
}

impl<D: Ord + Clone> ReachingFacts<D> {
    /// Union of both fact sets (the may-meet).
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.defs.extend(other.defs.iter().cloned());
        merged
    }

    /// Intersection of both fact sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            defs: self.defs.intersection(&other.defs).cloned().collect(),
        }
    }

    /// [`ReachingFacts::union`] shaped for [`crate::solve_dataflow`]'s meet slot.
    #[must_use]
    pub fn meet_union(left: &Self, right: &Self) -> Self {
        left.union(right)
    }

    /// [`ReachingFacts::intersection`] shaped for [`crate::solve_dataflow`]'s meet
    /// slot.
    #[must_use]
    pub fn meet_intersection(left: &Self, right: &Self) -> Self {
        left.intersection(right)
    }
}

impl<D: Ord> Default for ReachingFacts<D> {
    fn default() -> Self {
        Self::new()
    }
}

/// Live-variable facts: the set of variables that may be read before being
/// written along some path onward.
///
/// Use [`LivenessFacts::meet_union`] as the meet for a backward may-solve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessFacts<V: Ord> {
    variables: BTreeSet<V>,
}

impl<V: Ord> LivenessFacts<V> {
    /// Creates an empty fact set.
    #[must_use]
    pub fn new() -> Self {
        Self {
            variables: BTreeSet::new(),
        }
    }

    /// Number of live variables.
    #[must_use]
    pub fn len(&self) -> usize {
        self.variables.len()
    }

    /// Returns `true` if no variable is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.variables.is_empty()
    }

    /// Returns `true` if `variable` is live.
    #[must_use]
    pub fn contains(&self, variable: &V) -> bool {
        self.variables.contains(variable)
    }

    /// Marks `variable` as live (a use); returns whether it was newly added.
    pub fn use_var(&mut self, variable: V) -> bool {
        self.variables.insert(variable)
    }

    /// Marks `variable` as dead (a definition kills upstream liveness).
    /// Returns whether it was previously live.
    pub fn kill_var(&mut self, variable: &V) -> bool {
        self.variables.remove(variable)
    }

    /// Marks every variable from `variables` as live.
    pub fn extend_live<I>(&mut self, variables: I)
    where
        I: IntoIterator<Item = V>,
    {
        self.variables.extend(variables);
    }

    /// Iterates the live variables.
    pub fn live_vars(&self) -> impl Iterator<Item = &V> {
        self.variables.iter()
    }
}

impl<V: Ord + Clone> LivenessFacts<V> {
    /// Union of both fact sets (the may-meet).
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut merged = self.clone();
        merged.variables.extend(other.variables.iter().cloned());
        merged
    }

    /// Intersection of both fact sets.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            variables: self
                .variables
                .intersection(&other.variables)
                .cloned()
                .collect(),
        }
    }

    /// [`LivenessFacts::union`] shaped for [`crate::solve_dataflow`]'s meet slot.
    #[must_use]
    pub fn meet_union(left: &Self, right: &Self) -> Self {
        left.union(right)
    }

    /// [`LivenessFacts::intersection`] shaped for [`crate::solve_dataflow`]'s meet
    /// slot.
    #[must_use]
    pub fn meet_intersection(left: &Self, right: &Self) -> Self {
        left.intersection(right)
    }
}

impl<V: Ord> Default for LivenessFacts<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{Lv, Rd, lv, rd};
    use crate::{LivenessFacts, ReachingFacts, TaintFacts};

    #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct NonClone(u8);

    #[test]
    fn reaching_facts_set_operations() {
        let mut facts = rd(&[("a", 1)]);
        assert!(facts.insert(("b", 2)));
        assert!(!facts.insert(("b", 2)));
        facts.extend([("c", 3)]);
        assert!(facts.contains(&("c", 3)));
        facts.kill_where(|(name, _)| *name == "a");
        assert_eq!(facts, rd(&[("b", 2), ("c", 3)]));
        assert_eq!(facts.union(&rd(&[("d", 4)])).len(), 3);
        assert_eq!(
            facts.intersection(&rd(&[("c", 3), ("z", 9)])),
            rd(&[("c", 3)])
        );
        assert_eq!(Rd::meet_union(&facts, &facts), facts);
        assert_eq!(Rd::meet_intersection(&facts, &Rd::new()).len(), 0);
        assert_eq!(facts.defs().count(), 2);
        assert!(Rd::new().is_empty());
        assert_eq!(Rd::default().len(), 0);
    }

    #[test]
    fn liveness_facts_set_operations() {
        let mut facts = lv(&["a"]);
        assert!(facts.use_var("b"));
        assert!(facts.contains(&"b"));
        facts.extend_live(["c"]);
        assert!(facts.kill_var(&"a"));
        assert!(!facts.kill_var(&"missing"));
        assert_eq!(facts, lv(&["b", "c"]));
        assert_eq!(facts.union(&lv(&["d"])), lv(&["b", "c", "d"]));
        assert_eq!(facts.intersection(&lv(&["c", "z"])), lv(&["c"]));
        assert_eq!(Lv::meet_union(&facts, &facts), facts);
        assert_eq!(Lv::meet_intersection(&facts, &lv(&["c"])), lv(&["c"]));
        assert_eq!(facts.live_vars().count(), 2);
        assert_eq!(Lv::default().len(), 0);
    }

    #[test]
    fn basic_fact_operations_do_not_require_clone_values() {
        let mut reaching = ReachingFacts::<NonClone>::new();
        assert!(reaching.insert(NonClone(1)));
        reaching.kill_where(|definition| definition.0 == 2);
        assert!(reaching.contains(&NonClone(1)));

        let mut liveness = LivenessFacts::<NonClone>::default();
        assert!(liveness.use_var(NonClone(2)));
        assert!(liveness.kill_var(&NonClone(2)));
    }

    #[test]
    fn taint_facts_track_propagation_sanitization_and_joins() {
        let mut left = TaintFacts::new();
        assert!(left.taint("input", 1));
        assert!(left.propagate(&"input", "copy"));
        assert_eq!(left.origins(&"copy").copied().collect::<Vec<_>>(), [1]);

        let mut right = TaintFacts::new();
        assert!(right.taint("input", 2));
        let joined = TaintFacts::meet_union(&left, &right);
        assert_eq!(
            joined.origins(&"input").copied().collect::<Vec<_>>(),
            [1, 2]
        );
        assert!(joined.is_tainted(&"copy"));

        let mut sanitized = joined;
        assert!(sanitized.clear(&"input"));
        assert!(!sanitized.is_tainted(&"input"));
        assert!(sanitized.propagate(&"input", "copy"));
        assert!(sanitized.is_empty());
        assert_eq!(TaintFacts::<&str, usize>::default(), TaintFacts::new());
    }
}
