//! Ready-made fact lattices for common dataflow problems:
//! [`ReachingFacts`] and [`LivenessFacts`].

use std::collections::BTreeSet;

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
    use crate::{LivenessFacts, ReachingFacts};

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
}
