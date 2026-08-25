//! Incremental CFG construction: the frontier-tracking [`CfgBuilder`].

use crate::cfg::{BlockId, Cfg};

/// Incremental builder producing a [`Cfg`].
///
/// The builder tracks a *frontier*: the set of blocks whose outgoing flow is
/// not yet determined. Appending operations wire the frontier into the new
/// block; [`CfgBuilder::finish`] seals whatever remains into the exit.
#[derive(Debug)]
pub struct CfgBuilder<T> {
    cfg: Cfg<T>,
    frontier: Vec<BlockId>,
}

impl<T> CfgBuilder<T> {
    /// Starts a graph with the given entry and exit payloads and the entry as
    /// the sole open frontier block.
    #[must_use]
    pub fn new(entry_payload: T, exit_payload: T) -> Self {
        Self {
            cfg: Cfg::disconnected(entry_payload, exit_payload),
            frontier: vec![BlockId::new(0)],
        }
    }

    /// Appends a block wired after every open frontier block, which then
    /// collapses to the new block alone.
    pub fn push_block(&mut self, payload: T) -> BlockId {
        let id = self.cfg.append_node(payload);
        for open in std::mem::take(&mut self.frontier) {
            self.cfg.add_edge(open, id);
        }
        self.frontier.push(id);
        id
    }

    /// Appends a branch: the condition block is wired after the frontier and
    /// two disjoint arm heads become the new frontier.
    ///
    /// Arm heads need payloads because every block carries one; pass the
    /// arms' first statements, or a language's no-op placeholder when an arm
    /// starts with a nested construct.
    ///
    /// Returns the ids of the then-head and the else-head, in that order.
    pub fn branch(&mut self, condition: T, then_head: T, else_head: T) -> (BlockId, BlockId) {
        let cond = self.push_block(condition);
        let then_id = self.cfg.append_node(then_head);
        let else_id = self.cfg.append_node(else_head);
        self.cfg.add_edge(cond, then_id);
        self.cfg.add_edge(cond, else_id);
        self.frontier = vec![then_id, else_id];
        (then_id, else_id)
    }

    /// Adds a loop-back edge `from -> to` and closes `from`: it no longer
    /// participates in the frontier, so [`CfgBuilder::finish`] will not route
    /// it to the exit.
    ///
    /// # Panics
    ///
    /// Panics if either endpoint is not a valid id for this graph.
    pub fn back_edge(&mut self, from: BlockId, to: BlockId) {
        self.cfg.add_edge(from, to);
        self.frontier.retain(|&open| open != from);
    }

    /// Wires every open frontier block into `target` and empties the
    /// frontier, modelling an unconditional jump such as `break`.
    ///
    /// # Panics
    ///
    /// Panics if `target` is not a valid id for this graph.
    pub fn jump_to(&mut self, target: BlockId) {
        for open in std::mem::take(&mut self.frontier) {
            self.cfg.add_edge(open, target);
        }
    }

    /// Adds the edge `from -> to` without touching the frontier.
    ///
    /// # Panics
    ///
    /// Panics if either endpoint is not a valid id for this graph.
    pub fn add_edge(&mut self, from: BlockId, to: BlockId) -> bool {
        self.cfg.add_edge(from, to)
    }

    /// Appends an isolated block without touching the frontier.
    pub fn create_block(&mut self, payload: T) -> BlockId {
        self.cfg.append_node(payload)
    }

    /// Replaces the open frontier with `targets`.
    pub fn set_frontier<I>(&mut self, targets: I)
    where
        I: IntoIterator<Item = BlockId>,
    {
        self.frontier = targets.into_iter().collect();
    }

    /// Returns the currently open frontier blocks.
    #[must_use]
    pub fn frontier(&self) -> &[BlockId] {
        &self.frontier
    }

    /// Drains and returns the open frontier, leaving it empty.
    pub fn take_frontier(&mut self) -> Vec<BlockId> {
        std::mem::take(&mut self.frontier)
    }

    /// Returns the id the next appended block will receive.
    #[must_use]
    pub fn next_block_id(&self) -> BlockId {
        self.cfg.next_block_id()
    }

    /// Returns the exit block id (always `1`).
    #[must_use]
    pub const fn exit(&self) -> BlockId {
        self.cfg.exit()
    }

    /// Seals the graph: remaining frontier blocks are routed to the exit and
    /// the finished [`Cfg`] is returned.
    #[must_use]
    pub fn finish(mut self) -> Cfg<T> {
        let exit = self.cfg.exit();
        for open in std::mem::take(&mut self.frontier) {
            self.cfg.add_edge(open, exit);
        }
        self.cfg
    }
}

impl<T> Default for CfgBuilder<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::new(T::default(), T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::{Def, Nop, St, Use, block_by_payload};

    #[test]
    fn builder_push_chains_through_frontier() {
        let mut builder = CfgBuilder::new(Use("entry"), Use("exit"));
        let a = builder.push_block(Def("a", 0));
        let b = builder.push_block(Use("a"));
        let cfg = builder.finish();
        let expected = [cfg.entry(), a, b, cfg.exit()];
        for pair in expected.windows(2) {
            assert!(cfg.has_edge(pair[0], pair[1]));
        }
        assert_eq!(cfg.edge_count(), 3);
    }

    #[test]
    fn builder_branch_forms_explicit_diamond() {
        let mut builder = CfgBuilder::new(Nop, Nop);
        let (then_id, else_id) = builder.branch(Use("c"), Def("t", 0), Def("e", 0));
        let cfg = builder.finish();
        let cond = block_by_payload(&cfg, &Use("c"));
        assert!(cfg.has_edge(cfg.entry(), cond));
        assert!(cfg.has_edge(cond, then_id));
        assert!(cfg.has_edge(cond, else_id));
        assert!(cfg.has_edge(then_id, cfg.exit()));
        assert!(cfg.has_edge(else_id, cfg.exit()));
    }

    #[test]
    fn builder_back_edge_closes_source_against_exit() {
        let mut builder = CfgBuilder::new(Nop, Nop);
        let a = builder.push_block(Nop);
        let b = builder.create_block(Nop);
        builder.set_frontier([a, b]);
        builder.back_edge(b, a);
        assert_eq!(builder.frontier(), &[a], "back edge closes only its source");
        builder.set_frontier([a]);
        let cfg = builder.finish();
        assert!(cfg.has_edge(b, a));
        assert!(!cfg.has_edge(b, cfg.exit()));
    }

    #[test]
    fn builder_jump_to_routes_frontier_and_clears_it() {
        let mut builder = CfgBuilder::new(Nop, Nop);
        let a = builder.push_block(Nop);
        let target = builder.create_block(Def("t", 0));
        builder.jump_to(target);
        assert!(builder.frontier().is_empty());
        let drained = builder.take_frontier();
        assert!(drained.is_empty());
        let cfg = builder.finish();
        assert!(cfg.has_edge(a, target));
        assert!(!cfg.has_edge(a, cfg.exit()));
    }

    #[test]
    fn builder_set_frontier_and_low_level_helpers() {
        let mut builder: CfgBuilder<St> = CfgBuilder::new(Nop, Nop);
        let marker = builder.create_block(Nop);
        builder.set_frontier([marker]);
        assert_eq!(builder.frontier(), &[marker]);
        assert_eq!(builder.take_frontier(), vec![marker]);
        let extra = builder.create_block(Use("x"));
        assert!(builder.add_edge(marker, extra));
        assert_eq!(
            builder.next_block_id(),
            BlockId::new(u32::try_from(extra.index() + 1).expect("id fits u32")),
        );
        builder.set_frontier([extra]);
        let cfg = builder.finish();
        assert!(cfg.has_edge(extra, cfg.exit()));
    }

    #[test]
    fn builder_finish_without_blocks_links_entry_to_exit() {
        let cfg: Cfg<St> = CfgBuilder::new(Use("entry"), Use("exit")).finish();
        assert_eq!(cfg.edge_count(), 1);
        assert!(cfg.has_edge(cfg.entry(), cfg.exit()));
    }
}
