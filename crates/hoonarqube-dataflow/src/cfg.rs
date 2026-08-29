//! Control-flow graph primitives: dense block ids, the [`Cfg`] graph, and
//! its algorithms (reachability, pruning, cycle detection, dominators).

use std::collections::BTreeSet;

/// Dense identifier of one basic block inside a [`Cfg`].
///
/// Ids are assigned densely from `0` by [`crate::CfgBuilder`] and remain stable for
/// the lifetime of a graph; only [`Cfg::into_reachable_subgraph`] renumbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockId(u32);

impl BlockId {
    /// Creates an id from a dense block index.
    #[must_use]
    pub const fn new(index: u32) -> Self {
        Self(index)
    }

    /// Returns the dense index of this block, suitable for `Vec` indexing.
    #[must_use]
    pub fn index(self) -> usize {
        self.0 as usize
    }
}

/// A control-flow graph whose blocks carry opaque statement payloads `T`.
///
/// Blocks `0` and `1` are always the entry and the exit respectively; every
/// other block was appended by a builder. Edge sets are deduplicated and
/// mirrored between successor and predecessor lists.
#[derive(Debug, Clone)]
pub struct Cfg<T> {
    payloads: Vec<T>,
    succs: Vec<Vec<BlockId>>,
    preds: Vec<Vec<BlockId>>,
    entry: BlockId,
    exit: BlockId,
}

impl<T> Cfg<T> {
    /// Creates a minimal graph with an entry and an exit block connected by a
    /// single edge.
    #[must_use]
    pub fn new(entry_payload: T, exit_payload: T) -> Self {
        let mut cfg = Self::disconnected(entry_payload, exit_payload);
        let (entry, exit) = (cfg.entry, cfg.exit);
        cfg.add_edge(entry, exit);
        cfg
    }

    /// Creates an entry/exit pair with no edge between them.
    ///
    /// This is the raw form used by [`crate::CfgBuilder`]; prefer [`Cfg::new`] or the
    /// builder for real graphs.
    #[must_use]
    pub fn disconnected(entry_payload: T, exit_payload: T) -> Self {
        Self {
            payloads: vec![entry_payload, exit_payload],
            succs: vec![Vec::new(), Vec::new()],
            preds: vec![Vec::new(), Vec::new()],
            entry: BlockId::new(0),
            exit: BlockId::new(1),
        }
    }

    /// Returns the entry block id (always `0`).
    #[must_use]
    pub const fn entry(&self) -> BlockId {
        self.entry
    }

    /// Returns the exit block id (always `1`).
    #[must_use]
    pub const fn exit(&self) -> BlockId {
        self.exit
    }

    /// Returns the number of blocks, including entry and exit.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.payloads.len()
    }

    /// Returns whether `block` is a valid id for this graph.
    #[must_use]
    pub fn contains_block(&self, block: BlockId) -> bool {
        block.index() < self.payloads.len()
    }

    /// Returns the number of directed edges.
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.succs.iter().map(Vec::len).sum()
    }

    /// Returns the statement payload of `block`.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not a valid id for this graph.
    #[must_use]
    pub fn payload(&self, block: BlockId) -> &T {
        &self.payloads[block.index()]
    }

    /// Returns the successor blocks of `block`.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not a valid id for this graph.
    #[must_use]
    pub fn successors(&self, block: BlockId) -> &[BlockId] {
        &self.succs[block.index()]
    }

    /// Returns the predecessor blocks of `block`.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not a valid id for this graph.
    #[must_use]
    pub fn predecessors(&self, block: BlockId) -> &[BlockId] {
        &self.preds[block.index()]
    }

    /// Iterates all block ids in ascending order.
    ///
    /// # Panics
    ///
    /// Panics if the block count exceeds [`u32::MAX`] (unreachable in
    /// practice; enforced at every append).
    pub fn blocks(&self) -> impl Iterator<Item = BlockId> {
        let len = u32::try_from(self.payloads.len()).expect("block count exceeds u32::MAX");
        (0..len).map(BlockId::new)
    }

    /// Returns `true` if the edge `from -> to` exists.
    ///
    /// # Panics
    ///
    /// Panics if either endpoint is not a valid id for this graph.
    #[must_use]
    pub fn has_edge(&self, from: BlockId, to: BlockId) -> bool {
        self.succs[from.index()].contains(&to)
    }

    /// Adds the edge `from -> to` if absent. Returns whether the edge is new.
    ///
    /// # Panics
    ///
    /// Panics if either endpoint is not a valid id for this graph.
    pub fn add_edge(&mut self, from: BlockId, to: BlockId) -> bool {
        self.assert_valid_block(from);
        self.assert_valid_block(to);
        let succs = &mut self.succs[from.index()];
        if succs.contains(&to) {
            return false;
        }
        succs.push(to);
        self.preds[to.index()].push(from);
        true
    }

    /// Removes the edge `from -> to` if present. Returns whether it existed.
    ///
    /// # Panics
    ///
    /// Panics if either endpoint is not a valid id for this graph.
    pub fn remove_edge(&mut self, from: BlockId, to: BlockId) -> bool {
        self.assert_valid_block(from);
        self.assert_valid_block(to);
        let succs = &mut self.succs[from.index()];
        let Some(pos) = succs.iter().position(|&succ| succ == to) else {
            return false;
        };
        succs.remove(pos);
        let preds = &mut self.preds[to.index()];
        let pred_pos = preds
            .iter()
            .position(|&pred| pred == from)
            .expect("mirrored predecessor missing");
        preds.remove(pred_pos);
        true
    }

    /// Appends an isolated block carrying `payload` and returns its id.
    ///
    /// The new block has no edges; callers wire it with [`Cfg::add_edge`].
    pub fn append_node(&mut self, payload: T) -> BlockId {
        let id = self.next_block_id();
        self.payloads.push(payload);
        self.succs.push(Vec::new());
        self.preds.push(Vec::new());
        id
    }

    /// Returns the id the next appended block will receive.
    ///
    /// # Panics
    ///
    /// Panics if appending another block would make the block count exceed
    /// [`u32::MAX`] (unreachable in practice; enforced at every append).
    #[must_use]
    pub fn next_block_id(&self) -> BlockId {
        let len = u32::try_from(self.payloads.len()).expect("block count exceeds u32::MAX");
        assert!(len < u32::MAX, "block count reached u32::MAX");
        BlockId::new(len)
    }

    pub(crate) fn assert_valid_block(&self, block: BlockId) {
        assert!(
            self.contains_block(block),
            "block {} is not valid for a graph with {} blocks",
            block.index(),
            self.node_count()
        );
    }

    /// Collects every block reachable from the entry along forward edges.
    #[must_use]
    pub fn reachable_from_entry(&self) -> BTreeSet<BlockId> {
        let mut seen = vec![false; self.payloads.len()];
        seen[self.entry.index()] = true;
        let mut stack = vec![self.entry];
        while let Some(block) = stack.pop() {
            for &next in &self.succs[block.index()] {
                if !seen[next.index()] {
                    seen[next.index()] = true;
                    stack.push(next);
                }
            }
        }
        self.blocks().filter(|block| seen[block.index()]).collect()
    }

    /// Drops every block unreachable from the entry and renumbers the rest
    /// densely in ascending order.
    ///
    /// The exit is always retained even when no path reaches it (e.g. a program
    /// ending in an endless loop); the entry therefore keeps id `0`, but the
    /// exit's id may shift when unreachable blocks preceded it.
    #[must_use]
    pub fn into_reachable_subgraph(self) -> Self {
        let mut keep = self.reachable_from_entry();
        keep.insert(self.exit);
        let mut remap: Vec<Option<u32>> = vec![None; self.payloads.len()];
        Self::prune_impl(self, &keep, &mut remap)
    }

    fn prune_impl(self, keep: &BTreeSet<BlockId>, remap: &mut [Option<u32>]) -> Self {
        for (index, old) in keep.iter().enumerate() {
            remap[old.index()] = Some(u32::try_from(index).expect("kept blocks fit u32"));
        }
        let map_target = |target: &BlockId| remap[target.index()].map(BlockId::new);
        let mut new_payloads = Vec::with_capacity(keep.len());
        for (idx, payload) in self.payloads.into_iter().enumerate() {
            if remap[idx].is_some() {
                new_payloads.push(payload);
            }
        }
        let new_succs: Vec<Vec<BlockId>> = keep
            .iter()
            .map(|old| {
                self.succs[old.index()]
                    .iter()
                    .filter_map(map_target)
                    .collect()
            })
            .collect();
        let new_preds: Vec<Vec<BlockId>> = keep
            .iter()
            .map(|old| {
                self.preds[old.index()]
                    .iter()
                    .filter_map(map_target)
                    .collect()
            })
            .collect();
        Self {
            payloads: new_payloads,
            succs: new_succs,
            preds: new_preds,
            entry: BlockId::new(remap[self.entry.index()].expect("entry is reachable")),
            exit: BlockId::new(remap[self.exit.index()].expect("exit is always retained")),
        }
    }

    /// Returns `true` if the graph contains at least one cycle or self-loop.
    #[must_use]
    pub fn contains_cycle(&self) -> bool {
        !self.blocks_on_cycles().is_empty()
    }

    /// Collects every block lying on a cycle (including self-loops).
    ///
    /// Uses an iterative Kosaraju strongly-connected-components pass: a block
    /// is "on a cycle" when its SCC has more than one member or it links to
    /// itself.
    #[must_use]
    pub fn blocks_on_cycles(&self) -> BTreeSet<BlockId> {
        let (labels, count) = self.scc_labels();
        let mut sizes = vec![0usize; count];
        for &label in &labels {
            sizes[label] += 1;
        }
        let mut cyclic = BTreeSet::new();
        for block in self.blocks() {
            let idx = block.index();
            let self_loop = self.succs[idx].contains(&block);
            if self_loop || sizes[labels[idx]] > 1 {
                cyclic.insert(block);
            }
        }
        cyclic
    }

    /// Computes the immediate-dominator tree over the blocks reachable from
    /// the entry with the simple iterative Cooper-Harvey-Kennedy algorithm.
    #[must_use]
    pub fn dominators(&self) -> Dominators {
        let len = self.payloads.len();
        let reverse_post_order = self.reverse_post_order_from_entry();
        let mut rpo_pos: Vec<Option<usize>> = vec![None; len];
        for (pos, block) in reverse_post_order.iter().enumerate() {
            rpo_pos[block.index()] = Some(pos);
        }
        let idoms = self.compute_idoms(&reverse_post_order, &rpo_pos);
        let children = self.dominator_children(&idoms);
        let entry = self.entry;
        let (preorder, postorder) = Self::dominator_intervals(entry, &children);
        // Strip only the entry self-reference: genuine idominators pointing at
        // the entry must stay visible to callers.
        let public_idoms = idoms
            .iter()
            .enumerate()
            .map(|(idx, dom)| if idx == entry.index() { None } else { *dom })
            .collect();
        let reachable = rpo_pos.iter().map(Option::is_some).collect();
        Dominators {
            entry,
            idoms: public_idoms,
            reachable,
            children,
            preorder,
            postorder,
        }
    }

    fn compute_idoms(
        &self,
        reverse_post_order: &[BlockId],
        rpo_pos: &[Option<usize>],
    ) -> Vec<Option<BlockId>> {
        // Raw idoms: `None` marks unprocessed blocks; the entry starts as its
        // own idominator so the finger intersection terminates.
        let mut idoms = vec![None; self.payloads.len()];
        if let Some(&root) = reverse_post_order.first() {
            idoms[root.index()] = Some(root);
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &block in &reverse_post_order[1..] {
                let candidate = self.dominator_candidate(block, &idoms, rpo_pos);
                if candidate != idoms[block.index()] {
                    idoms[block.index()] = candidate;
                    changed = true;
                }
            }
        }
        idoms
    }

    fn dominator_candidate(
        &self,
        block: BlockId,
        idoms: &[Option<BlockId>],
        rpo_pos: &[Option<usize>],
    ) -> Option<BlockId> {
        let mut candidate = None;
        for &predecessor in &self.preds[block.index()] {
            if idoms[predecessor.index()].is_some() {
                candidate = Some(match candidate {
                    None => predecessor,
                    Some(current) => Self::intersect(current, predecessor, idoms, rpo_pos),
                });
            }
        }
        candidate
    }

    fn dominator_children(&self, idoms: &[Option<BlockId>]) -> Vec<Vec<BlockId>> {
        let mut children = vec![Vec::new(); self.payloads.len()];
        for block in self.blocks() {
            if block != self.entry
                && let Some(dom) = idoms[block.index()]
            {
                children[dom.index()].push(block);
            }
        }
        children
    }

    fn dominator_intervals(entry: BlockId, children: &[Vec<BlockId>]) -> (Vec<usize>, Vec<usize>) {
        let mut preorder = vec![usize::MAX; children.len()];
        let mut postorder = vec![usize::MAX; children.len()];
        let mut clock = 0usize;
        preorder[entry.index()] = clock;
        clock += 1;
        let mut stack = vec![(entry, 0usize)];
        while let Some(frame) = stack.last_mut() {
            if let Some(&child) = children[frame.0.index()].get(frame.1) {
                frame.1 += 1;
                preorder[child.index()] = clock;
                clock += 1;
                stack.push((child, 0));
            } else {
                let (block, _) = stack.pop().expect("stack contains current frame");
                postorder[block.index()] = clock;
                clock += 1;
            }
        }
        (preorder, postorder)
    }

    fn intersect(
        mut finger_a: BlockId,
        mut finger_b: BlockId,
        idoms: &[Option<BlockId>],
        rpo_pos: &[Option<usize>],
    ) -> BlockId {
        while finger_a != finger_b {
            while rpo_pos[finger_a.index()] > rpo_pos[finger_b.index()] {
                finger_a = idoms[finger_a.index()].expect("processed node has an idom");
            }
            while rpo_pos[finger_b.index()] > rpo_pos[finger_a.index()] {
                finger_b = idoms[finger_b.index()].expect("processed node has an idom");
            }
        }
        finger_a
    }

    fn reverse_post_order_from_entry(&self) -> Vec<BlockId> {
        let mut order = Vec::with_capacity(self.payloads.len());
        let mut visited = vec![false; self.payloads.len()];
        visited[self.entry.index()] = true;
        let mut stack = vec![(self.entry, 0usize)];
        while let Some(frame) = stack.last_mut() {
            let succs = &self.succs[frame.0.index()];
            if frame.1 < succs.len() {
                let next = succs[frame.1];
                frame.1 += 1;
                if !visited[next.index()] {
                    visited[next.index()] = true;
                    stack.push((next, 0));
                }
            } else if let Some((block, _)) = stack.pop() {
                order.push(block);
            }
        }
        order.reverse();
        order
    }

    fn scc_labels(&self) -> (Vec<usize>, usize) {
        let finish_order = self.scc_finish_order();
        let mut labels = vec![usize::MAX; self.payloads.len()];
        let mut label = 0;
        for &block in finish_order.iter().rev() {
            if labels[block.index()] == usize::MAX {
                self.label_reverse_component(block, label, &mut labels);
                label += 1;
            }
        }
        (labels, label)
    }

    fn scc_finish_order(&self) -> Vec<BlockId> {
        let mut visited = vec![false; self.payloads.len()];
        let mut finish_order = Vec::with_capacity(self.payloads.len());
        for start in self.blocks() {
            if !visited[start.index()] {
                self.append_finish_order(start, &mut visited, &mut finish_order);
            }
        }
        finish_order
    }

    fn append_finish_order(
        &self,
        start: BlockId,
        visited: &mut [bool],
        finish_order: &mut Vec<BlockId>,
    ) {
        visited[start.index()] = true;
        let mut stack = vec![(start, 0usize)];
        while let Some(frame) = stack.last_mut() {
            let successors = &self.succs[frame.0.index()];
            if frame.1 < successors.len() {
                let next = successors[frame.1];
                frame.1 += 1;
                if !visited[next.index()] {
                    visited[next.index()] = true;
                    stack.push((next, 0));
                }
            } else if let Some((block, _)) = stack.pop() {
                finish_order.push(block);
            }
        }
    }

    fn label_reverse_component(&self, block: BlockId, label: usize, labels: &mut [usize]) {
        labels[block.index()] = label;
        let mut stack = vec![block];
        while let Some(node) = stack.pop() {
            for &predecessor in &self.preds[node.index()] {
                if labels[predecessor.index()] == usize::MAX {
                    labels[predecessor.index()] = label;
                    stack.push(predecessor);
                }
            }
        }
    }
}

/// Immediate-dominator tree of a [`Cfg`], as computed by [`Cfg::dominators`].
///
/// The entry has no immediate dominator; blocks unreachable from the entry
/// report `None` as well and participate in no domination relation beyond
/// reflexivity.
#[derive(Debug, Clone)]
pub struct Dominators {
    entry: BlockId,
    idoms: Vec<Option<BlockId>>,
    reachable: Vec<bool>,
    children: Vec<Vec<BlockId>>,
    preorder: Vec<usize>,
    postorder: Vec<usize>,
}

impl Dominators {
    /// Returns the entry block of the originating graph.
    #[must_use]
    pub const fn entry(&self) -> BlockId {
        self.entry
    }
    /// Returns the immediate dominator of `block`, or `None` for the entry and
    /// for blocks unreachable from the entry.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not a valid id of the originating graph.
    #[must_use]
    pub fn immediate_dominator(&self, block: BlockId) -> Option<BlockId> {
        self.idoms[block.index()]
    }

    /// Returns the blocks whose immediate dominator is `block`.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not a valid id of the originating graph.
    #[must_use]
    pub fn immediate_dominated_by(&self, block: BlockId) -> &[BlockId] {
        &self.children[block.index()]
    }

    /// Returns `true` if `a` dominates `b` inclusively (`a == b` counts when
    /// `b` is reachable from the entry).
    ///
    /// # Panics
    ///
    /// Panics if either argument is not a valid id of the originating graph.
    #[must_use]
    pub fn dominates(&self, a: BlockId, b: BlockId) -> bool {
        if a == b {
            return self.reachable[b.index()];
        }
        self.strictly_dominates(a, b)
    }

    /// Returns `true` if `a` strictly dominates `b` (`a != b` and every path
    /// from the entry to `b` passes through `a`).
    ///
    /// # Panics
    ///
    /// Panics if either argument is not a valid id of the originating graph.
    #[must_use]
    pub fn strictly_dominates(&self, a: BlockId, b: BlockId) -> bool {
        self.assert_valid_block(a);
        self.assert_valid_block(b);
        a != b
            && self.reachable[a.index()]
            && self.reachable[b.index()]
            && self.preorder[a.index()] < self.preorder[b.index()]
            && self.postorder[b.index()] < self.postorder[a.index()]
    }

    fn assert_valid_block(&self, block: BlockId) {
        assert!(
            block.index() < self.idoms.len(),
            "block {} is not valid for a dominator tree with {} blocks",
            block.index(),
            self.idoms.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use crate::test_support::{Def, Nop, St, Use, block_by_payload, stmts};

    use crate::{CfgBuilder, ControlFlowSpec, build_from_blocks};

    #[test]
    fn block_id_roundtrip_and_ordering() {
        let id = BlockId::new(7);
        assert_eq!(id.index(), 7);
        assert!(BlockId::new(8) > BlockId::new(7));
    }

    #[test]
    fn cfg_new_has_single_entry_exit_edge() {
        let cfg: Cfg<St> = Cfg::new(Use("entry"), Use("exit"));
        assert_eq!(cfg.entry(), BlockId::new(0));
        assert_eq!(cfg.exit(), BlockId::new(1));
        assert_eq!(cfg.node_count(), 2);
        assert_eq!(cfg.edge_count(), 1);
        assert!(cfg.has_edge(cfg.entry(), cfg.exit()));
        assert_eq!(cfg.payload(cfg.entry()), &Use("entry"));
        assert_eq!(
            cfg.blocks().collect::<Vec<_>>(),
            vec![BlockId::new(0), BlockId::new(1)]
        );
        let raw: Cfg<St> = Cfg::disconnected(Nop, Nop);
        assert_eq!(raw.edge_count(), 0);
    }

    #[test]
    fn cfg_edges_stay_mirrored_and_deduplicated() {
        let mut cfg: Cfg<St> = Cfg::new(Nop, Nop);
        let node = cfg.append_node(Nop);
        assert!(cfg.contains_block(node));
        assert!(!cfg.contains_block(BlockId::new(99)));
        assert_eq!(
            cfg.next_block_id(),
            BlockId::new(u32::try_from(node.index() + 1).expect("id fits u32")),
        );
        assert!(cfg.add_edge(cfg.entry(), node));
        assert!(!cfg.add_edge(cfg.entry(), node), "duplicate edge rejected");
        assert!(cfg.has_edge(cfg.entry(), node));
        assert_eq!(cfg.predecessors(node), &[cfg.entry()]);
        assert!(cfg.remove_edge(cfg.entry(), node));
        assert!(!cfg.remove_edge(cfg.entry(), node));
        assert!(cfg.predecessors(node).is_empty());
    }

    #[test]
    fn invalid_edge_endpoints_do_not_partially_mutate_graph() {
        let mut cfg: Cfg<St> = Cfg::new(Nop, Nop);
        let before_edges = cfg.edge_count();
        let before_successors = cfg.successors(cfg.entry()).to_vec();
        let invalid = BlockId::new(99);

        let add = catch_unwind(AssertUnwindSafe(|| cfg.add_edge(cfg.entry(), invalid)));
        assert!(add.is_err());
        assert_eq!(cfg.edge_count(), before_edges);
        assert_eq!(cfg.successors(cfg.entry()), before_successors);

        let remove = catch_unwind(AssertUnwindSafe(|| cfg.remove_edge(cfg.entry(), invalid)));
        assert!(remove.is_err());
        assert_eq!(cfg.edge_count(), before_edges);
        assert_eq!(cfg.successors(cfg.entry()), before_successors);
    }

    #[test]
    #[should_panic(expected = "index out of bounds")]
    fn cfg_payload_panics_on_invalid_id() {
        let cfg: Cfg<St> = Cfg::new(Nop, Nop);
        let _ = cfg.payload(BlockId::new(42));
    }

    #[test]
    fn dominators_on_diamond_join() {
        let cfg = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c"),
                then_arm: Box::new(ControlFlowSpec::Stmt(Def("x", 0))),
                else_arm: Some(Box::new(ControlFlowSpec::Stmt(Def("y", 0)))),
            },
            Nop,
            Nop,
        );
        let doms = cfg.dominators();
        let cond = block_by_payload(&cfg, &Use("c"));
        let then_block = block_by_payload(&cfg, &Def("x", 0));
        let else_block = block_by_payload(&cfg, &Def("y", 0));
        assert!(doms.immediate_dominator(cfg.entry()).is_none());
        assert_eq!(doms.immediate_dominator(cond), Some(cfg.entry()));
        assert_eq!(doms.immediate_dominator(then_block), Some(cond));
        assert_eq!(doms.immediate_dominator(else_block), Some(cond));
        assert!(doms.strictly_dominates(cfg.entry(), cfg.exit()));
        assert!(!doms.strictly_dominates(then_block, else_block));
        assert!(doms.dominates(cond, cfg.exit()));
        assert!(doms.dominates(cond, cond));
        assert_eq!(
            doms.immediate_dominated_by(cond),
            &[cfg.exit(), then_block, else_block]
        );
    }

    #[test]
    fn dominators_on_nested_branches() {
        let cfg = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c1"),
                then_arm: Box::new(ControlFlowSpec::Seq(vec![
                    ControlFlowSpec::Stmt(Def("a", 1)),
                    ControlFlowSpec::If {
                        condition: Use("c2"),
                        then_arm: Box::new(ControlFlowSpec::Stmt(Def("b", 2))),
                        else_arm: Some(Box::new(ControlFlowSpec::Stmt(Def("c", 3)))),
                    },
                ])),
                else_arm: Some(Box::new(ControlFlowSpec::Stmt(Def("d", 4)))),
            },
            Nop,
            Nop,
        );
        let doms = cfg.dominators();
        let outer = block_by_payload(&cfg, &Use("c1"));
        let inner = block_by_payload(&cfg, &Use("c2"));
        let a = block_by_payload(&cfg, &Def("a", 1));
        assert_eq!(doms.immediate_dominator(a), Some(outer));
        assert_eq!(doms.immediate_dominator(inner), Some(a));
        assert!(doms.strictly_dominates(outer, inner));
        assert!(doms.strictly_dominates(inner, block_by_payload(&cfg, &Def("b", 2))));
        assert!(!doms.dominates(inner, block_by_payload(&cfg, &Def("d", 4))));
    }

    #[test]
    fn dominators_ignore_unreachable_blocks() {
        let mut builder = CfgBuilder::new(Nop, Nop);
        let reachable = builder.push_block(Def("x", 0));
        builder.create_block(Def("dead", 0));
        builder.set_frontier([reachable]);
        let cfg = builder.finish();
        let orphan = BlockId::new(3);
        let doms = cfg.dominators();
        assert!(doms.immediate_dominator(orphan).is_none());
        assert!(!doms.dominates(cfg.entry(), orphan));
        assert!(
            doms.immediate_dominated_by(cfg.entry())
                .contains(&reachable)
        );
    }

    #[test]
    fn cycle_detection_distinguishes_shapes() {
        let linear = build_from_blocks(stmts(&[Def("a", 0), Use("a")]), Nop, Nop);
        assert!(!linear.contains_cycle());
        assert!(linear.blocks_on_cycles().is_empty());

        let looping = build_from_blocks(
            ControlFlowSpec::DoWhile {
                body: Box::new(ControlFlowSpec::Stmt(Def("i", 0))),
                condition: Use("c"),
            },
            Nop,
            Nop,
        );
        assert!(looping.contains_cycle());
        let cyclic = looping.blocks_on_cycles();
        assert!(cyclic.contains(&block_by_payload(&looping, &Def("i", 0))));
        assert!(cyclic.contains(&block_by_payload(&looping, &Use("c"))));

        let mut builder: CfgBuilder<St> = CfgBuilder::new(Nop, Nop);
        let self_loop = builder.create_block(Nop);
        builder.set_frontier([self_loop]);
        let mut self_cfg = builder.finish();
        assert!(self_cfg.add_edge(self_loop, self_loop));
        assert!(self_cfg.contains_cycle());
        assert_eq!(self_cfg.blocks_on_cycles(), BTreeSet::from([self_loop]));
    }

    #[test]
    fn pruning_drops_unreachable_and_compacts_ids() {
        let mut builder = CfgBuilder::new(Nop, Nop);
        let live = builder.push_block(Def("keep", 0));
        builder.create_block(Def("drop", 0));
        builder.set_frontier([live]);
        let cfg = builder.finish();
        assert_eq!(cfg.node_count(), 4);
        assert_eq!(cfg.edge_count(), 2);

        let pruned = cfg.into_reachable_subgraph();
        assert_eq!(pruned.node_count(), 3);
        assert_eq!(pruned.edge_count(), 2);
        assert_eq!(pruned.exit(), BlockId::new(1));
        assert_eq!(pruned.payload(BlockId::new(2)), &Def("keep", 0));
        assert!(pruned.has_edge(pruned.entry(), BlockId::new(2)));
        assert!(
            pruned
                .blocks()
                .all(|block| pruned.payload(block) != &Def("drop", 0))
        );
        assert_eq!(
            pruned.reachable_from_entry().len(),
            pruned.node_count(),
            "pruned graph is fully reachable"
        );
    }

    #[test]
    fn reachable_from_entry_walks_all_forward_paths() {
        let cfg = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c"),
                then_arm: Box::new(ControlFlowSpec::Stmt(Def("x", 0))),
                else_arm: Some(Box::new(ControlFlowSpec::Stmt(Def("y", 0)))),
            },
            Nop,
            Nop,
        );
        assert_eq!(cfg.reachable_from_entry().len(), cfg.node_count());
    }

    #[test]
    fn graph_algorithms_match_independent_references() {
        for mask in 0..(1_u64 << 9) {
            check_graph_algorithms(&graph_from_mask(3, mask));
        }

        let mut state = 0x6a09_e667_f3bc_c909_u64;
        for nodes in 4..=8 {
            for _ in 0..128 {
                state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                check_graph_algorithms(&graph_from_mask(nodes, state));
            }
        }
    }

    #[test]
    fn graph_algorithms_are_stack_safe_on_deep_cycles() {
        const NODES: usize = 25_000;
        let mut cfg = Cfg::disconnected(0_u32, 1);
        for payload in 2..u32::try_from(NODES).expect("test size fits u32") {
            cfg.append_node(payload);
        }
        let first_body = BlockId::new(2);
        cfg.add_edge(cfg.entry(), first_body);
        for index in 2..NODES - 1 {
            cfg.add_edge(
                BlockId::new(u32::try_from(index).expect("index fits u32")),
                BlockId::new(u32::try_from(index + 1).expect("index fits u32")),
            );
        }
        let tail = BlockId::new(u32::try_from(NODES - 1).expect("index fits u32"));
        cfg.add_edge(tail, first_body);
        cfg.add_edge(tail, cfg.exit());

        assert_eq!(cfg.reachable_from_entry().len(), NODES);
        assert_eq!(cfg.blocks_on_cycles().len(), NODES - 2);
        let dominators = cfg.dominators();
        assert!(dominators.strictly_dominates(cfg.entry(), cfg.exit()));
        assert_eq!(
            dominators.immediate_dominator(first_body),
            Some(cfg.entry())
        );
    }

    fn graph_from_mask(nodes: usize, mask: u64) -> Cfg<u8> {
        let mut cfg = Cfg::disconnected(0, 1);
        for payload in 2..u8::try_from(nodes).expect("test size fits u8") {
            cfg.append_node(payload);
        }
        for from in 0..nodes {
            for to in 0..nodes {
                let bit = from * nodes + to;
                if mask & (1_u64 << bit) != 0 {
                    cfg.add_edge(
                        BlockId::new(u32::try_from(from).expect("index fits u32")),
                        BlockId::new(u32::try_from(to).expect("index fits u32")),
                    );
                }
            }
        }
        cfg
    }

    fn check_graph_algorithms(cfg: &Cfg<u8>) {
        let reachable = cfg.reachable_from_entry();
        let expected_reachable = cfg
            .blocks()
            .filter(|&block| path_exists(cfg, cfg.entry(), block, None))
            .collect::<BTreeSet<_>>();
        assert_eq!(reachable, expected_reachable);
        check_reachable_pruning(cfg, &reachable);

        let expected_cycles = cfg
            .blocks()
            .filter(|&block| {
                cfg.successors(block)
                    .iter()
                    .any(|&successor| path_exists(cfg, successor, block, None))
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(cfg.blocks_on_cycles(), expected_cycles);
        assert_eq!(cfg.contains_cycle(), !expected_cycles.is_empty());

        let dominators = cfg.dominators();
        for dominated in cfg.blocks() {
            let strict = cfg
                .blocks()
                .filter(|&candidate| {
                    candidate != dominated && reference_dominates(cfg, candidate, dominated)
                })
                .collect::<Vec<_>>();
            let expected_idom = strict.iter().copied().find(|&candidate| {
                strict
                    .iter()
                    .all(|&other| other == candidate || reference_dominates(cfg, other, candidate))
            });
            assert_eq!(dominators.immediate_dominator(dominated), expected_idom);
            for candidate in cfg.blocks() {
                assert_eq!(
                    dominators.dominates(candidate, dominated),
                    reference_dominates(cfg, candidate, dominated)
                );
            }
        }
    }

    fn check_reachable_pruning(cfg: &Cfg<u8>, reachable: &BTreeSet<BlockId>) {
        let mut keep = reachable.clone();
        keep.insert(cfg.exit());
        let kept = keep.iter().copied().collect::<Vec<_>>();
        let mut remap = vec![None; cfg.node_count()];
        for (new_index, old) in kept.iter().enumerate() {
            remap[old.index()] = Some(BlockId::new(
                u32::try_from(new_index).expect("index fits u32"),
            ));
        }

        let pruned = cfg.clone().into_reachable_subgraph();
        assert_eq!(pruned.node_count(), kept.len());
        assert_eq!(
            pruned.entry(),
            remap[cfg.entry().index()].expect("entry kept")
        );
        assert_eq!(pruned.exit(), remap[cfg.exit().index()].expect("exit kept"));
        for &old in &kept {
            let new = remap[old.index()].expect("kept block remapped");
            assert_eq!(pruned.payload(new), cfg.payload(old));
            let expected_successors = cfg
                .successors(old)
                .iter()
                .filter_map(|successor| remap[successor.index()])
                .collect::<Vec<_>>();
            let expected_predecessors = cfg
                .predecessors(old)
                .iter()
                .filter_map(|predecessor| remap[predecessor.index()])
                .collect::<Vec<_>>();
            assert_eq!(pruned.successors(new), expected_successors);
            assert_eq!(pruned.predecessors(new), expected_predecessors);
        }
    }

    fn reference_dominates(cfg: &Cfg<u8>, candidate: BlockId, block: BlockId) -> bool {
        path_exists(cfg, cfg.entry(), block, None)
            && (candidate == block || !path_exists(cfg, cfg.entry(), block, Some(candidate)))
    }

    fn path_exists(cfg: &Cfg<u8>, start: BlockId, target: BlockId, skip: Option<BlockId>) -> bool {
        if Some(start) == skip {
            return false;
        }
        let mut seen = vec![false; cfg.node_count()];
        seen[start.index()] = true;
        let mut stack = vec![start];
        while let Some(block) = stack.pop() {
            if block == target {
                return true;
            }
            for &next in cfg.successors(block) {
                if Some(next) != skip && !seen[next.index()] {
                    seen[next.index()] = true;
                    stack.push(next);
                }
            }
        }
        false
    }
}
