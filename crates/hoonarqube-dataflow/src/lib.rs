//! Generic intra-procedural control-flow and dataflow analysis for Hoonarqube
//! language crates.
//!
//! This crate is the reusable Tier-B engine: language adapters lower their ASTs
//! onto [`ControlFlowSpec`] (or drive [`CfgBuilder`] directly), then run classic
//! worklist dataflow frameworks over the resulting [`Cfg`] with their own
//! lattice type `F`. Nothing here knows about a concrete language, issue
//! reporting, or the frozen catalog — that is deliberately the callers' job.
//!
//! The engine is allocation-conscious and dependency-free: graphs are flat
//! `Vec`s keyed by dense [`BlockId`]s, and payloads `T` (one statement bundle
//! per block) are moved, never cloned.
//!
//! # Example
//!
//! Build a diamond CFG from a structured description and solve reaching
//! definitions with a caller-owned union meet:
//!
//! ```
//! use hoonarqube_dataflow::{
//!     build_from_blocks, solve_dataflow, ControlFlowSpec, Direction, ReachingFacts,
//! };
//!
//! #[derive(Debug, Clone, PartialEq, Eq)]
//! enum Stmt {
//!     Def(&'static str),
//!     Use(&'static str),
//! }
//!
//! let spec = ControlFlowSpec::Seq(vec![
//!     ControlFlowSpec::Stmt(Stmt::Def("x")),
//!     ControlFlowSpec::If {
//!         condition: Stmt::Use("c"),
//!         then_arm: Box::new(ControlFlowSpec::Stmt(Stmt::Def("y"))),
//!         else_arm: None,
//!     },
//!     ControlFlowSpec::Stmt(Stmt::Use("z")),
//! ]);
//! let cfg = build_from_blocks(spec, Stmt::Use("entry"), Stmt::Use("exit"));
//! let result = solve_dataflow(
//!     &cfg,
//!     Direction::Forward,
//!     &ReachingFacts::new(),
//!     ReachingFacts::meet_union,
//!     |facts, stmt| {
//!         let mut next = facts.clone();
//!         if let Stmt::Def(var) = stmt {
//!             next.insert((*var, 0));
//!         }
//!         next
//!     },
//!     |_block, facts| facts.clone(),
//! );
//! // `x@0` and `y@0` both reach the exit along the join edge.
//! assert_eq!(result.out_fact(cfg.exit()).len(), 2);
//! ```

#![deny(missing_docs)]

use std::collections::{BTreeSet, VecDeque};

/// Dense identifier of one basic block inside a [`Cfg`].
///
/// Ids are assigned densely from `0` by [`CfgBuilder`] and remain stable for
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
    /// This is the raw form used by [`CfgBuilder`]; prefer [`Cfg::new`] or the
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
    /// Panics if the block count exceeds [`u32::MAX`] (unreachable in
    /// practice; enforced at every append).
    #[must_use]
    pub fn next_block_id(&self) -> BlockId {
        let len = u32::try_from(self.payloads.len()).expect("block count exceeds u32::MAX");
        BlockId::new(len)
    }

    /// Collects every block reachable from the entry along forward edges.
    #[must_use]
    pub fn reachable_from_entry(&self) -> BTreeSet<BlockId> {
        let mut seen = BTreeSet::new();
        seen.insert(self.entry);
        let mut stack = vec![self.entry];
        while let Some(block) = stack.pop() {
            for &next in &self.succs[block.index()] {
                if seen.insert(next) {
                    stack.push(next);
                }
            }
        }
        seen
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
        // Raw idoms: `None` marks unprocessed blocks; the entry starts as its
        // own idominator so the finger intersection terminates.
        let mut idoms: Vec<Option<BlockId>> = vec![None; len];
        if let Some(&root) = reverse_post_order.first() {
            idoms[root.index()] = Some(root);
        }
        let mut changed = true;
        while changed {
            changed = false;
            for &block in &reverse_post_order[1..] {
                let mut candidate: Option<BlockId> = None;
                for &pred in &self.preds[block.index()] {
                    if idoms[pred.index()].is_none() {
                        continue;
                    }
                    candidate = Some(match candidate {
                        None => pred,
                        Some(current) => Self::intersect(current, pred, &idoms, &rpo_pos),
                    });
                }
                if candidate != idoms[block.index()] {
                    idoms[block.index()] = candidate;
                    changed = true;
                }
            }
        }
        let entry = self.entry;
        let mut children: Vec<Vec<BlockId>> = vec![Vec::new(); len];
        for block in self.blocks() {
            if block != entry
                && let Some(dom) = idoms[block.index()]
            {
                children[dom.index()].push(block);
            }
        }
        // Strip only the entry self-reference: genuine idominators pointing at
        // the entry must stay visible to callers.
        let public_idoms: Vec<Option<BlockId>> = idoms
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
        }
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
            } else {
                let (block, _) = stack.pop().expect("frame checked above");
                order.push(block);
            }
        }
        order.reverse();
        order
    }

    fn scc_labels(&self) -> (Vec<usize>, usize) {
        let len = self.payloads.len();
        let mut visited = vec![false; len];
        let mut finish_order: Vec<BlockId> = Vec::with_capacity(len);
        for start in self.blocks() {
            if visited[start.index()] {
                continue;
            }
            visited[start.index()] = true;
            let mut stack = vec![(start, 0usize)];
            while let Some(frame) = stack.last_mut() {
                let succs = &self.succs[frame.0.index()];
                if frame.1 < succs.len() {
                    let next = succs[frame.1];
                    frame.1 += 1;
                    if !visited[next.index()] {
                        visited[next.index()] = true;
                        stack.push((next, 0));
                    }
                } else {
                    let (block, _) = stack.pop().expect("frame checked above");
                    finish_order.push(block);
                }
            }
        }
        let mut labels: Vec<usize> = vec![usize::MAX; len];
        let mut label = 0usize;
        for &block in finish_order.iter().rev() {
            if labels[block.index()] != usize::MAX {
                continue;
            }
            labels[block.index()] = label;
            let mut stack = vec![block];
            while let Some(node) = stack.pop() {
                for &pred in &self.preds[node.index()] {
                    if labels[pred.index()] == usize::MAX {
                        labels[pred.index()] = label;
                        stack.push(pred);
                    }
                }
            }
            label += 1;
        }
        (labels, label)
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
        if a == b || !self.reachable[b.index()] {
            return false;
        }
        let mut cursor = b;
        while let Some(next) = self.idoms[cursor.index()] {
            if next == a {
                return true;
            }
            cursor = next;
        }
        false
    }
}

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
        self.cfg.exit
    }

    /// Seals the graph: remaining frontier blocks are routed to the exit and
    /// the finished [`Cfg`] is returned.
    #[must_use]
    pub fn finish(mut self) -> Cfg<T> {
        let exit = self.cfg.exit;
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

/// Language-neutral description of structured control flow.
///
/// Adapters map their AST nodes onto this enum; [`build_from_blocks`] lowers
/// it into a [`Cfg`]. Payloads `T` are moved out of the description, so no
/// `Clone` bound is required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlFlowSpec<T> {
    /// One straight-line statement bundle occupying a single block.
    Stmt(T),
    /// Sequenced constructs, each lowered in order.
    Seq(Vec<Self>),
    /// Conditional branch; a missing else arm lets the condition block fall
    /// through to the join directly.
    If {
        /// Payload of the condition block.
        condition: T,
        /// Construct executed when the condition holds.
        then_arm: Box<Self>,
        /// Construct executed otherwise, if any.
        else_arm: Option<Box<Self>>,
    },
    /// Tested-loop shape covering `while` and `for`.
    ///
    /// A `None` condition models `for (;;)`; the loop-back then targets the
    /// body entries and the `step` is ignored because it would be unreachable,
    /// matching the source language.
    For {
        /// Run once before the loop header, if present.
        init: Option<Box<Self>>,
        /// Header condition evaluated before each iteration.
        condition: Option<T>,
        /// Loop body.
        body: Box<Self>,
        /// Run after each iteration, if present.
        step: Option<Box<Self>>,
    },
    /// Post-tested loop: the body runs at least once before the condition.
    DoWhile {
        /// Loop body.
        body: Box<Self>,
        /// Condition evaluated after each iteration.
        condition: T,
    },
    /// Exits the innermost enclosing loop; a no-op outside any loop.
    Break,
    /// Jumps to the re-evaluation point of the innermost enclosing loop; a
    /// no-op outside any loop.
    Continue,
    /// Exception-handling approximation.
    ///
    /// Normal completion of `body` flows onward; edges are added from the try
    /// region's entry points to the catch handler (or the finally block when
    /// no handler exists) to approximate a throw anywhere in the body. This is
    /// conservative for may-analyses and weakens must-analyses, which is the
    /// intended trade-off of the approximation.
    Try {
        /// Protected region.
        body: Box<Self>,
        /// Handler executed on the exceptional edge, if any.
        catch: Option<Box<Self>>,
        /// Executed after body/catch on every path, if any.
        finally: Option<Box<Self>>,
    },
}

/// Lowers a structured-control-flow description into a [`Cfg`].
///
/// The description is consumed by value so payloads move without cloning.
/// Entry and exit payloads are supplied explicitly because every block must
/// carry one; languages typically pass a synthetic no-op statement.
#[must_use]
pub fn build_from_blocks<T>(spec: ControlFlowSpec<T>, entry_payload: T, exit_payload: T) -> Cfg<T> {
    let mut builder = CfgBuilder::new(entry_payload, exit_payload);
    let mut loops = Vec::new();
    emit_spec(spec, &mut builder, &mut loops);
    builder.finish()
}

struct LoopContext {
    break_sources: Vec<BlockId>,
    continue_sources: Vec<BlockId>,
}

impl LoopContext {
    fn new() -> Self {
        Self {
            break_sources: Vec::new(),
            continue_sources: Vec::new(),
        }
    }
}

fn emit_spec<T>(
    spec: ControlFlowSpec<T>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    match spec {
        ControlFlowSpec::Stmt(payload) => {
            builder.push_block(payload);
        }
        ControlFlowSpec::Seq(items) => {
            for item in items {
                emit_spec(item, builder, loops);
            }
        }
        ControlFlowSpec::If {
            condition,
            then_arm,
            else_arm,
        } => emit_if(
            condition,
            *then_arm,
            else_arm.map(|boxed| *boxed),
            builder,
            loops,
        ),
        ControlFlowSpec::For {
            init,
            condition,
            body,
            step,
        } => {
            if let Some(pre) = init {
                emit_spec(*pre, builder, loops);
            }
            match condition {
                Some(cond) => {
                    emit_tested_loop(cond, *body, step.map(|boxed| *boxed), builder, loops);
                }
                None => emit_endless_loop(*body, builder, loops),
            }
        }
        ControlFlowSpec::DoWhile { body, condition } => {
            emit_do_while(*body, condition, builder, loops);
        }
        ControlFlowSpec::Break => {
            if let Some(context) = loops.last_mut() {
                context.break_sources.extend(builder.take_frontier());
            }
        }
        ControlFlowSpec::Continue => {
            if let Some(context) = loops.last_mut() {
                context.continue_sources.extend(builder.take_frontier());
            }
        }
        ControlFlowSpec::Try {
            body,
            catch,
            finally,
        } => emit_try(
            *body,
            catch.map(|boxed| *boxed),
            finally.map(|boxed| *boxed),
            builder,
            loops,
        ),
    }
}

fn emit_if<T>(
    condition: T,
    then_arm: ControlFlowSpec<T>,
    else_arm: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let cond_id = builder.push_block(condition);
    builder.set_frontier([cond_id]);
    emit_spec(then_arm, builder, loops);
    let mut join_sources = builder.take_frontier();
    match else_arm {
        Some(arm) => {
            builder.set_frontier([cond_id]);
            emit_spec(arm, builder, loops);
            join_sources.extend(builder.take_frontier());
        }
        None => join_sources.push(cond_id),
    }
    builder.set_frontier(join_sources);
}

fn emit_tested_loop<T>(
    condition: T,
    body: ControlFlowSpec<T>,
    step: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let header = builder.push_block(condition);
    loops.push(LoopContext::new());
    builder.set_frontier([header]);
    emit_spec(body, builder, loops);
    let mut tail_sources = builder.take_frontier();
    if let Some(post) = step {
        builder.set_frontier(tail_sources);
        emit_spec(post, builder, loops);
        tail_sources = builder.take_frontier();
    }
    let context = loops.pop().expect("loop context pushed above");
    for end in tail_sources {
        builder.add_edge(end, header);
    }
    for source in context.continue_sources {
        builder.add_edge(source, header);
    }
    let mut after = context.break_sources;
    after.push(header);
    builder.set_frontier(after);
}

fn emit_endless_loop<T>(
    body: ControlFlowSpec<T>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let entries: Vec<BlockId> = builder.frontier().to_vec();
    loops.push(LoopContext::new());
    emit_spec(body, builder, loops);
    let ends = builder.take_frontier();
    let context = loops.pop().expect("loop context pushed above");
    for end in ends {
        for &entry in &entries {
            builder.add_edge(end, entry);
        }
    }
    for source in context.continue_sources {
        for &entry in &entries {
            builder.add_edge(source, entry);
        }
    }
    builder.set_frontier(context.break_sources);
}

fn emit_do_while<T>(
    body: ControlFlowSpec<T>,
    condition: T,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    // The body's first created block is its single entry point; remember it
    // so the header's true edge can re-enter the body.
    let body_hint = builder.next_block_id();
    loops.push(LoopContext::new());
    emit_spec(body, builder, loops);
    let created_body = builder.next_block_id() != body_hint;
    let header = builder.push_block(condition);
    let context = loops.pop().expect("loop context pushed above");
    for source in context.continue_sources {
        builder.add_edge(source, header);
    }
    if created_body {
        builder.add_edge(header, body_hint);
    }
    let mut after = context.break_sources;
    after.push(header);
    builder.set_frontier(after);
}

fn emit_try<T>(
    body: ControlFlowSpec<T>,
    catch: Option<ControlFlowSpec<T>>,
    finally: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let exceptional_entries: Vec<BlockId> = builder.frontier().to_vec();
    emit_spec(body, builder, loops);
    let mut join_sources = builder.take_frontier();
    match catch {
        Some(handler) => {
            builder.set_frontier(exceptional_entries);
            emit_spec(handler, builder, loops);
            join_sources.extend(builder.take_frontier());
        }
        None => {
            if finally.is_some() {
                join_sources.extend(exceptional_entries);
            } else {
                // An unhandled exception escapes the function altogether.
                let exit = builder.exit();
                for source in exceptional_entries {
                    builder.add_edge(source, exit);
                }
            }
        }
    }
    builder.set_frontier(join_sources);
    if let Some(cleanup) = finally {
        emit_spec(cleanup, builder, loops);
    }
}

/// Traversal orientation of a dataflow solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Facts flow from the entry toward the exit.
    Forward,
    /// Facts flow from the exit toward the entry.
    Backward,
}

/// Per-block input and output facts of a solved dataflow problem, indexed by
/// [`BlockId::index`].
#[derive(Debug, Clone)]
pub struct DataflowResult<F> {
    /// Fact flowing into each block.
    pub in_facts: Vec<F>,
    /// Fact flowing out of each block.
    pub out_facts: Vec<F>,
}

impl<F> DataflowResult<F> {
    /// Returns the input fact of `block`.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not a valid id of the solved graph.
    #[must_use]
    pub fn in_fact(&self, block: BlockId) -> &F {
        &self.in_facts[block.index()]
    }

    /// Returns the output fact of `block`.
    ///
    /// # Panics
    ///
    /// Panics if `block` is not a valid id of the solved graph.
    #[must_use]
    pub fn out_fact(&self, block: BlockId) -> &F {
        &self.out_facts[block.index()]
    }
}

/// Solves a monotone framework over `cfg` with a worklist algorithm.
///
/// * `direction` selects forward or backward propagation.
/// * `boundary` is the fixed fact at the entry (forward) or exit (backward);
///   it is re-applied on every visit of the boundary block.
/// * `meet` combines the propagated facts of visited neighbours; supply a
///   union for may-analyses or an intersection for must-analyses.
/// * `stmt_transfer` applies one block's statement payload to a fact.
/// * `block_effect` applies the per-block gen/kill composition afterwards,
///   modelling effects that individual statements cannot express.
///
/// Blocks never reached from the boundary keep [`Default::default`]. The
/// solve terminates provided the caller's lattice has finite height and the
/// transfers are monotone — the standard obligation of the framework user.
#[must_use]
pub fn solve_dataflow<T, F, M, S, G>(
    cfg: &Cfg<T>,
    direction: Direction,
    boundary: &F,
    meet: M,
    stmt_transfer: S,
    block_effect: G,
) -> DataflowResult<F>
where
    F: Clone + PartialEq + Default,
    M: Fn(&F, &F) -> F,
    S: Fn(&F, &T) -> F,
    G: Fn(BlockId, &F) -> F,
{
    let len = cfg.node_count();
    let mut result = DataflowResult {
        in_facts: vec![F::default(); len],
        out_facts: vec![F::default(); len],
    };
    let mut visited = vec![false; len];
    let mut queued = vec![false; len];
    let root = match direction {
        Direction::Forward => cfg.entry(),
        Direction::Backward => cfg.exit(),
    };
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    worklist.push_back(root);
    queued[root.index()] = true;
    while let Some(block) = worklist.pop_front() {
        queued[block.index()] = false;
        let readers = match direction {
            Direction::Forward => cfg.predecessors(block),
            Direction::Backward => cfg.successors(block),
        };
        let side = if block == root {
            F::clone(boundary)
        } else {
            meet_neighbours(readers, direction, &result, &visited, &meet).unwrap_or_else(|| {
                match direction {
                    Direction::Forward => result.in_facts[block.index()].clone(),
                    Direction::Backward => result.out_facts[block.index()].clone(),
                }
            })
        };
        let transferred = stmt_transfer(&side, cfg.payload(block));
        let computed = block_effect(block, &transferred);
        let idx = block.index();
        let prior = match direction {
            Direction::Forward => result.out_facts[idx].clone(),
            Direction::Backward => result.in_facts[idx].clone(),
        };
        let changed = computed != prior;
        match direction {
            Direction::Forward => {
                result.in_facts[idx] = side;
                result.out_facts[idx] = computed;
            }
            Direction::Backward => {
                result.out_facts[idx] = side;
                result.in_facts[idx] = computed;
            }
        }
        let first_visit = !visited[idx];
        visited[idx] = true;
        if changed || first_visit {
            let spread = match direction {
                Direction::Forward => cfg.successors(block),
                Direction::Backward => cfg.predecessors(block),
            };
            for &next in spread {
                if !queued[next.index()] {
                    queued[next.index()] = true;
                    worklist.push_back(next);
                }
            }
        }
    }
    result
}

fn meet_neighbours<F, M>(
    neighbours: &[BlockId],
    direction: Direction,
    result: &DataflowResult<F>,
    visited: &[bool],
    meet: &M,
) -> Option<F>
where
    F: Clone,
    M: Fn(&F, &F) -> F,
{
    let mut accumulator: Option<F> = None;
    for &neighbour in neighbours {
        if !visited[neighbour.index()] {
            continue;
        }
        let fact = match direction {
            Direction::Forward => &result.out_facts[neighbour.index()],
            Direction::Backward => &result.in_facts[neighbour.index()],
        };
        accumulator = Some(match accumulator {
            None => fact.clone(),
            Some(current) => meet(&current, fact),
        });
    }
    accumulator
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

impl<D: Ord + Clone> ReachingFacts<D> {
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

    /// [`ReachingFacts::union`] shaped for [`solve_dataflow`]'s meet slot.
    #[must_use]
    pub fn meet_union(left: &Self, right: &Self) -> Self {
        left.union(right)
    }

    /// [`ReachingFacts::intersection`] shaped for [`solve_dataflow`]'s meet
    /// slot.
    #[must_use]
    pub fn meet_intersection(left: &Self, right: &Self) -> Self {
        left.intersection(right)
    }
}

impl<D: Ord + Clone> Default for ReachingFacts<D> {
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

impl<V: Ord + Clone> LivenessFacts<V> {
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

    /// [`LivenessFacts::union`] shaped for [`solve_dataflow`]'s meet slot.
    #[must_use]
    pub fn meet_union(left: &Self, right: &Self) -> Self {
        left.union(right)
    }

    /// [`LivenessFacts::intersection`] shaped for [`solve_dataflow`]'s meet
    /// slot.
    #[must_use]
    pub fn meet_intersection(left: &Self, right: &Self) -> Self {
        left.intersection(right)
    }
}

impl<V: Ord + Clone> Default for LivenessFacts<V> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BlockId, Cfg, CfgBuilder, ControlFlowSpec, Direction, LivenessFacts, ReachingFacts,
        build_from_blocks, solve_dataflow,
    };
    use std::collections::BTreeSet;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum St {
        Def(&'static str, u32),
        Use(&'static str),
        Nop,
    }

    use St::{Def, Nop, Use};
    type Rd = ReachingFacts<(&'static str, u32)>;

    fn rd(entries: &[(&'static str, u32)]) -> Rd {
        let mut facts = Rd::new();
        facts.extend(entries.iter().copied());
        facts
    }

    fn reaching_step(facts: &Rd, stmt: &St) -> Rd {
        let mut next = facts.clone();
        if let Def(var, site) = stmt {
            next.kill_where(|(name, _)| name == var);
            next.insert((var, *site));
        }
        next
    }

    type Lv = LivenessFacts<&'static str>;

    fn lv(vars: &[&'static str]) -> Lv {
        let mut facts = Lv::new();
        facts.extend_live(vars.iter().copied());
        facts
    }

    fn liveness_step(later: &Lv, stmt: &St) -> Lv {
        let mut earlier = later.clone();
        match stmt {
            Def(var, _) => {
                earlier.kill_var(var);
            }
            Use(var) => {
                earlier.use_var(*var);
            }
            Nop => {}
        }
        earlier
    }

    fn block_by_payload(cfg: &Cfg<St>, payload: &St) -> BlockId {
        cfg.blocks()
            .find(|block| cfg.payload(*block) == payload)
            .expect("payload present in test graph")
    }

    fn stmts(names: &[St]) -> ControlFlowSpec<St> {
        ControlFlowSpec::Seq(
            names
                .iter()
                .map(|s| ControlFlowSpec::Stmt(s.clone()))
                .collect(),
        )
    }

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
    #[should_panic(expected = "index out of bounds")]
    fn cfg_payload_panics_on_invalid_id() {
        let cfg: Cfg<St> = Cfg::new(Nop, Nop);
        let _ = cfg.payload(BlockId::new(42));
    }

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

    #[test]
    fn spec_seq_builds_linear_chain() {
        let cfg = build_from_blocks(stmts(&[Def("a", 0), Use("a"), Def("b", 0)]), Nop, Nop);
        assert_eq!(cfg.node_count(), 5);
        let mut cursor = cfg.entry();
        for payload in [Def("a", 0), Use("a"), Def("b", 0)] {
            let succ = cfg.successors(cursor);
            assert_eq!(succ.len(), 1);
            cursor = succ[0];
            assert_eq!(cfg.payload(cursor), &payload);
        }
        assert!(cfg.has_edge(cursor, cfg.exit()));
    }

    #[test]
    fn spec_if_without_else_joins_through_condition() {
        let cfg = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c"),
                then_arm: Box::new(ControlFlowSpec::Stmt(Def("x", 0))),
                else_arm: None,
            },
            Nop,
            Nop,
        );
        let cond = block_by_payload(&cfg, &Use("c"));
        let then_block = block_by_payload(&cfg, &Def("x", 0));
        assert!(cfg.has_edge(cfg.entry(), cond));
        assert!(cfg.has_edge(cond, then_block));
        assert!(cfg.has_edge(cond, cfg.exit()), "false path skips to join");
        assert!(cfg.has_edge(then_block, cfg.exit()));
    }

    #[test]
    fn spec_if_else_forms_true_diamond() {
        let cfg = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c"),
                then_arm: Box::new(ControlFlowSpec::Stmt(Def("x", 0))),
                else_arm: Some(Box::new(ControlFlowSpec::Stmt(Def("y", 0)))),
            },
            Nop,
            Nop,
        );
        let cond = block_by_payload(&cfg, &Use("c"));
        let then_block = block_by_payload(&cfg, &Def("x", 0));
        let else_block = block_by_payload(&cfg, &Def("y", 0));
        assert!(cfg.has_edge(cond, then_block));
        assert!(cfg.has_edge(cond, else_block));
        assert!(!cfg.has_edge(cond, cfg.exit()));
        assert!(cfg.has_edge(then_block, cfg.exit()));
        assert!(cfg.has_edge(else_block, cfg.exit()));
    }

    #[test]
    fn spec_while_has_header_body_and_back_edge() {
        let cfg = build_from_blocks(
            ControlFlowSpec::For {
                init: None,
                condition: Some(Use("c")),
                body: Box::new(stmts(&[Def("i", 0), Use("i")])),
                step: None,
            },
            Nop,
            Nop,
        );
        let header = block_by_payload(&cfg, &Use("c"));
        assert!(cfg.has_edge(cfg.entry(), header));
        assert!(cfg.has_edge(header, block_by_payload(&cfg, &Def("i", 0))));
        assert!(
            cfg.has_edge(block_by_payload(&cfg, &Use("i")), header),
            "body end loops back to the header"
        );
        assert!(cfg.has_edge(header, cfg.exit()));
        assert!(cfg.contains_cycle());
    }

    #[test]
    fn spec_do_while_runs_body_before_header() {
        let cfg = build_from_blocks(
            ControlFlowSpec::DoWhile {
                body: Box::new(ControlFlowSpec::Stmt(Def("i", 0))),
                condition: Use("c"),
            },
            Nop,
            Nop,
        );
        let body_block = block_by_payload(&cfg, &Def("i", 0));
        let header = block_by_payload(&cfg, &Use("c"));
        assert!(cfg.has_edge(cfg.entry(), body_block));
        assert!(cfg.has_edge(body_block, header));
        assert!(cfg.has_edge(header, body_block), "repeat edge");
        assert!(cfg.has_edge(header, cfg.exit()));
    }

    #[test]
    fn spec_endless_for_loops_back_and_honours_break() {
        let cfg = build_from_blocks(
            ControlFlowSpec::For {
                init: Some(Box::new(ControlFlowSpec::Stmt(Def("i", 0)))),
                condition: None,
                body: Box::new(ControlFlowSpec::Seq(vec![
                    ControlFlowSpec::Stmt(Use("i")),
                    ControlFlowSpec::If {
                        condition: Use("done"),
                        then_arm: Box::new(ControlFlowSpec::Break),
                        else_arm: None,
                    },
                ])),
                step: Some(Box::new(ControlFlowSpec::Stmt(Nop))),
            },
            Nop,
            Nop,
        );
        let init_block = block_by_payload(&cfg, &Def("i", 0));
        let body_use = block_by_payload(&cfg, &Use("i"));
        let guard = block_by_payload(&cfg, &Use("done"));
        assert!(cfg.has_edge(cfg.entry(), init_block));
        assert!(cfg.has_edge(init_block, body_use));
        assert!(
            cfg.has_edge(guard, init_block),
            "body end loops back to the body entry"
        );
        assert!(cfg.has_edge(guard, cfg.exit()), "break escapes the loop");
        assert!(cfg.contains_cycle());
    }

    #[test]
    fn spec_continue_returns_to_header_break_skips_merge() {
        let cfg = build_from_blocks(
            ControlFlowSpec::For {
                init: None,
                condition: Some(Use("c")),
                body: Box::new(ControlFlowSpec::Seq(vec![
                    ControlFlowSpec::If {
                        condition: Use("skip"),
                        then_arm: Box::new(ControlFlowSpec::Continue),
                        else_arm: None,
                    },
                    ControlFlowSpec::If {
                        condition: Use("stop"),
                        then_arm: Box::new(ControlFlowSpec::Break),
                        else_arm: None,
                    },
                    ControlFlowSpec::Stmt(Def("work", 0)),
                ])),
                step: None,
            },
            Nop,
            Nop,
        );
        let header = block_by_payload(&cfg, &Use("c"));
        let continue_guard = block_by_payload(&cfg, &Use("skip"));
        let break_guard = block_by_payload(&cfg, &Use("stop"));
        assert!(
            cfg.has_edge(continue_guard, header),
            "continue rewires the header"
        );
        assert!(
            cfg.has_edge(break_guard, cfg.exit()),
            "break bypasses merge"
        );
        let work = block_by_payload(&cfg, &Def("work", 0));
        assert!(cfg.has_edge(work, header), "fall-through body loops back");
    }

    #[test]
    fn spec_nested_loops_bind_innermost() {
        let cfg = build_from_blocks(
            ControlFlowSpec::For {
                init: None,
                condition: Some(Use("outer")),
                body: Box::new(ControlFlowSpec::For {
                    init: None,
                    condition: Some(Use("inner")),
                    body: Box::new(ControlFlowSpec::Break),
                    step: None,
                }),
                step: None,
            },
            Nop,
            Nop,
        );
        let outer_header = block_by_payload(&cfg, &Use("outer"));
        let inner_header = block_by_payload(&cfg, &Use("inner"));
        assert!(
            cfg.has_edge(inner_header, outer_header),
            "inner loop exit flows back into the outer header"
        );
        assert_eq!(
            cfg.predecessors(cfg.exit()),
            &[outer_header],
            "the inner break must not escape straight to the exit"
        );
    }

    #[test]
    fn spec_stray_break_is_a_no_op() {
        let cfg = build_from_blocks(
            ControlFlowSpec::Seq(vec![
                ControlFlowSpec::Break,
                ControlFlowSpec::Stmt(Def("x", 0)),
            ]),
            Nop,
            Nop,
        );
        let after = block_by_payload(&cfg, &Def("x", 0));
        assert!(cfg.has_edge(cfg.entry(), after), "control falls through");
        assert_eq!(cfg.edge_count(), 2);
    }

    #[test]
    fn spec_try_routes_normal_exceptional_and_finally_flow() {
        let cfg = build_from_blocks(
            ControlFlowSpec::Try {
                body: Box::new(ControlFlowSpec::Stmt(Def("r", 0))),
                catch: Some(Box::new(ControlFlowSpec::Stmt(Use("log")))),
                finally: Some(Box::new(ControlFlowSpec::Stmt(Use("cleanup")))),
            },
            Nop,
            Nop,
        );
        let body = block_by_payload(&cfg, &Def("r", 0));
        let handler = block_by_payload(&cfg, &Use("log"));
        let cleanup = block_by_payload(&cfg, &Use("cleanup"));
        assert!(
            cfg.has_edge(cfg.entry(), handler),
            "throw approximation enters the handler"
        );
        assert!(cfg.has_edge(body, cleanup), "normal path reaches finally");
        assert!(
            cfg.has_edge(handler, cleanup),
            "handler path reaches finally"
        );
        assert!(cfg.has_edge(cleanup, cfg.exit()));
    }

    #[test]
    fn spec_try_without_catch_routes_exception_to_finally() {
        let cfg = build_from_blocks(
            ControlFlowSpec::Try {
                body: Box::new(ControlFlowSpec::Stmt(Def("r", 0))),
                catch: None,
                finally: Some(Box::new(ControlFlowSpec::Stmt(Use("cleanup")))),
            },
            Nop,
            Nop,
        );
        let cleanup = block_by_payload(&cfg, &Use("cleanup"));
        assert!(cfg.has_edge(cfg.entry(), cleanup), "exceptional edge");
        assert!(cfg.has_edge(block_by_payload(&cfg, &Def("r", 0)), cleanup));

        let bare = build_from_blocks(
            ControlFlowSpec::Try {
                body: Box::new(ControlFlowSpec::Stmt(Def("r", 0))),
                catch: None,
                finally: None,
            },
            Nop,
            Nop,
        );
        assert_eq!(
            bare.edge_count(),
            3,
            "body falls to exit and the unhandled exception escapes via exit"
        );
    }

    #[test]
    fn diamond_reaching_definitions_meet_at_join() {
        let cfg = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c"),
                then_arm: Box::new(ControlFlowSpec::Stmt(Def("x", 7))),
                else_arm: Some(Box::new(ControlFlowSpec::Stmt(Def("y", 9)))),
            },
            Nop,
            Nop,
        );
        let result = solve_dataflow(
            &cfg,
            Direction::Forward,
            &Rd::new(),
            Rd::meet_union,
            reaching_step,
            |_block, facts| facts.clone(),
        );
        let join_in = result.in_fact(cfg.exit());
        assert!(join_in.contains(&("x", 7)));
        assert!(join_in.contains(&("y", 9)));
        assert_eq!(join_in.len(), 2);
    }

    #[test]
    fn reaching_kill_removes_superseded_definition() {
        let cfg = build_from_blocks(stmts(&[Def("x", 0), Use("c"), Def("x", 1)]), Nop, Nop);
        let result = solve_dataflow(
            &cfg,
            Direction::Forward,
            &Rd::new(),
            Rd::meet_union,
            reaching_step,
            |_block, facts| facts.clone(),
        );
        let exit_out = result.out_fact(cfg.exit());
        assert!(exit_out.contains(&("x", 1)));
        assert_eq!(
            exit_out.len(),
            1,
            "the redefinition killed the earlier site"
        );
    }

    #[test]
    fn liveness_converges_across_loop_fixpoint() {
        let cfg = build_from_blocks(
            ControlFlowSpec::Seq(vec![
                ControlFlowSpec::Stmt(Def("bound", 0)),
                ControlFlowSpec::For {
                    init: None,
                    condition: Some(Use("bound")),
                    body: Box::new(stmts(&[Use("acc"), Def("acc", 0)])),
                    step: None,
                },
                ControlFlowSpec::Stmt(Use("acc")),
            ]),
            Nop,
            Nop,
        );
        let result = solve_dataflow(
            &cfg,
            Direction::Backward,
            &Lv::new(),
            Lv::meet_union,
            liveness_step,
            |_block, facts| facts.clone(),
        );
        let header = block_by_payload(&cfg, &Use("bound"));
        assert_eq!(
            result.in_fact(header),
            &lv(&["acc", "bound"]),
            "fixpoint terminates with exactly the loop-carried live set"
        );
        assert_eq!(result.in_fact(cfg.exit()), &lv(&[]));
        assert!(result.out_fact(cfg.exit()).is_empty(), "boundary respected");
    }

    #[test]
    fn must_intersection_yields_definite_assignment() {
        let meet = |left: &BTreeSet<&'static str>, right: &BTreeSet<&'static str>| {
            left.intersection(right)
                .copied()
                .collect::<BTreeSet<&'static str>>()
        };
        let transfer = |facts: &BTreeSet<&'static str>, stmt: &St| {
            let mut next = facts.clone();
            if let Def(var, _) = stmt {
                next.insert(var);
            }
            next
        };
        let both_arms = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c"),
                then_arm: Box::new(ControlFlowSpec::Stmt(Def("x", 0))),
                else_arm: Some(Box::new(ControlFlowSpec::Stmt(Def("x", 1)))),
            },
            Nop,
            Nop,
        );
        let result = solve_dataflow(
            &both_arms,
            Direction::Forward,
            &BTreeSet::new(),
            meet,
            transfer,
            |_block, facts| facts.clone(),
        );
        assert!(result.in_fact(both_arms.exit()).contains(&"x"));

        let one_arm = build_from_blocks(
            ControlFlowSpec::If {
                condition: Use("c"),
                then_arm: Box::new(ControlFlowSpec::Stmt(Def("x", 0))),
                else_arm: None,
            },
            Nop,
            Nop,
        );
        let skipped = solve_dataflow(
            &one_arm,
            Direction::Forward,
            &BTreeSet::new(),
            meet,
            transfer,
            |_block, facts| facts.clone(),
        );
        assert!(
            !skipped.in_fact(one_arm.exit()).contains(&"x"),
            "skipping the arm leaves x possibly unassigned"
        );
    }

    #[test]
    fn unreachable_block_keeps_default_facts() {
        let mut builder = CfgBuilder::new(Nop, Nop);
        let middle = builder.push_block(Def("x", 0));
        builder.create_block(Def("dead", 0));
        builder.set_frontier([middle]);
        let cfg = builder.finish();
        let orphan = BlockId::new(3);
        let result = solve_dataflow(
            &cfg,
            Direction::Forward,
            &Rd::new(),
            Rd::meet_union,
            reaching_step,
            |_block, facts| facts.clone(),
        );
        assert!(result.in_fact(orphan).is_empty());
        assert!(result.out_fact(orphan).is_empty());
    }

    #[test]
    fn dataflow_result_accessors_match_arrays() {
        let cfg = build_from_blocks(ControlFlowSpec::Stmt(Def("x", 0)), Nop, Nop);
        let result = solve_dataflow(
            &cfg,
            Direction::Forward,
            &rd(&[("seed", 1)]),
            Rd::meet_union,
            reaching_step,
            |_block, facts| facts.clone(),
        );
        assert_eq!(result.in_fact(cfg.entry()), &rd(&[("seed", 1)]));
        assert_eq!(result.out_fact(cfg.entry()), result.in_fact(cfg.entry()));
    }

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
}
