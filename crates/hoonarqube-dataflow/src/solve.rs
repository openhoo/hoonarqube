//! Monotone dataflow solving over a [`Cfg`]: [`solve_dataflow`] with a
//! forward or backward [`Direction`] and caller-supplied meet/transfers.

use crate::cfg::{BlockId, Cfg};
use std::collections::VecDeque;

/// Traversal orientation of a dataflow solve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Direction {
    /// Facts flow from the entry toward the exit.
    Forward,
    /// Facts flow from the exit toward the entry.
    Backward,
}

impl Direction {
    fn root<T>(self, cfg: &Cfg<T>) -> BlockId {
        match self {
            Self::Forward => cfg.entry(),
            Self::Backward => cfg.exit(),
        }
    }

    fn readers<T>(self, cfg: &Cfg<T>, block: BlockId) -> &[BlockId] {
        match self {
            Self::Forward => cfg.predecessors(block),
            Self::Backward => cfg.successors(block),
        }
    }

    fn spread<T>(self, cfg: &Cfg<T>, block: BlockId) -> &[BlockId] {
        match self {
            Self::Forward => cfg.successors(block),
            Self::Backward => cfg.predecessors(block),
        }
    }

    fn prior<F: Clone>(self, result: &DataflowResult<F>, block: BlockId) -> F {
        match self {
            Self::Forward => result.out_facts[block.index()].clone(),
            Self::Backward => result.in_facts[block.index()].clone(),
        }
    }

    fn retained_side<F: Clone>(self, result: &DataflowResult<F>, block: BlockId) -> F {
        match self {
            Self::Forward => result.in_facts[block.index()].clone(),
            Self::Backward => result.out_facts[block.index()].clone(),
        }
    }

    fn store<F>(self, result: &mut DataflowResult<F>, block: BlockId, side: F, computed: F) {
        match self {
            Self::Forward => {
                result.in_facts[block.index()] = side;
                result.out_facts[block.index()] = computed;
            }
            Self::Backward => {
                result.out_facts[block.index()] = side;
                result.in_facts[block.index()] = computed;
            }
        }
    }
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
    let root = direction.root(cfg);
    let mut worklist: VecDeque<BlockId> = VecDeque::new();
    worklist.push_back(root);
    queued[root.index()] = true;
    while let Some(block) = worklist.pop_front() {
        queued[block.index()] = false;
        let side = if block == root {
            F::clone(boundary)
        } else {
            meet_neighbours(
                direction.readers(cfg, block),
                direction,
                &result,
                &visited,
                &meet,
            )
            .unwrap_or_else(|| direction.retained_side(&result, block))
        };
        let transferred = stmt_transfer(&side, cfg.payload(block));
        let computed = block_effect(block, &transferred);
        let idx = block.index();
        let prior = direction.prior(&result, block);
        let changed = computed != prior;
        direction.store(&mut result, block, side, computed);
        let first_visit = !visited[idx];
        visited[idx] = true;
        if changed || first_visit {
            enqueue_unqueued(direction.spread(cfg, block), &mut queued, &mut worklist);
        }
    }
    result
}

fn enqueue_unqueued(spread: &[BlockId], queued: &mut [bool], worklist: &mut VecDeque<BlockId>) {
    for &next in spread {
        if !queued[next.index()] {
            queued[next.index()] = true;
            worklist.push_back(next);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeSet;

    use crate::test_support::{
        Def, Lv, Nop, Rd, St, Use, block_by_payload, liveness_step, lv, rd, reaching_step, stmts,
    };

    use crate::{CfgBuilder, ControlFlowSpec, build_from_blocks};

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
    fn forward_and_backward_solvers_match_synchronous_reference() {
        const BOUNDARY: u64 = 1_u64 << 63;
        for mask in 0..(1_u64 << 9) {
            let cfg = graph_from_mask(3, mask);
            for direction in [Direction::Forward, Direction::Backward] {
                let actual = solve_dataflow(
                    &cfg,
                    direction,
                    &BOUNDARY,
                    |left, right| left | right,
                    |facts, payload| facts | (1_u64 << payload),
                    |_block, facts| *facts,
                );
                let expected = synchronous_union_solve(&cfg, direction, BOUNDARY);
                assert_eq!(actual.in_facts, expected.in_facts);
                assert_eq!(actual.out_facts, expected.out_facts);
            }
        }
    }

    #[test]
    fn solver_is_stack_safe_on_deep_graphs() {
        const NODES: usize = 50_000;
        let mut cfg = Cfg::disconnected(0_u8, 1);
        for payload in 2..NODES {
            cfg.append_node(u8::try_from(payload % 64).expect("remainder fits u8"));
        }
        let mut previous = cfg.entry();
        for index in 2..NODES {
            let next = BlockId::new(u32::try_from(index).expect("index fits u32"));
            cfg.add_edge(previous, next);
            previous = next;
        }
        cfg.add_edge(previous, cfg.exit());

        let result = solve_dataflow(
            &cfg,
            Direction::Forward,
            &0_u64,
            |left, right| left | right,
            |facts, payload| facts | (1_u64 << payload),
            |_block, facts| *facts,
        );
        assert_eq!(result.out_fact(cfg.exit()).count_ones(), 64);
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

    fn synchronous_union_solve(
        cfg: &Cfg<u8>,
        direction: Direction,
        boundary: u64,
    ) -> DataflowResult<u64> {
        let mut result = DataflowResult {
            in_facts: vec![0; cfg.node_count()],
            out_facts: vec![0; cfg.node_count()],
        };
        let root = direction.root(cfg);
        let reachable = oriented_reachable(cfg, direction);
        loop {
            let previous = result.clone();
            for block in cfg.blocks().filter(|block| reachable[block.index()]) {
                let side = if block == root {
                    boundary
                } else {
                    direction
                        .readers(cfg, block)
                        .iter()
                        .fold(0, |facts, &reader| {
                            facts
                                | match direction {
                                    Direction::Forward => previous.out_facts[reader.index()],
                                    Direction::Backward => previous.in_facts[reader.index()],
                                }
                        })
                };
                let computed = side | (1_u64 << cfg.payload(block));
                direction.store(&mut result, block, side, computed);
            }
            if result.in_facts == previous.in_facts && result.out_facts == previous.out_facts {
                return result;
            }
        }
    }

    fn oriented_reachable(cfg: &Cfg<u8>, direction: Direction) -> Vec<bool> {
        let root = direction.root(cfg);
        let mut reachable = vec![false; cfg.node_count()];
        reachable[root.index()] = true;
        let mut stack = vec![root];
        while let Some(block) = stack.pop() {
            for &next in direction.spread(cfg, block) {
                if !reachable[next.index()] {
                    reachable[next.index()] = true;
                    stack.push(next);
                }
            }
        }
        reachable
    }
}
