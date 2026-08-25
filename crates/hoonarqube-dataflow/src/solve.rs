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
}
