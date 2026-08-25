//! Structured-control-flow lowering: [`ControlFlowSpec`] descriptions in,
//! [`Cfg`] graphs out.

use crate::builder::CfgBuilder;
use crate::cfg::{BlockId, Cfg};

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
    // Capture the step's entry block before emitting it, so `continue` can be
    // routed through the step (C-family semantics: the step runs after each
    // iteration, including one ended by `continue`).
    let step_hint = step.as_ref().map(|_| builder.next_block_id());
    if let Some(post) = step {
        builder.set_frontier(tail_sources);
        emit_spec(post, builder, loops);
        tail_sources = builder.take_frontier();
    }
    let context = loops.pop().expect("loop context pushed above");
    for end in tail_sources {
        builder.add_edge(end, header);
    }
    // A step that emitted no blocks (e.g. an empty `Seq`) falls back to the
    // header, preserving the plain `while`-shape lowering.
    let continue_target = match step_hint {
        Some(entry) if builder.next_block_id() != entry => entry,
        _ => header,
    };
    for source in context.continue_sources {
        builder.add_edge(source, continue_target);
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_support::{Def, Nop, Use, block_by_payload, stmts};

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
    fn spec_continue_runs_step_first() {
        let cfg = build_from_blocks(
            ControlFlowSpec::For {
                init: None,
                condition: Some(Use("c")),
                body: Box::new(ControlFlowSpec::If {
                    condition: Use("skip"),
                    then_arm: Box::new(ControlFlowSpec::Continue),
                    else_arm: None,
                }),
                step: Some(Box::new(ControlFlowSpec::Stmt(Def("i", 0)))),
            },
            Nop,
            Nop,
        );
        let continue_guard = block_by_payload(&cfg, &Use("skip"));
        let step_block = block_by_payload(&cfg, &Def("i", 0));
        let header = block_by_payload(&cfg, &Use("c"));
        assert!(
            cfg.has_edge(continue_guard, step_block),
            "continue must run the step before re-testing"
        );
        assert!(
            !cfg.has_edge(continue_guard, header),
            "continue must not bypass the step"
        );
        assert!(
            cfg.has_edge(step_block, header),
            "the step flows back into the header"
        );
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
}
