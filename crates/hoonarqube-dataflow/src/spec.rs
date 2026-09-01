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
    /// A `None` condition models `for (;;)`; the loop-back targets the body
    /// entry and still runs `step` after each completed iteration.
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
    /// Terminates the current control-flow path, as with a function return.
    Return,
    /// Exception-handling approximation.
    ///
    /// Normal completion of `body` flows onward; edges are added from every
    /// emitted block in the try region to the catch handler (or the finally
    /// block when no handler exists) to approximate a throw anywhere in the
    /// body. This is conservative for may-analyses and weakens must-analyses,
    /// which is the intended trade-off of the approximation. Handler blocks
    /// likewise receive exceptional edges to `finally` or the function exit.
    /// A shared cleanup block cannot retain path-specific `break`/`continue`
    /// destinations, so adapters needing exact abrupt-jump/finally semantics
    /// must lower those constructs directly with [`CfgBuilder`].
    Try {
        /// Protected region.
        body: Box<Self>,
        /// Handler executed on the exceptional edge, if any.
        catch: Option<Box<Self>>,
        /// Executed after normal and modelled exceptional completion, if any.
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
    let mut actions = vec![EmitAction::Spec(spec)];
    while let Some(action) = actions.pop() {
        run_action(action, builder, loops, &mut actions);
    }
}

enum EmitAction<T> {
    Spec(ControlFlowSpec<T>),
    ReachableSpec(ControlFlowSpec<T>),
    StartFor {
        condition: Option<T>,
        body: ControlFlowSpec<T>,
        step: Option<ControlFlowSpec<T>>,
    },
    FinishIfThen {
        condition: BlockId,
        else_arm: Option<ControlFlowSpec<T>>,
    },
    FinishIfElse {
        then_sources: Vec<BlockId>,
    },
    FinishTestedBody {
        header: BlockId,
        step: Option<ControlFlowSpec<T>>,
    },
    FinishTestedStep {
        header: BlockId,
        step_hint: BlockId,
        body_continues: Vec<BlockId>,
    },
    FinishEndlessBody {
        body_hint: BlockId,
        step: Option<ControlFlowSpec<T>>,
    },
    FinishEndlessStep {
        body_entry: Option<BlockId>,
        step_hint: BlockId,
        body_continues: Vec<BlockId>,
    },
    FinishDoWhile {
        body_hint: BlockId,
        condition: T,
    },
    FinishTryBody {
        body_start: BlockId,
        catch: Option<ControlFlowSpec<T>>,
        finally: Option<ControlFlowSpec<T>>,
    },
    FinishTryCatch {
        body_sources: Vec<BlockId>,
        handler_start: BlockId,
        finally: Option<ControlFlowSpec<T>>,
    },
}

fn run_action<T>(
    action: EmitAction<T>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
    actions: &mut Vec<EmitAction<T>>,
) {
    match action {
        EmitAction::Spec(spec) => schedule_spec(spec, builder, loops, actions),
        EmitAction::ReachableSpec(spec) => {
            if !builder.frontier().is_empty() {
                schedule_spec(spec, builder, loops, actions);
            }
        }
        EmitAction::StartFor {
            condition,
            body,
            step,
        } => start_for(condition, body, step, builder, loops, actions),
        EmitAction::FinishIfThen {
            condition,
            else_arm,
        } => finish_if_then(condition, else_arm, builder, actions),
        EmitAction::FinishIfElse { then_sources } => {
            let mut join_sources = then_sources;
            join_sources.extend(builder.take_frontier());
            builder.set_valid_frontier(join_sources);
        }
        EmitAction::FinishTestedBody { header, step } => {
            finish_tested_body(header, step, builder, loops, actions);
        }
        EmitAction::FinishTestedStep {
            header,
            step_hint,
            body_continues,
        } => finish_tested_step(header, step_hint, body_continues, builder, loops),
        EmitAction::FinishEndlessBody { body_hint, step } => {
            finish_endless_body(body_hint, step, builder, loops, actions);
        }
        EmitAction::FinishEndlessStep {
            body_entry,
            step_hint,
            body_continues,
        } => finish_endless_step(body_entry, step_hint, body_continues, builder, loops),
        EmitAction::FinishDoWhile {
            body_hint,
            condition,
        } => finish_do_while(body_hint, condition, builder, loops),
        EmitAction::FinishTryBody {
            body_start,
            catch,
            finally,
        } => finish_try_body(body_start, catch, finally, builder, actions),
        EmitAction::FinishTryCatch {
            body_sources,
            handler_start,
            finally,
        } => finish_try_catch(body_sources, handler_start, finally, builder, actions),
    }
}

fn schedule_spec<T>(
    spec: ControlFlowSpec<T>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
    actions: &mut Vec<EmitAction<T>>,
) {
    match spec {
        ControlFlowSpec::Stmt(payload) => {
            builder.push_block(payload);
        }
        ControlFlowSpec::Seq(items) => {
            actions.extend(items.into_iter().rev().map(EmitAction::ReachableSpec));
        }
        ControlFlowSpec::If {
            condition,
            then_arm,
            else_arm,
        } => {
            let condition = builder.push_block(condition);
            builder.set_valid_frontier([condition]);
            actions.push(EmitAction::FinishIfThen {
                condition,
                else_arm: else_arm.map(|arm| *arm),
            });
            actions.push(EmitAction::Spec(*then_arm));
        }
        ControlFlowSpec::For {
            init,
            condition,
            body,
            step,
        } => {
            actions.push(EmitAction::StartFor {
                condition,
                body: *body,
                step: step.map(|post| *post),
            });
            if let Some(init) = init {
                actions.push(EmitAction::Spec(*init));
            }
        }
        ControlFlowSpec::DoWhile { body, condition } => {
            let body_hint = builder.next_block_id();
            loops.push(LoopContext::new());
            actions.push(EmitAction::FinishDoWhile {
                body_hint,
                condition,
            });
            actions.push(EmitAction::Spec(*body));
        }
        ControlFlowSpec::Break => record_loop_jump(builder, loops, true),
        ControlFlowSpec::Continue => record_loop_jump(builder, loops, false),
        ControlFlowSpec::Return => record_return(builder),
        ControlFlowSpec::Try {
            body,
            catch,
            finally,
        } => {
            actions.push(EmitAction::FinishTryBody {
                body_start: builder.next_block_id(),
                catch: catch.map(|handler| *handler),
                finally: finally.map(|cleanup| *cleanup),
            });
            actions.push(EmitAction::Spec(*body));
        }
    }
}

fn record_return<T>(builder: &mut CfgBuilder<T>) {
    let exit = builder.exit();
    for source in builder.take_frontier() {
        builder.add_edge(source, exit);
    }
}

fn record_loop_jump<T>(builder: &mut CfgBuilder<T>, loops: &mut [LoopContext], is_break: bool) {
    let sources = builder.take_frontier();
    let Some(context) = loops.last_mut() else {
        builder.set_valid_frontier(sources);
        return;
    };
    if is_break {
        context.break_sources.extend(sources);
    } else {
        context.continue_sources.extend(sources);
    }
}

fn finish_if_then<T>(
    condition: BlockId,
    else_arm: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    actions: &mut Vec<EmitAction<T>>,
) {
    let mut then_sources = builder.take_frontier();
    if let Some(else_arm) = else_arm {
        builder.set_valid_frontier([condition]);
        actions.push(EmitAction::FinishIfElse { then_sources });
        actions.push(EmitAction::Spec(else_arm));
    } else {
        then_sources.push(condition);
        builder.set_valid_frontier(then_sources);
    }
}

fn start_for<T>(
    condition: Option<T>,
    body: ControlFlowSpec<T>,
    step: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
    actions: &mut Vec<EmitAction<T>>,
) {
    if let Some(condition) = condition {
        let header = builder.push_block(condition);
        loops.push(LoopContext::new());
        builder.set_valid_frontier([header]);
        actions.push(EmitAction::FinishTestedBody { header, step });
    } else {
        let body_hint = builder.next_block_id();
        loops.push(LoopContext::new());
        actions.push(EmitAction::FinishEndlessBody { body_hint, step });
    }
    actions.push(EmitAction::Spec(body));
}

fn finish_tested_body<T>(
    header: BlockId,
    step: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
    actions: &mut Vec<EmitAction<T>>,
) {
    let mut tail_sources = builder.take_frontier();
    let body_continues = take_continue_sources(loops);
    if let Some(post) = step {
        let step_hint = builder.next_block_id();
        builder.set_valid_frontier(tail_sources);
        actions.push(EmitAction::FinishTestedStep {
            header,
            step_hint,
            body_continues,
        });
        actions.push(EmitAction::Spec(post));
        return;
    }
    tail_sources.extend(body_continues);
    for end in tail_sources {
        builder.add_edge(end, header);
    }
    finish_tested_loop(header, builder, loops);
}

fn finish_tested_step<T>(
    header: BlockId,
    step_hint: BlockId,
    body_continues: Vec<BlockId>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let step_entry = (builder.next_block_id() != step_hint).then_some(step_hint);
    for source in builder.take_frontier() {
        builder.add_edge(source, header);
    }
    for source in body_continues {
        builder.add_edge(source, step_entry.unwrap_or(header));
    }
    for source in take_continue_sources(loops) {
        builder.add_edge(source, header);
    }
    finish_tested_loop(header, builder, loops);
}

fn finish_tested_loop<T>(
    header: BlockId,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let context = loops.pop().expect("loop context pushed above");
    let mut after = context.break_sources;
    after.push(header);
    builder.set_valid_frontier(after);
}

fn finish_endless_body<T>(
    body_hint: BlockId,
    step: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
    actions: &mut Vec<EmitAction<T>>,
) {
    let body_entry = (builder.next_block_id() != body_hint).then_some(body_hint);
    let tail_sources = builder.take_frontier();
    let body_continues = take_continue_sources(loops);
    if let Some(step) = step {
        let step_hint = builder.next_block_id();
        builder.set_valid_frontier(tail_sources);
        actions.push(EmitAction::FinishEndlessStep {
            body_entry,
            step_hint,
            body_continues,
        });
        actions.push(EmitAction::Spec(step));
        return;
    }
    wire_loop_sources(builder, tail_sources, body_entry);
    wire_loop_sources(builder, body_continues, body_entry);
    finish_endless_loop(builder, loops);
}

fn finish_endless_step<T>(
    body_entry: Option<BlockId>,
    step_hint: BlockId,
    body_continues: Vec<BlockId>,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let step_entry = (builder.next_block_id() != step_hint).then_some(step_hint);
    let loop_target = body_entry.or(step_entry);
    let step_tails = builder.take_frontier();
    wire_loop_sources(builder, step_tails, loop_target);
    wire_loop_sources(builder, body_continues, step_entry.or(body_entry));
    let step_continues = take_continue_sources(loops);
    wire_loop_sources(builder, step_continues, loop_target);
    finish_endless_loop(builder, loops);
}

fn wire_loop_sources<T>(
    builder: &mut CfgBuilder<T>,
    sources: Vec<BlockId>,
    target: Option<BlockId>,
) {
    for source in sources {
        builder.add_edge(source, target.unwrap_or(source));
    }
}

fn finish_endless_loop<T>(builder: &mut CfgBuilder<T>, loops: &mut Vec<LoopContext>) {
    let context = loops.pop().expect("loop context pushed above");
    builder.set_valid_frontier(context.break_sources);
}

fn finish_do_while<T>(
    body_hint: BlockId,
    condition: T,
    builder: &mut CfgBuilder<T>,
    loops: &mut Vec<LoopContext>,
) {
    let created_body = builder.next_block_id() != body_hint;
    let header = builder.push_block(condition);
    let context = loops.pop().expect("loop context pushed above");
    for source in context.continue_sources {
        builder.add_edge(source, header);
    }
    builder.add_edge(header, if created_body { body_hint } else { header });
    let mut after = context.break_sources;
    after.push(header);
    builder.set_valid_frontier(after);
}

fn finish_try_body<T>(
    body_start: BlockId,
    catch: Option<ControlFlowSpec<T>>,
    finally: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    actions: &mut Vec<EmitAction<T>>,
) {
    let mut join_sources = builder.take_frontier();
    let exceptional_sources = (body_start.index()..builder.next_block_id().index())
        .map(|index| BlockId::new(u32::try_from(index).expect("block index fits u32")))
        .collect::<Vec<_>>();
    if let Some(handler) = catch {
        builder.set_valid_frontier(exceptional_sources);
        actions.push(EmitAction::FinishTryCatch {
            body_sources: join_sources,
            handler_start: builder.next_block_id(),
            finally,
        });
        actions.push(EmitAction::Spec(handler));
    } else {
        if finally.is_some() {
            join_sources.extend(exceptional_sources);
        } else {
            let exit = builder.exit();
            for source in exceptional_sources {
                builder.add_edge(source, exit);
            }
        }
        builder.set_valid_frontier(join_sources);
        if let Some(cleanup) = finally {
            actions.push(EmitAction::Spec(cleanup));
        }
    }
}

fn finish_try_catch<T>(
    mut body_sources: Vec<BlockId>,
    handler_start: BlockId,
    finally: Option<ControlFlowSpec<T>>,
    builder: &mut CfgBuilder<T>,
    actions: &mut Vec<EmitAction<T>>,
) {
    body_sources.extend(builder.take_frontier());
    let exceptional_handler_sources = (handler_start.index()..builder.next_block_id().index())
        .map(|index| BlockId::new(u32::try_from(index).expect("block index fits u32")));
    builder.set_valid_frontier(body_sources);
    if let Some(cleanup) = finally {
        let mut cleanup_sources = builder.take_frontier();
        cleanup_sources.extend(exceptional_handler_sources);
        builder.set_valid_frontier(cleanup_sources);
        actions.push(EmitAction::Spec(cleanup));
    } else {
        let exit = builder.exit();
        for source in exceptional_handler_sources {
            builder.add_edge(source, exit);
        }
    }
}

fn take_continue_sources(loops: &mut [LoopContext]) -> Vec<BlockId> {
    std::mem::take(
        &mut loops
            .last_mut()
            .expect("loop context pushed above")
            .continue_sources,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

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
    fn spec_return_terminates_only_the_current_path() {
        let cfg = build_from_blocks(
            ControlFlowSpec::Seq(vec![
                ControlFlowSpec::Stmt(Def("x", 0)),
                ControlFlowSpec::Return,
                ControlFlowSpec::Stmt(Use("x")),
            ]),
            Nop,
            Nop,
        );
        let definition = block_by_payload(&cfg, &Def("x", 0));
        assert!(cfg.has_edge(definition, cfg.exit()));
        assert!(
            !cfg.blocks().any(|block| cfg.payload(block) == &Use("x")),
            "statements after an unconditional return are not emitted",
        );
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
        let step = cfg
            .blocks()
            .find(|&block| {
                block != cfg.entry() && block != cfg.exit() && cfg.payload(block) == &Nop
            })
            .expect("step block present");
        assert!(cfg.has_edge(cfg.entry(), init_block));
        assert!(cfg.has_edge(init_block, body_use));
        assert!(
            cfg.has_edge(guard, step),
            "normal body completion runs the step"
        );
        assert!(
            cfg.has_edge(step, body_use),
            "the step loops to the body entry"
        );
        assert!(
            !cfg.has_edge(step, init_block),
            "the initializer must run exactly once"
        );
        assert!(cfg.has_edge(guard, cfg.exit()), "break escapes the loop");
        assert!(cfg.contains_cycle());
    }

    #[test]
    fn spec_endless_for_continue_runs_step() {
        let cfg = build_from_blocks(
            ControlFlowSpec::For {
                init: None,
                condition: None,
                body: Box::new(ControlFlowSpec::If {
                    condition: Use("skip"),
                    then_arm: Box::new(ControlFlowSpec::Continue),
                    else_arm: Some(Box::new(ControlFlowSpec::Stmt(Use("work")))),
                }),
                step: Some(Box::new(ControlFlowSpec::Stmt(Def("i", 1)))),
            },
            Nop,
            Nop,
        );
        let guard = block_by_payload(&cfg, &Use("skip"));
        let work = block_by_payload(&cfg, &Use("work"));
        let step = block_by_payload(&cfg, &Def("i", 1));
        assert!(cfg.has_edge(guard, step), "continue enters the step");
        assert!(
            cfg.has_edge(work, step),
            "normal completion enters the step"
        );
        assert!(cfg.has_edge(step, guard), "step starts the next iteration");
        assert!(!cfg.reachable_from_entry().contains(&cfg.exit()));
    }

    #[test]
    fn spec_empty_do_while_retains_repeat_edge() {
        let cfg = build_from_blocks(
            ControlFlowSpec::DoWhile {
                body: Box::new(ControlFlowSpec::Seq(Vec::new())),
                condition: Use("c"),
            },
            Nop,
            Nop,
        );
        let condition = block_by_payload(&cfg, &Use("c"));
        assert!(cfg.has_edge(cfg.entry(), condition));
        assert!(cfg.has_edge(condition, condition));
        assert!(cfg.has_edge(condition, cfg.exit()));
        assert_eq!(cfg.blocks_on_cycles(), BTreeSet::from([condition]));
    }

    #[test]
    fn deeply_nested_specs_lower_without_using_call_stack() {
        const DEPTH: usize = 20_000;
        let mut spec = ControlFlowSpec::Stmt(Nop);
        for _ in 0..DEPTH {
            spec = ControlFlowSpec::If {
                condition: Nop,
                then_arm: Box::new(spec),
                else_arm: None,
            };
        }
        let cfg = build_from_blocks(spec, Nop, Nop);
        assert_eq!(cfg.node_count(), DEPTH + 3);
        assert_eq!(cfg.reachable_from_entry().len(), cfg.node_count());
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
            cfg.has_edge(body, handler),
            "a throw from the protected block enters the handler"
        );
        assert!(!cfg.has_edge(cfg.entry(), handler));
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
                body: Box::new(stmts(&[Def("r", 0), Use("r")])),
                catch: None,
                finally: Some(Box::new(ControlFlowSpec::Stmt(Use("cleanup")))),
            },
            Nop,
            Nop,
        );
        let cleanup = block_by_payload(&cfg, &Use("cleanup"));
        assert!(cfg.has_edge(block_by_payload(&cfg, &Def("r", 0)), cleanup));
        assert!(cfg.has_edge(block_by_payload(&cfg, &Use("r")), cleanup));
        assert!(
            !cfg.has_edge(cfg.entry(), cleanup),
            "only protected blocks may throw"
        );

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
            2,
            "normal and exceptional completion share the same exit edge"
        );
    }

    #[test]
    fn spec_try_models_exceptions_from_each_catch_block() {
        let cfg = build_from_blocks(
            ControlFlowSpec::Try {
                body: Box::new(ControlFlowSpec::Stmt(Def("r", 0))),
                catch: Some(Box::new(stmts(&[Use("log"), Use("recover")]))),
                finally: None,
            },
            Nop,
            Nop,
        );
        let body = block_by_payload(&cfg, &Def("r", 0));
        let log = block_by_payload(&cfg, &Use("log"));
        let recover = block_by_payload(&cfg, &Use("recover"));
        assert!(cfg.has_edge(body, log));
        assert!(cfg.has_edge(log, recover));
        assert!(cfg.has_edge(log, cfg.exit()), "catch may throw early");
        assert!(cfg.has_edge(recover, cfg.exit()));
    }
}
