//! Generic intra-procedural control-flow and dataflow analysis for Hoonarqube
//! language crates.
//!
//! This crate is the reusable Tier-B engine: language adapters lower their ASTs
//! onto [`ControlFlowSpec`] (or drive [`CfgBuilder`] directly), then run classic
//! worklist dataflow frameworks over the resulting [`Cfg`] with their own
//! lattice type `F`. Nothing here knows about a concrete language, issue
//! reporting, or the frozen catalog — that is deliberately the callers' job.
//!
//! Status: the engine is not yet consumed by any analyzer crate — the
//! language analyzers still ship their own statement-level approximation
//! walkers. It is kept as a workspace member and reserved for future
//! Tier-B adoption.
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

mod builder;
mod cfg;
mod facts;
mod solve;
mod spec;

pub use builder::CfgBuilder;
pub use cfg::{BlockId, Cfg, Dominators};
pub use facts::{LivenessFacts, ReachingFacts};
pub use solve::{DataflowResult, Direction, solve_dataflow};
pub use spec::{ControlFlowSpec, build_from_blocks};

#[cfg(test)]
mod test_support;
