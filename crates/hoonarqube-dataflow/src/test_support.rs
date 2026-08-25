//! Shared fixtures for the dataflow unit tests: a small statement payload
//! enum plus helpers used by the per-module test suites.

use crate::{BlockId, Cfg, ControlFlowSpec, LivenessFacts, ReachingFacts};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum St {
    Def(&'static str, u32),
    Use(&'static str),
    Nop,
}

pub use St::{Def, Nop, Use};
pub type Rd = ReachingFacts<(&'static str, u32)>;

pub fn rd(entries: &[(&'static str, u32)]) -> Rd {
    let mut facts = Rd::new();
    facts.extend(entries.iter().copied());
    facts
}

pub fn reaching_step(facts: &Rd, stmt: &St) -> Rd {
    let mut next = facts.clone();
    if let Def(var, site) = stmt {
        next.kill_where(|(name, _)| name == var);
        next.insert((var, *site));
    }
    next
}

pub type Lv = LivenessFacts<&'static str>;

pub fn lv(vars: &[&'static str]) -> Lv {
    let mut facts = Lv::new();
    facts.extend_live(vars.iter().copied());
    facts
}

pub fn liveness_step(later: &Lv, stmt: &St) -> Lv {
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

pub fn block_by_payload(cfg: &Cfg<St>, payload: &St) -> BlockId {
    cfg.blocks()
        .find(|block| cfg.payload(*block) == payload)
        .expect("payload present in test graph")
}

pub fn stmts(names: &[St]) -> ControlFlowSpec<St> {
    ControlFlowSpec::Seq(
        names
            .iter()
            .map(|s| ControlFlowSpec::Stmt(s.clone()))
            .collect(),
    )
}
