//! In-file usage heuristics (Tier A10).
//! A10 — in-file usage heuristics

pub(crate) mod magic_numbers;
mod support;
pub(crate) mod uninvoked_events;
pub(crate) mod unused_locals;
pub(crate) mod unused_method_parameters;
pub(crate) mod unused_private_members;
pub(crate) mod unused_usings;
mod walker;

pub(crate) use support::mentions_identifier_outside_parameter_list;
pub(crate) use walker::usage_heuristic_issues;
