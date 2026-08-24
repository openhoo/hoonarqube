//! Rule families grouped thematically; children see siblings via `super::*`.

pub(crate) mod api_contracts;
pub(crate) mod api_patterns;
pub(crate) mod dataflow;
pub(crate) mod datetime_aspnet;
pub(crate) mod declaration_contracts;
pub(crate) mod expressions;
pub(crate) mod linq_api;
pub(crate) mod literals;
pub(crate) mod logging;
pub(crate) mod modifiers;
pub(crate) mod naming;
pub(crate) mod security;
pub(crate) mod structure;
pub(crate) mod text_scans;
pub(crate) mod tier_c;
pub(crate) mod tier_c_pending;
pub(crate) mod type_members;
pub(crate) mod usage;
pub(crate) mod usage_analysis;
