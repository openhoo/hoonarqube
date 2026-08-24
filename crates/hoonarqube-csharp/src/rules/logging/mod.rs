//! Logging family: templates, placeholders, loggers (Tier A14).
//! A14 — logging family (templates, placeholders, loggers)

pub(crate) mod catch_logging_passes_exception;
pub(crate) mod constant_log_templates;
pub(crate) mod create_logger_types;
pub(crate) mod ilogger_generics;
pub(crate) mod log_call_counts;
pub(crate) mod log_placeholder_casing;
pub(crate) mod log_placeholder_order;
pub(crate) mod log_template_syntax;
pub(crate) mod log_unique_placeholders;
pub(crate) mod logger_field_modifiers;
mod support;
pub(crate) mod trace_write_line_if_switches;
pub(crate) mod trace_writes;
mod walker;

pub(crate) use support::field_declarator_names;
pub(crate) use support::logging_calls;
pub(crate) use support::template_placeholders;
pub(crate) use walker::logging_issues;
