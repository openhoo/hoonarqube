use super::catch_logging_passes_exception::check as check_catch_logging_passes_exception;
use super::constant_log_templates::check as check_constant_log_templates;
use super::create_logger_types::check as check_create_logger_types;
use super::ilogger_generics::check as check_ilogger_generics;
use super::log_call_counts::check as check_log_call_counts;
use super::log_placeholder_casing::check as check_log_placeholder_casing;
use super::log_placeholder_order::check as check_log_placeholder_order;
use super::log_template_syntax::check as check_log_template_syntax;
use super::log_unique_placeholders::check as check_log_unique_placeholders;
use super::logger_field_modifiers::check as check_logger_field_modifiers;
use super::trace_write_line_if_switches::check as check_trace_write_line_if_switches;
use super::trace_writes::check as check_trace_writes;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-A14 logging-family issue.
pub(crate) fn logging_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_trace_writes(root, source, language));
    issues.extend(check_trace_write_line_if_switches(root, source, language));
    issues.extend(check_log_call_counts(root, source, language));
    issues.extend(check_log_placeholder_order(root, source, language));
    issues.extend(check_log_template_syntax(root, source, language));
    issues.extend(check_log_unique_placeholders(root, source, language));
    issues.extend(check_log_placeholder_casing(root, source, language));
    issues.extend(check_catch_logging_passes_exception(root, source, language));
    issues.extend(check_constant_log_templates(root, source, language));
    issues.extend(check_logger_field_modifiers(
        root, source, language, options,
    ));
    issues.extend(check_create_logger_types(root, source, language));
    issues.extend(check_ilogger_generics(root, source, language));
    issues
}
