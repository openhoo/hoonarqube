// Family 'batch2d' (generated).
pub(crate) mod collectors;
mod s1067_condition_operators;
mod s1534_emit_duplicate_key;
mod s1536_s1536_formal_parameters;
mod s1541_s3776_report_complexity;
mod s3358_s3358_conditional_expression;
mod s3498_s3499_s3498_s3499_object_expression;
mod s3512_es_idioms;
mod s3513_s3513_identifier_reference;
mod s3514_scan_swap_triples;
mod s3523_s3523_new_expression;
mod s3796_s3796_call_expression;
mod s3801_mixed_returns;
mod s3854_s6635_constructor;
mod s3972_keyword_line;
mod s3973_unbraced_indent;
mod s4158_s4158_member_expression;
mod s4275_accessor;
mod s4619_s4619_binary_expression;
mod s4634_s4634_new_expression;
mod s4822_s4822_try_statement;
mod s6582_s6582_logical_expression;
mod s6594_s6594_call_expression;
mod s6671_s6671_call_expression;
mod s6861_s6861_export_declaration;
mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
