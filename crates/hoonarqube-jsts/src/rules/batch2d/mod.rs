// Family 'batch2d' (generated).
pub(crate) mod collectors;
pub(crate) mod s1067_condition_operators;
pub(crate) mod s1534_emit_duplicate_key;
pub(crate) mod s1536_s1536_formal_parameters;
pub(crate) mod s1541_s3776_report_complexity;
pub(crate) mod s3358_s3358_conditional_expression;
pub(crate) mod s3498_s3499_s3498_s3499_object_expression;
pub(crate) mod s3512_es_idioms;
pub(crate) mod s3513_s3513_identifier_reference;
pub(crate) mod s3514_scan_swap_triples;
pub(crate) mod s3523_s3523_new_expression;
pub(crate) mod s3796_s3796_call_expression;
pub(crate) mod s3801_mixed_returns;
pub(crate) mod s3854_s6635_constructor;
pub(crate) mod s3972_keyword_line;
pub(crate) mod s3973_unbraced_indent;
pub(crate) mod s4158_s4158_member_expression;
pub(crate) mod s4275_accessor;
pub(crate) mod s4619_s4619_binary_expression;
pub(crate) mod s4634_s4634_new_expression;
pub(crate) mod s4822_s4822_try_statement;
pub(crate) mod s6582_s6582_logical_expression;
pub(crate) mod s6594_s6594_call_expression;
pub(crate) mod s6671_s6671_call_expression;
pub(crate) mod s6861_s6861_export_declaration;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
