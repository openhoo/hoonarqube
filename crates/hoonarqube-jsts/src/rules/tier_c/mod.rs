// Family 'tier_c' (generated).
mod s3402_string_addition;
mod s3403_dissimilar_strict_equality;
mod s3579_array_string_index;
mod s3699_void_function_results;
mod s3757_nan_parse;
mod s3758_relational_composite_operand;
mod s3760_arithmetic_non_number;
mod s3782_string_expecting_builtin;
mod s3785_in_with_primitive;
mod s4123_awaited_value;
mod s6523_mixed_optional_chains;
mod s6551_missing_to_string;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
