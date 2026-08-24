// Family 'tier_c' (generated).
pub(crate) mod s3402_string_addition;
pub(crate) mod s3403_dissimilar_strict_equality;
pub(crate) mod s3579_array_string_index;
pub(crate) mod s3699_void_function_results;
pub(crate) mod s3757_nan_parse;
pub(crate) mod s3758_relational_composite_operand;
pub(crate) mod s3760_arithmetic_non_number;
pub(crate) mod s3782_string_expecting_builtin;
pub(crate) mod s3785_in_with_primitive;
pub(crate) mod s4123_awaited_value;
pub(crate) mod s6523_mixed_optional_chains;
pub(crate) mod s6551_missing_to_string;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
