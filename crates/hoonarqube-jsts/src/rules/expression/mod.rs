// Family 'expression' (generated).
pub(crate) mod walker;
pub(crate) mod s6644_redundant_ternary;
pub(crate) mod s1125_binary_operators;
pub(crate) mod s2692_index_of_comparisons;
pub(crate) mod s3981_length_comparison;
pub(crate) mod s3003_relational_strings;
pub(crate) mod s4125_typeof_literal;
pub(crate) mod s2424_assignment_rules;
pub(crate) mod s1442_plain_calls;
pub(crate) mod s1528_constructor_calls;
pub(crate) mod s1313_string_literal_raw;
pub(crate) mod s1314_numeric_literal;

use crate::context::AnalysisContext;
use crate::Issue;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
