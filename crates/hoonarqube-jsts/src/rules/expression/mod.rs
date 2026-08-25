// Family 'expression' (generated).
pub(crate) mod collectors;
mod s1125_binary_operators;
mod s1313_string_literal_raw;
mod s1314_numeric_literal;
mod s1442_plain_calls;
pub(crate) mod s1528_constructor_calls;
mod s2424_assignment_rules;
mod s2692_index_of_comparisons;
mod s3003_relational_strings;
mod s3981_length_comparison;
mod s4125_typeof_literal;
mod s6644_redundant_ternary;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
