use super::assignments_in_expressions::check as check_assignments_in_expressions;
use super::constant_returning_methods::check as check_constant_returning_methods;
use super::doubled_prefix_operators::check as check_doubled_prefix_operators;
use super::dropped_objects::check as check_dropped_objects;
use super::duplicate_sibling_methods::check as check_duplicate_sibling_methods;
use super::duplicate_switch_sections::check as check_duplicate_switch_sections;
use super::embedded_increments::check as check_embedded_increments;
use super::float_equality::check as check_float_equality;
use super::gettype_typeof_comparisons::check as check_gettype_typeof_comparisons;
use super::identical_branches::check as check_identical_branches;
use super::identical_operands::check as check_identical_operands;
use super::indexof_positive_checks::check as check_indexof_positive_checks;
use super::inverted_boolean_checks::check as check_inverted_boolean_checks;
use super::local_shadowing::check as check_local_shadowing;
use super::modulus_equality::check as check_modulus_equality;
use super::nan_comparisons::check as check_nan_comparisons;
use super::negative_size_comparisons::check as check_negative_size_comparisons;
use super::nested_ternaries::check as check_nested_ternaries;
use super::not_implemented_throws::check as check_not_implemented_throws;
use super::null_check_with_is::check as check_null_check_with_is;
use super::null_or_empty_patterns::check as check_null_or_empty_patterns;
use super::redundant_anonymous_properties::check as check_redundant_anonymous_properties;
use super::redundant_boolean_comparisons::check as check_redundant_boolean_comparisons;
use super::redundant_jumps::check as check_redundant_jumps;
use super::redundant_member_initializers::check as check_redundant_member_initializers;
use super::repeated_adjacent_conditions::check as check_repeated_adjacent_conditions;
use super::repeated_chain_conditions::check as check_repeated_chain_conditions;
use super::self_assignments::check as check_self_assignments;
use super::self_relational_comparisons::check as check_self_relational_comparisons;
use super::shift_amounts::check as check_shift_amounts;
use super::simplifiable_conditions::check as check_simplifiable_conditions;
use super::this_is_checks::check as check_this_is_checks;
use super::unnecessary_bit_operations::check as check_unnecessary_bit_operations;
use super::unthrown_exceptions::check as check_unthrown_exceptions;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every issue contributed by this rule family.
pub(crate) fn expression_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_local_shadowing(root, source, language));
    issues.extend(check_assignments_in_expressions(root, source, language));
    issues.extend(check_embedded_increments(root, source, language));
    issues.extend(check_self_assignments(root, source, language));
    issues.extend(check_redundant_boolean_comparisons(root, source, language));
    issues.extend(check_simplifiable_conditions(root, source, language));
    issues.extend(check_inverted_boolean_checks(root, source, language));
    issues.extend(check_doubled_prefix_operators(root, source, language));
    issues.extend(check_nan_comparisons(root, source, language));
    issues.extend(check_float_equality(root, source, language));
    issues.extend(check_self_relational_comparisons(root, source, language));
    issues.extend(check_negative_size_comparisons(root, source, language));
    issues.extend(check_indexof_positive_checks(root, source, language));
    issues.extend(check_shift_amounts(root, source, language));
    issues.extend(check_unnecessary_bit_operations(root, source, language));
    issues.extend(check_modulus_equality(root, source, language));
    issues.extend(check_nested_ternaries(root, source, language));
    issues.extend(check_this_is_checks(root, source, language));
    issues.extend(check_null_check_with_is(root, source, language));
    issues.extend(check_gettype_typeof_comparisons(root, source, language));
    issues.extend(check_null_or_empty_patterns(root, source, language));
    issues.extend(constant_fold_issues(root, source, language));
    issues
}

/// Gathers every Tier-A6 constant-fold pattern issue.
fn constant_fold_issues(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_identical_operands(root, source, language));
    issues.extend(check_repeated_chain_conditions(root, source, language));
    issues.extend(check_identical_branches(root, source, language));
    issues.extend(check_duplicate_switch_sections(root, source, language));
    issues.extend(check_duplicate_sibling_methods(root, source, language));
    issues.extend(check_repeated_adjacent_conditions(root, source, language));
    issues.extend(check_redundant_anonymous_properties(root, source, language));
    issues.extend(check_redundant_member_initializers(root, source, language));
    issues.extend(check_constant_returning_methods(root, source, language));
    issues.extend(check_redundant_jumps(root, source, language));
    issues.extend(check_dropped_objects(root, source, language));
    issues.extend(check_unthrown_exceptions(root, source, language));
    issues.extend(check_not_implemented_throws(root, source, language));
    issues
}
