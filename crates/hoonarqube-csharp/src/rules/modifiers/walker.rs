use super::abstract_class_constructors::check as check_abstract_class_constructors;
use super::arglist_usage::check as check_arglist_usage;
use super::async_void_methods::check as check_async_void_methods;
use super::attribute_classes_sealed::check as check_attribute_classes_sealed;
use super::break_statements::check as check_break_statements;
use super::caller_information_parameters_last::check as check_caller_information_parameters_last;
use super::contextual_keyword_identifiers::check as check_contextual_keyword_identifiers;
use super::default_parameter_value_needs_optional::check as check_default_parameter_value_needs_optional;
use super::default_value_attribute_parameters::check as check_default_value_attribute_parameters;
use super::enum_underlying_types::check as check_enum_underlying_types;
use super::exception_visibility::check as check_exception_visibility;
use super::goto_statements::check as check_goto_statements;
use super::iequatable_classes_sealed::check as check_iequatable_classes_sealed;
use super::member_visibility_above_type::check as check_member_visibility_above_type;
use super::multidimensional_arrays::check as check_multidimensional_arrays;
use super::mutable_public_static_fields::check as check_mutable_public_static_fields;
use super::native_methods_wrapped::check as check_native_methods_wrapped;
use super::nested_generics_in_signatures::check as check_nested_generics_in_signatures;
use super::non_private_fields::check as check_non_private_fields;
use super::only_private_constructors::check as check_only_private_constructors;
use super::optional_attribute_on_ref_out_parameters::check as check_optional_attribute_on_ref_out_parameters;
use super::optional_parameters::check as check_optional_parameters;
use super::out_ref_parameters::check as check_out_ref_parameters;
use super::pinvoke_visibility::check as check_pinvoke_visibility;
use super::private_types_sealed::check as check_private_types_sealed;
use super::public_constants::check as check_public_constants;
use super::public_instance_fields::check as check_public_instance_fields;
use super::public_multidimensional_parameters::check as check_public_multidimensional_parameters;
use super::public_pointer_signatures::check as check_public_pointer_signatures;
use super::sealed_protected_members::check as check_sealed_protected_members;
use super::type_parameter_counts::check as check_type_parameter_counts;
use super::unsafe_code::check as check_unsafe_code;
use super::unused_type_parameters::check as check_unused_type_parameters;
use super::unused_type_parameters_in_parameters::check as check_unused_type_parameters_in_parameters;
use super::virtual_field_events::check as check_virtual_field_events;
use super::visible_static_fields::check as check_visible_static_fields;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every issue contributed by this rule family.
pub(crate) fn modifier_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_public_instance_fields(root, source, language));
    issues.extend(check_non_private_fields(root, source, language));
    issues.extend(check_visible_static_fields(root, source, language));
    issues.extend(check_public_constants(root, source, language));
    issues.extend(check_mutable_public_static_fields(root, source, language));
    issues.extend(check_sealed_protected_members(root, source, language));
    issues.extend(check_virtual_field_events(root, source, language));
    issues.extend(check_abstract_class_constructors(root, source, language));
    issues.extend(check_only_private_constructors(root, source, language));
    issues.extend(check_exception_visibility(root, source, language));
    issues.extend(check_out_ref_parameters(root, source, language));
    issues.extend(check_attribute_classes_sealed(root, source, language));
    issues.extend(check_iequatable_classes_sealed(root, source, language));
    issues.extend(check_private_types_sealed(root, source, language));
    issues.extend(check_member_visibility_above_type(root, source, language));
    issues.extend(check_optional_parameters(root, source, language));
    issues.extend(check_optional_attribute_on_ref_out_parameters(
        root, source, language,
    ));
    issues.extend(check_default_parameter_value_needs_optional(
        root, source, language,
    ));
    issues.extend(check_default_value_attribute_parameters(
        root, source, language,
    ));
    issues.extend(check_caller_information_parameters_last(
        root, source, language,
    ));
    issues.extend(check_pinvoke_visibility(root, source, language));
    issues.extend(check_native_methods_wrapped(root, source, language));
    issues.extend(check_public_pointer_signatures(root, source, language));
    issues.extend(check_multidimensional_arrays(root, source, language));
    issues.extend(check_public_multidimensional_parameters(
        root, source, language,
    ));
    issues.extend(check_enum_underlying_types(root, source, language));
    issues.extend(check_nested_generics_in_signatures(root, source, language));
    issues.extend(check_type_parameter_counts(root, source, language, options));
    issues.extend(check_unused_type_parameters_in_parameters(
        root, source, language,
    ));
    issues.extend(check_unused_type_parameters(root, source, language));
    issues.extend(check_async_void_methods(root, source, language));
    issues.extend(check_contextual_keyword_identifiers(root, source, language));
    issues.extend(check_goto_statements(root, source, language));
    issues.extend(check_break_statements(root, source, language));
    issues.extend(check_unsafe_code(root, source, language));
    issues.extend(check_arglist_usage(root, source, language));
    issues
}
