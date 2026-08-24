use super::assembly_annotations::check as check_assembly_annotations;
use super::attribute_classes_constrained::check as check_attribute_classes_constrained;
use super::custom_event_handler_delegates::check as check_custom_event_handler_delegates;
use super::default_field_initializers::check as check_default_field_initializers;
use super::event_delegate_return_types::check as check_event_delegate_return_types;
use super::event_payload_types::check as check_event_payload_types;
use super::extension_methods_on_object::check as check_extension_methods_on_object;
use super::flags_enums_used_bitwise::check as check_flags_enums_used_bitwise;
use super::flags_members_explicit_values::check as check_flags_members_explicit_values;
use super::flags_zero_member_named_none::check as check_flags_zero_member_named_none;
use super::partial_methods_implemented::check as check_partial_methods_implemented;
use super::redundant_constructors::check as check_redundant_constructors;
use super::reserved_enum_members::check as check_reserved_enum_members;
use super::static_fields_in_generic_types::check as check_static_fields_in_generic_types;
use super::static_fields_initialized_inline::check as check_static_fields_initialized_inline;
use super::static_fields_updated_in_constructors::check as check_static_fields_updated_in_constructors;
use super::static_readonly_literals::check as check_static_readonly_literals;
use super::thread_static_initializers::check as check_thread_static_initializers;
use super::thread_static_needs_static::check as check_thread_static_needs_static;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-A11 declaration contract issue.
pub(crate) fn declaration_contract_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_partial_methods_implemented(root, source, language));
    issues.extend(check_redundant_constructors(root, source, language));
    issues.extend(check_default_field_initializers(root, source, language));
    issues.extend(check_static_fields_initialized_inline(
        root, source, language,
    ));
    issues.extend(check_static_readonly_literals(root, source, language));
    issues.extend(check_static_fields_updated_in_constructors(
        root, source, language,
    ));
    issues.extend(check_thread_static_initializers(root, source, language));
    issues.extend(check_thread_static_needs_static(root, source, language));
    issues.extend(check_static_fields_in_generic_types(root, source, language));
    issues.extend(check_event_delegate_return_types(root, source, language));
    issues.extend(check_custom_event_handler_delegates(root, source, language));
    issues.extend(check_attribute_classes_constrained(root, source, language));
    issues.extend(check_extension_methods_on_object(root, source, language));
    issues.extend(check_event_payload_types(root, source, language));
    issues.extend(check_assembly_annotations(root, source, language));
    issues.extend(check_reserved_enum_members(root, source, language));
    issues.extend(check_flags_enums_used_bitwise(root, source, language));
    issues.extend(check_flags_members_explicit_values(root, source, language));
    issues.extend(check_flags_zero_member_named_none(root, source, language));
    issues
}
