use super::antiforgery_disabled::check as check_antiforgery_disabled;
use super::argument_exception_param_names::check as check_argument_exception_param_names;
use super::clear_text_protocols::check as check_clear_text_protocols;
use super::conflicting_transparency_attributes::check as check_conflicting_transparency_attributes;
use super::constructor_argument_names::check as check_constructor_argument_names;
use super::cryptographic_keys_robust::check as check_cryptographic_keys_robust;
use super::debugging_left_enabled::check as check_debugging_left_enabled;
use super::empty_guid_creations::check as check_empty_guid_creations;
use super::insecure_cipher_modes::check as check_insecure_cipher_modes;
use super::jwt_strong_algorithms::check as check_jwt_strong_algorithms;
use super::one_way_contracts_return_void::check as check_one_way_contracts_return_void;
use super::operation_contract_pairing::check as check_operation_contract_pairing;
use super::optional_fields_have_deserialization_hooks::check as check_optional_fields_have_deserialization_hooks;
use super::part_creation_policy_needs_export::check as check_part_creation_policy_needs_export;
use super::permissive_cors::check as check_permissive_cors;
use super::permissive_csp::check as check_permissive_csp;
use super::predictable_temp_files::check as check_predictable_temp_files;
use super::publicly_writable_temp_paths::check as check_publicly_writable_temp_paths;
use super::pure_methods_return_values::check as check_pure_methods_return_values;
use super::request_size_limits::check as check_request_size_limits;
use super::request_validation_disabled::check as check_request_validation_disabled;
use super::robust_ciphers_required::check as check_robust_ciphers_required;
use super::serialization_constructors_secured::check as check_serialization_constructors_secured;
use super::serialization_event_handler_shapes::check as check_serialization_event_handler_shapes;
use super::unbounded_archive_extraction::check as check_unbounded_archive_extraction;
use super::unrestricted_deserialization::check as check_unrestricted_deserialization;
use super::weak_hash_algorithms::check as check_weak_hash_algorithms;
use super::weak_ssl_protocols::check as check_weak_ssl_protocols;
use super::winforms_entry_points::check as check_winforms_entry_points;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-A12 security deny/require-list issue.
pub(crate) fn security_deny_list_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_operation_contract_pairing(root, source, language));
    issues.extend(check_one_way_contracts_return_void(root, source, language));
    issues.extend(check_pure_methods_return_values(root, source, language));
    issues.extend(check_winforms_entry_points(root, source, language));
    issues.extend(check_conflicting_transparency_attributes(
        root, source, language,
    ));
    issues.extend(check_serialization_constructors_secured(
        root, source, language,
    ));
    issues.extend(check_optional_fields_have_deserialization_hooks(
        root, source, language,
    ));
    issues.extend(check_serialization_event_handler_shapes(
        root, source, language,
    ));
    issues.extend(check_argument_exception_param_names(root, source, language));
    issues.extend(check_empty_guid_creations(root, source, language));
    issues.extend(check_constructor_argument_names(root, source, language));
    issues.extend(check_part_creation_policy_needs_export(
        root, source, language,
    ));
    issues.extend(check_weak_ssl_protocols(root, source, language));
    issues.extend(check_weak_hash_algorithms(root, source, language));
    issues.extend(check_insecure_cipher_modes(root, source, language));
    issues.extend(check_robust_ciphers_required(root, source, language));
    issues.extend(check_cryptographic_keys_robust(root, source, language));
    issues.extend(check_jwt_strong_algorithms(root, source, language));
    issues.extend(check_clear_text_protocols(root, source, language));
    issues.extend(check_publicly_writable_temp_paths(root, source, language));
    issues.extend(check_predictable_temp_files(root, source, language));
    issues.extend(check_debugging_left_enabled(root, source, language));
    issues.extend(check_request_validation_disabled(root, source, language));
    issues.extend(check_antiforgery_disabled(root, source, language));
    issues.extend(check_unrestricted_deserialization(root, source, language));
    issues.extend(check_unbounded_archive_extraction(root, source, language));
    issues.extend(check_permissive_cors(root, source, language));
    issues.extend(check_permissive_csp(root, source, language));
    issues.extend(check_request_size_limits(root, source, language));
    issues
}
