use crate::AnalyzerOptions;
use crate::engine::file_context::FileContext;
use crate::engine::rx::collect_regex_sites;
use crate::engine::rx::parse_regex;
use crate::engine::scope::build_symbol_table;
use crate::engine::scope::collect_file_facts;
use crate::rules::all_exports_exist::check_all_exports_exist;
use crate::rules::any_all_list_comprehension::check_any_all_list_comprehension;
use crate::rules::any_type_hints::check_any_type_hints;
use crate::rules::assertion_at_end_of_except::check_assertion_at_end_of_except;
use crate::rules::async_timeout_parameters::check_async_timeout_parameters;
use crate::rules::async_without_awaits::check_async_without_awaits;
use crate::rules::autograd_variable_usage::check_autograd_variable_usage;
use crate::rules::bare_generic_hints::check_bare_generic_hints;
use crate::rules::base_estimator_underscore_attributes::check_base_estimator_underscore_attributes;
use crate::rules::blocking_sleep_in_async::check_blocking_sleep_in_async;
use crate::rules::boolean_except_clauses::check_boolean_except_clauses;
use crate::rules::boundary_slice_comparisons::check_boundary_slice_comparisons;
use crate::rules::cancellation_scope_checkpoints::check_cancellation_scope_checkpoints;
use crate::rules::class_field_names::check_class_field_names;
use crate::rules::class_names::check_class_names;
use crate::rules::classmethod_parameter_names::check_classmethod_parameter_names;
use crate::rules::closure_captures_loop_variable::check_closure_captures_loop_variable;
use crate::rules::collapsible_ifs::check_collapsible_ifs;
use crate::rules::complexity::check_class_complexity;
use crate::rules::complexity::check_cognitive_complexity;
use crate::rules::complexity::check_file_complexity;
use crate::rules::complexity::check_function_complexity;
use crate::rules::confusing_type_checks::check_confusing_type_checks;
use crate::rules::confusing_walrus_placement::check_confusing_walrus_placement;
use crate::rules::constant_conditions::check_constant_conditions;
use crate::rules::constant_dict_comprehension_values::check_constant_dict_comprehension_values;
use crate::rules::constant_none_comparisons::check_constant_none_comparisons;
use crate::rules::constant_populated_dict_loop::check_constant_populated_dict_loop;
use crate::rules::control_flow_in_nurseries::check_control_flow_in_nurseries;
use crate::rules::cookie_flag::check_cookie_flag;
use crate::rules::copy_only_comprehensions::check_copy_only_comprehensions;
use crate::rules::dataframe_values_attribute::check_dataframe_values_attribute;
use crate::rules::dataloader_workers::check_dataloader_workers;
use crate::rules::datetime_component_ranges::check_datetime_component_ranges;
use crate::rules::dead_stores::check_dead_stores;
use crate::rules::debug_features::check_debug_features;
use crate::rules::defaultdict_keyword_factory::check_defaultdict_keyword_factory;
use crate::rules::deprecated_numpy_aliases::check_deprecated_numpy_aliases;
use crate::rules::deprecated_utc_helpers::check_deprecated_utc_helpers;
use crate::rules::disclosed_secret_keys::check_disclosed_secret_keys;
use crate::rules::django_model_str::check_django_model_str;
use crate::rules::django_string_field_null::check_django_string_field_null;
use crate::rules::doubled_prefix_operators::check_doubled_prefix_operators;
use crate::rules::dunder_all_strings::check_dunder_all_strings;
use crate::rules::duplicate_branches::check_duplicate_branches;
use crate::rules::duplicate_call_arguments::check_duplicate_call_arguments;
use crate::rules::duplicate_conditions::check_duplicate_conditions;
use crate::rules::duplicate_dict_keys::check_duplicate_dict_keys;
use crate::rules::duplicate_set_elements::check_duplicate_set_elements;
use crate::rules::duplicated_string_literals::check_duplicated_string_literals;
use crate::rules::einops_patterns::check_einops_patterns;
use crate::rules::empty_blocks::check_empty_blocks;
use crate::rules::empty_collection_constructors::check_empty_collection_constructors;
use crate::rules::empty_functions::check_empty_functions;
use crate::rules::estimator_hyperparameters::check_estimator_hyperparameters;
use crate::rules::except_star_groups::check_except_star_groups;
use crate::rules::exception_inheritance::check_exception_inheritance;
use crate::rules::exit_reraises_argument::check_exit_reraises_argument;
use crate::rules::exit_signatures::check_exit_signatures;
use crate::rules::explicit_test_skips::check_explicit_test_skips;
use crate::rules::f_string_nesting::check_f_string_nesting;
use crate::rules::float_equality_comparisons::check_float_equality_comparisons;
use crate::rules::fresh_object_identity_checks::check_fresh_object_identity_checks;
use crate::rules::function_lengths::check_function_lengths;
use crate::rules::function_parameter_counts::check_function_parameter_counts;
use crate::rules::function_return_counts::check_function_return_counts;
use crate::rules::gather_validate_indices::check_gather_validate_indices;
use crate::rules::generator_into_constructor::check_generator_into_constructor;
use crate::rules::generator_return_values::check_generator_return_values;
use crate::rules::identical_if_else_branches::check_identical_if_else_branches;
use crate::rules::identical_operands::check_identical_operands;
use crate::rules::identical_sibling_functions::check_identical_sibling_functions;
use crate::rules::imprecise_assertions::check_imprecise_assertions;
use crate::rules::incompatible_assert_literals::check_incompatible_assert_literals;
use crate::rules::inconsistent_returns::check_inconsistent_returns;
use crate::rules::infinite_recursion::check_infinite_recursion;
use crate::rules::init_return_values::check_init_return_values;
use crate::rules::input_in_async::check_input_in_async;
use crate::rules::insecure_temp_files::check_insecure_temp_files;
use crate::rules::instance_self_parameters::check_instance_self_parameters;
use crate::rules::invalid_weekmask::check_invalid_weekmask;
use crate::rules::invariant_returns::check_invariant_returns;
use crate::rules::inverted_boolean_checks::check_inverted_boolean_checks;
use crate::rules::isclose_zero_tolerance::check_isclose_zero_tolerance;
use crate::rules::items_only_keys_needed::check_items_only_keys_needed;
use crate::rules::json_response_safe_flag::check_json_response_safe_flag;
use crate::rules::jwt_secret_arguments::check_jwt_secret_arguments;
use crate::rules::keras_model_input_shape::check_keras_model_input_shape;
use crate::rules::known_value_comparisons::check_known_value_comparisons;
use crate::rules::lambda_assignments::check_lambda_assignments;
use crate::rules::lines_of_code::check_lines_of_code;
use crate::rules::list_wrapped_iteration::check_list_wrapped_iteration;
use crate::rules::literal_re_sub_patterns::check_literal_re_sub_patterns;
use crate::rules::long_dataframe_chains::check_long_dataframe_chains;
use crate::rules::long_sleeps::check_long_sleeps;
use crate::rules::loop_else_without_break::check_loop_else_without_break;
use crate::rules::manual_key_iteration::check_manual_key_iteration;
use crate::rules::map_lambda_calls::check_map_lambda_calls;
use crate::rules::meaningless_size_comparisons::check_meaningless_size_comparisons;
use crate::rules::member_name_matches_class::check_member_name_matches_class;
use crate::rules::method_and_function_names::check_method_and_function_names;
use crate::rules::methods_missing_parameters::check_methods_missing_parameters;
use crate::rules::missing_docstrings::check_missing_docstrings;
use crate::rules::missing_eval_after_load::check_missing_eval_after_load;
use crate::rules::missing_parameter_annotations::check_missing_parameter_annotations;
use crate::rules::missing_return_annotations::check_missing_return_annotations;
use crate::rules::modelform_meta_fields::check_modelform_meta_fields;
use crate::rules::mutable_default_mutation::check_mutable_default_mutation;
use crate::rules::named_group_references::check_named_group_references;
use crate::rules::named_steps_bypass::check_named_steps_bypass;
use crate::rules::nan_comparisons::check_nan_comparisons;
use crate::rules::needless_pass::check_needless_pass;
use crate::rules::nested_conditional_expressions::check_nested_conditional_expressions;
use crate::rules::nested_estimator_parameters::check_nested_estimator_parameters;
use crate::rules::nested_identical_constructors::check_nested_identical_constructors;
use crate::rules::nesting_depths::check_nesting_depths;
use crate::rules::nn_module_super_init::check_nn_module_super_init;
use crate::rules::no_effect_statements::check_no_effect_statements;
use crate::rules::notimplemented_raises::check_notimplemented_raises;
use crate::rules::np_array_generator::check_np_array_generator;
use crate::rules::old_style_classes::check_old_style_classes;
use crate::rules::only_reraise_handlers::check_only_reraise_handlers;
use crate::rules::open_modes::check_open_modes;
use crate::rules::overwritten_collection_items::check_overwritten_collection_items;
use crate::rules::overwritten_parameters::check_overwritten_parameters;
use crate::rules::pandas_inplace::check_pandas_inplace;
use crate::rules::parameter_and_local_names::check_parameter_and_local_names;
use crate::rules::pep695_generic_classes::check_pep695_generic_classes;
use crate::rules::percent_argument_counts::check_percent_argument_counts;
use crate::rules::percent_argument_types::check_percent_argument_types;
use crate::rules::pipeline_memory_missing::check_pipeline_memory_missing;
use crate::rules::property_accessor_arities::check_property_accessor_arities;
use crate::rules::pytz_timezone_usage::check_pytz_timezone_usage;
use crate::rules::pytz_tzinfo_kwarg::check_pytz_tzinfo_kwarg;
use crate::rules::raise_and_jump_flow::check_raise_and_jump_flow;
use crate::rules::random_state_usage::check_random_state_usage;
use crate::rules::read_without_dtype::check_read_without_dtype;
use crate::rules::reduction_axis_missing::check_reduction_axis_missing;
use crate::rules::redundant_jump_statements::check_redundant_jump_statements;
use crate::rules::redundant_parentheses::check_redundant_parentheses;
use crate::rules::redundant_typevars::check_redundant_typevars;
use crate::rules::render_locals::check_render_locals;
use crate::rules::replacement_references::check_replacement_references;
use crate::rules::route_decorator_ordering::check_route_decorator_ordering;
use crate::rules::s930_arity_mismatches::check_s930_arity_mismatches;
use crate::rules::s935_bare_returns::check_s935_bare_returns;
use crate::rules::s1523_dynamic_code_execution::check_s1523_dynamic_code_execution;
use crate::rules::s2053_static_salt::check_s2053_static_salt;
use crate::rules::s2077_sql_formatting::check_s2077_sql_formatting;
use crate::rules::s2115_empty_database_password::check_s2115_empty_database_password;
use crate::rules::s2201_ignored_pure_returns::check_s2201_ignored_pure_returns;
use crate::rules::s2245_prng_security_contexts::check_s2245_prng_security_contexts;
use crate::rules::s2257_custom_cryptography::check_s2257_custom_cryptography;
use crate::rules::s2638_override_contracts::check_s2638_override_contracts;
use crate::rules::s2755_xxe_parsers::check_s2755_xxe_parsers;
use crate::rules::s2876_iter_returns::check_s2876_iter_returns;
use crate::rules::s3329_static_cbc_iv::check_s3329_static_cbc_iv;
use crate::rules::s3403_identity_dissimilar_types::check_s3403_identity_dissimilar_types;
use crate::rules::s3699_used_void_outputs::check_s3699_used_void_outputs;
use crate::rules::s3752_route_methods::check_s3752_route_methods;
use crate::rules::s3862_iterating_non_iterables::check_s3862_iterating_non_iterables;
use crate::rules::s4423_weak_ssl_protocols::check_s4423_weak_ssl_protocols;
use crate::rules::s4426_weak_key_generation::check_s4426_weak_key_generation;
use crate::rules::s4433_ldap_unauthenticated::check_s4433_ldap_unauthenticated;
use crate::rules::s4502_csrf_disabled::check_s4502_csrf_disabled;
use crate::rules::s4721_shell_commands::check_s4721_shell_commands;
use crate::rules::s4787_encrypting_data::check_s4787_encrypting_data;
use crate::rules::s4792_logger_configuration::check_s4792_logger_configuration;
use crate::rules::s4823_command_line_arguments::check_s4823_command_line_arguments;
use crate::rules::s4828_signal_parameters::check_s4828_signal_parameters;
use crate::rules::s4829_standard_input::check_s4829_standard_input;
use crate::rules::s4830_certificate_verification::check_s4830_certificate_verification;
use crate::rules::s5122_cors_wildcard::check_s5122_cors_wildcard;
use crate::rules::s5247_autoescaping_disabled::check_s5247_autoescaping_disabled;
use crate::rules::s5300_sending_emails::check_s5300_sending_emails;
use crate::rules::s5344_plaintext_passwords::check_s5344_plaintext_passwords;
use crate::rules::s5439_global_autoescape_disabled::check_s5439_global_autoescape_disabled;
use crate::rules::s5443_public_temp_files::check_s5443_public_temp_files;
use crate::rules::s5527_hostname_verification::check_s5527_hostname_verification;
use crate::rules::s5542_weak_modes_and_paddings::check_s5542_weak_modes_and_paddings;
use crate::rules::s5547_weak_ciphers::check_s5547_weak_ciphers;
use crate::rules::s5607_incompatible_operator_pairs::check_s5607_incompatible_operator_pairs;
use crate::rules::s5632_raising_non_exceptions::check_s5632_raising_non_exceptions;
use crate::rules::s5642_membership_operands::check_s5642_membership_operands;
use crate::rules::s5644_literal_item_operations::check_s5644_literal_item_operations;
use crate::rules::s5655_argument_kind_mismatches::check_s5655_argument_kind_mismatches;
use crate::rules::s5659_jwt_signing::check_s5659_jwt_signing;
use crate::rules::s5707_raise_from_non_exception::check_s5707_raise_from_non_exception;
use crate::rules::s5708_excepting_non_exceptions::check_s5708_excepting_non_exceptions;
use crate::rules::s5713_parent_child_except_pairs::check_s5713_parent_child_except_pairs;
use crate::rules::s5756_non_callable_callees::check_s5756_non_callable_callees;
use crate::rules::s5795_identity_cached_types::check_s5795_identity_cached_types;
use crate::rules::s5886_return_hint_mismatches::check_s5886_return_hint_mismatches;
use crate::rules::s5890_annotated_assignment_kinds::check_s5890_annotated_assignment_kinds;
use crate::rules::s6245_s3_encryption_configuration::check_s6245_s3_encryption_configuration;
use crate::rules::s6252_s3_versioning::check_s6252_s3_versioning;
use crate::rules::s6265_s3_public_acl::check_s6265_s3_public_acl;
use crate::rules::s6270_public_resource_policy::check_s6270_public_resource_policy;
use crate::rules::s6275_ebs_encryption::check_s6275_ebs_encryption;
use crate::rules::s6281_s3_public_access_block::check_s6281_s3_public_access_block;
use crate::rules::s6302_all_privileges_policy::check_s6302_all_privileges_policy;
use crate::rules::s6303_rds_encryption::check_s6303_rds_encryption;
use crate::rules::s6304_all_resources_policy::check_s6304_all_resources_policy;
use crate::rules::s6308_opensearch_encryption::check_s6308_opensearch_encryption;
use crate::rules::s6317_wildcard_action_scope::check_s6317_wildcard_action_scope;
use crate::rules::s6319_sagemaker_encryption::check_s6319_sagemaker_encryption;
use crate::rules::s6321_admin_ports_open_world::check_s6321_admin_ports_open_world;
use crate::rules::s6327_sns_encryption::check_s6327_sns_encryption;
use crate::rules::s6329_public_network_access::check_s6329_public_network_access;
use crate::rules::s6330_sqs_encryption::check_s6330_sqs_encryption;
use crate::rules::s6332_efs_encryption::check_s6332_efs_encryption;
use crate::rules::s6333_api_gateway_authorization::check_s6333_api_gateway_authorization;
use crate::rules::s6377_weak_xml_signature_transforms::check_s6377_weak_xml_signature_transforms;
use crate::rules::s6463_unrestricted_egress::check_s6463_unrestricted_egress;
use crate::rules::s6662_unhashable_collection_literals::check_s6662_unhashable_collection_literals;
use crate::rules::s6663_sequence_index_type::check_s6663_sequence_index_type;
use crate::rules::s6785_graphql_depth_limiting::check_s6785_graphql_depth_limiting;
use crate::rules::self_assignment::check_self_assignment;
use crate::rules::shadowed_builtins::check_shadowed_builtins;
use crate::rules::similar_names_scope::check_similar_names_scope;
use crate::rules::single_arg_np_where::check_single_arg_np_where;
use crate::rules::single_iteration_loops::check_single_iteration_loops;
use crate::rules::single_task_nurseries::check_single_task_nurseries;
use crate::rules::skip_without_reason::check_skip_without_reason;
use crate::rules::sleep_in_async_loop::check_sleep_in_async_loop;
use crate::rules::sleep_zero_checkpoint::check_sleep_zero_checkpoint;
use crate::rules::sorted_reversed_shapes::check_sorted_reversed_shapes;
use crate::rules::special_method_arities::check_special_method_arities;
use crate::rules::static_candidates::check_static_candidates;
use crate::rules::strftime_hour_markers::check_strftime_hour_markers;
use crate::rules::swallowed_cancellations::check_swallowed_cancellations;
use crate::rules::swallowed_system_exit::check_swallowed_system_exit;
use crate::rules::sync_file_ops_in_async::check_sync_file_ops_in_async;
use crate::rules::sync_http_in_async::check_sync_http_in_async;
use crate::rules::sync_open_without_async_with::check_sync_open_without_async_with;
use crate::rules::sync_os_calls_in_async::check_sync_os_calls_in_async;
use crate::rules::sync_subprocess_in_async::check_sync_subprocess_in_async;
use crate::rules::tf_function_global_captures::check_tf_function_global_captures;
use crate::rules::tf_function_recursion::check_tf_function_recursion;
use crate::rules::tf_function_side_effects::check_tf_function_side_effects;
use crate::rules::tf_variable_creation::check_tf_variable_creation;
use crate::rules::to_datetime_ambiguity::check_to_datetime_ambiguity;
use crate::rules::torch_load_weights_only::check_torch_load_weights_only;
use crate::rules::trailing_comments::check_trailing_comments;
use crate::rules::tuple_assertions::check_tuple_assertions;
use crate::rules::type_equality_comparisons::check_type_equality_comparisons;
use crate::rules::typealias_assignments::check_typealias_assignments;
use crate::rules::typevar_annotated_functions::check_typevar_annotated_functions;
use crate::rules::typing_alias_hints::check_typing_alias_hints;
use crate::rules::typing_union_hints::check_typing_union_hints;
use crate::rules::unbounded_archive_extraction::check_unbounded_archive_extraction;
use crate::rules::unconditional_assertions::check_unconditional_assertions;
use crate::rules::undefined_names::check_undefined_names;
use crate::rules::unqualified_merge::check_unqualified_merge;
use crate::rules::unraised_exceptions::check_unraised_exceptions;
use crate::rules::unreachable_code::check_unreachable_code;
use crate::rules::unreachable_except_blocks::check_unreachable_except_blocks;
use crate::rules::unreachable_test_methods::check_unreachable_test_methods;
use crate::rules::unread_private_attributes::check_unread_private_attributes;
use crate::rules::unreferenced_asyncio_tasks::check_unreferenced_asyncio_tasks;
use crate::rules::unseeded_randomness::check_unseeded_randomness;
use crate::rules::unused_imports::check_unused_imports;
use crate::rules::unused_locals::check_unused_locals;
use crate::rules::unused_nested_definitions::check_unused_nested_definitions;
use crate::rules::unused_parameters::check_unused_parameters;
use crate::rules::unused_private_methods::check_unused_private_methods;
use crate::rules::unused_private_nested_classes::check_unused_private_nested_classes;
use crate::rules::use_before_definition::check_use_before_definition;
use crate::rules::weak_hashing::check_weak_hashing;
use crate::rules::wildcard_imports::check_wildcard_imports;
use crate::rules::world_writable_modes::check_world_writable_modes;
use crate::rules::wrapping_collection_constructors::check_wrapping_collection_constructors;
use crate::rules::yield_return_outside_function::check_yield_return_outside_function;
use crate::support::issue_at;
use crate::support::module_all_exports;
use crate::support::run_structural_regex_rules;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// ---------------------------------------------------------------------------
// Battery aggregation: every Tier-A entry #48–#110 in artifact order.
// ---------------------------------------------------------------------------

pub(crate) fn check_tier_a_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_needless_pass(parsed, index, source));
    issues.extend(check_dunder_all_strings(parsed, index, source));
    issues.extend(check_loop_else_without_break(index, source, file_ctx));
    issues.extend(check_nested_conditional_expressions(
        index, source, file_ctx,
    ));
    issues.extend(check_redundant_jump_statements(index, source, file_ctx));
    issues.extend(check_identical_if_else_branches(index, source, file_ctx));
    issues.extend(check_meaningless_size_comparisons(index, source, file_ctx));
    issues.extend(check_unreachable_code(parsed, index, source, file_ctx));
    issues.extend(check_identical_operands(parsed, index, source));
    issues.extend(check_duplicate_conditions(index, source, file_ctx));
    issues.extend(check_duplicate_branches(index, source, file_ctx));
    issues.extend(check_inverted_boolean_checks(index, source, file_ctx));
    issues.extend(check_self_assignment(index, source, file_ctx));
    issues.extend(check_wildcard_imports(index, source, file_ctx));
    issues.extend(check_doubled_prefix_operators(index, source, file_ctx));
    issues.extend(check_confusing_walrus_placement(index, source, file_ctx));
    issues.extend(check_constant_none_comparisons(index, source, file_ctx));
    issues.extend(check_fresh_object_identity_checks(index, source, file_ctx));
    issues.extend(check_tuple_assertions(index, source, file_ctx));
    issues.extend(check_type_equality_comparisons(index, source, file_ctx));
    issues.extend(check_lambda_assignments(index, source, file_ctx));
    issues.extend(check_boundary_slice_comparisons(index, source, file_ctx));
    issues.extend(check_float_equality_comparisons(index, source, file_ctx));
    issues.extend(check_no_effect_statements(parsed, index, source));
    issues.extend(check_exit_signatures(index, source, file_ctx));
    issues.extend(check_init_return_values(index, source, file_ctx));
    issues.extend(check_only_reraise_handlers(index, source, file_ctx));
    issues.extend(check_notimplemented_raises(index, source, file_ctx));
    issues.extend(check_methods_missing_parameters(parsed, index, source));
    issues.extend(check_instance_self_parameters(parsed, index, source));
    issues.extend(check_special_method_arities(index, source, file_ctx));
    issues.extend(check_property_accessor_arities(parsed, index, source));
    issues.extend(check_exception_inheritance(index, source, file_ctx));
    issues.extend(check_boolean_except_clauses(index, source, file_ctx));
    issues.extend(check_raise_and_jump_flow(parsed, index, source));
    issues.extend(check_exit_reraises_argument(index, source, file_ctx));
    issues.extend(check_swallowed_system_exit(index, source, file_ctx));
    issues.extend(check_closure_captures_loop_variable(
        index, source, file_ctx,
    ));
    issues.extend(check_classmethod_parameter_names(parsed, index, source));
    issues.extend(check_yield_return_outside_function(parsed, index, source));
    issues.extend(check_generator_return_values(index, source, file_ctx));
    issues.extend(check_unreachable_test_methods(index, source, file_ctx));
    issues.extend(check_assertion_at_end_of_except(index, source, file_ctx));
    issues.extend(check_duplicate_dict_keys(index, source, file_ctx));
    issues.extend(check_duplicate_set_elements(index, source, file_ctx));
    issues.extend(check_empty_collection_constructors(index, source, file_ctx));
    issues.extend(check_wrapping_collection_constructors(
        index, source, file_ctx,
    ));
    issues.extend(check_generator_into_constructor(index, source, file_ctx));
    issues.extend(check_copy_only_comprehensions(parsed, index, source));
    issues.extend(check_list_wrapped_iteration(index, source, file_ctx));
    issues.extend(check_map_lambda_calls(index, source, file_ctx));
    issues.extend(check_constant_dict_comprehension_values(
        index, source, file_ctx,
    ));
    issues.extend(check_defaultdict_keyword_factory(index, source, file_ctx));
    issues.extend(check_nested_identical_constructors(index, source, file_ctx));
    issues.extend(check_sorted_reversed_shapes(index, source, file_ctx));
    issues.extend(check_manual_key_iteration(index, source, file_ctx));
    issues.extend(check_constant_populated_dict_loop(index, source, file_ctx));
    issues.extend(check_items_only_keys_needed(index, source, file_ctx));
    issues
}

// ---------------------------------------------------------------------------
// Battery aggregation: every Tier-A entry #111–#193 in artifact order.
// ---------------------------------------------------------------------------

pub(crate) fn check_tier_a_battery_2(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    tier_a2_general_checks(parsed, index, source, options, file_ctx, &mut issues);
    tier_a2_web_async_typing_checks(parsed, index, source, options, file_ctx, &mut issues);
    tier_a2_data_science_checks(parsed, index, source, file_ctx, &mut issues);
    issues
}

/// Tier-A battery 2: builtin IO, hashing, regex, and numeric-shape checks.
fn tier_a2_general_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    issues.extend(check_duplicated_string_literals(
        parsed, index, source, options,
    ));
    issues.extend(check_open_modes(index, source, file_ctx));
    issues.extend(check_weak_hashing(index, source, file_ctx));
    issues.extend(check_insecure_temp_files(index, source, file_ctx));
    issues.extend(check_unbounded_archive_extraction(index, source, file_ctx));
    issues.extend(check_debug_features(index, source, file_ctx));
    issues.extend(check_literal_re_sub_patterns(index, source, file_ctx));
    issues.extend(check_world_writable_modes(index, source, file_ctx));
    issues.extend(check_deprecated_utc_helpers(index, source, file_ctx));
    issues.extend(check_nan_comparisons(parsed, index, source));
}

/// Tier-A battery 2: scientific-stack checks (numpy, pandas, scikit, torch).
fn tier_a2_data_science_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    issues.extend(check_isclose_zero_tolerance(index, source, file_ctx));
    issues.extend(check_single_arg_np_where(index, source, file_ctx));
    issues.extend(check_deprecated_numpy_aliases(parsed, index, source));
    issues.extend(check_random_state_usage(parsed, index, source));
    issues.extend(check_np_array_generator(index, source, file_ctx));
    issues.extend(check_pandas_inplace(index, source, file_ctx));
    issues.extend(check_unqualified_merge(index, source, file_ctx));
    issues.extend(check_read_without_dtype(index, source, file_ctx));
    issues.extend(check_dataframe_values_attribute(parsed, index, source));
    issues.extend(check_long_dataframe_chains(parsed, index, source, file_ctx));
    issues.extend(check_to_datetime_ambiguity(index, source, file_ctx));
    issues.extend(check_invalid_weekmask(index, source, file_ctx));
    issues.extend(check_datetime_component_ranges(index, source, file_ctx));
    issues.extend(check_strftime_hour_markers(index, source, file_ctx));
    issues.extend(check_pytz_tzinfo_kwarg(index, source, file_ctx));
    issues.extend(check_pytz_timezone_usage(index, source, file_ctx));
    issues.extend(check_reduction_axis_missing(index, source, file_ctx));
    issues.extend(check_gather_validate_indices(index, source, file_ctx));
    issues.extend(check_keras_model_input_shape(parsed, index, source));
    issues.extend(check_pipeline_memory_missing(index, source, file_ctx));
    issues.extend(check_estimator_hyperparameters(index, source, file_ctx));
    issues.extend(check_base_estimator_underscore_attributes(
        parsed, index, source,
    ));
    issues.extend(check_nn_module_super_init(index, source, file_ctx));
    issues.extend(check_autograd_variable_usage(index, source, file_ctx));
    issues.extend(check_dataloader_workers(index, source, file_ctx));
    issues.extend(check_torch_load_weights_only(index, source, file_ctx));
    issues.extend(check_einops_patterns(index, source, file_ctx));
    issues.extend(check_named_steps_bypass(parsed, index, source));
}

/// Tier-A battery 2: Django/web, async hygiene, typing, and quality checks.
fn tier_a2_web_async_typing_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    issues.extend(check_django_string_field_null(index, source, file_ctx));
    issues.extend(check_django_model_str(index, source, file_ctx));
    issues.extend(check_render_locals(index, source, file_ctx));
    issues.extend(check_modelform_meta_fields(index, source, file_ctx));
    issues.extend(check_json_response_safe_flag(index, source, file_ctx));
    issues.extend(check_route_decorator_ordering(index, source, file_ctx));
    issues.extend(check_async_timeout_parameters(index, source, file_ctx));
    issues.extend(check_sleep_in_async_loop(parsed, index, source));
    issues.extend(check_long_sleeps(index, source, file_ctx));
    issues.extend(check_sync_subprocess_in_async(parsed, index, source));
    issues.extend(check_blocking_sleep_in_async(parsed, index, source));
    issues.extend(check_sleep_zero_checkpoint(parsed, index, source));
    issues.extend(check_any_all_list_comprehension(index, source, file_ctx));
    issues.extend(check_sync_file_ops_in_async(parsed, index, source));
    issues.extend(check_sync_http_in_async(parsed, index, source));
    issues.extend(check_input_in_async(parsed, index, source));
    issues.extend(check_async_without_awaits(index, source, file_ctx));
    issues.extend(check_single_task_nurseries(parsed, index, source));
    issues.extend(check_control_flow_in_nurseries(parsed, index, source));
    issues.extend(check_missing_return_annotations(
        index, source, options, file_ctx,
    ));
    issues.extend(check_missing_parameter_annotations(
        index, source, options, file_ctx,
    ));
    issues.extend(check_any_type_hints(parsed, index, source));
    issues.extend(check_bare_generic_hints(parsed, index, source));
    issues.extend(check_typing_alias_hints(parsed, index, source));
    issues.extend(check_typing_union_hints(parsed, index, source));
    issues.extend(check_pep695_generic_classes(index, source, file_ctx));
    issues.extend(check_typealias_assignments(index, source, file_ctx));
    issues.extend(check_redundant_typevars(parsed, index, source, file_ctx));
    issues.extend(check_typevar_annotated_functions(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_except_star_groups(parsed, index, source));
    issues.extend(check_unraised_exceptions(parsed, index, source));
    issues.extend(check_incompatible_assert_literals(index, source, file_ctx));
    issues.extend(check_duplicate_call_arguments(index, source, file_ctx));
    issues.extend(check_skip_without_reason(index, source, file_ctx));
    issues.extend(check_disclosed_secret_keys(index, source, file_ctx));
    issues.extend(check_jwt_secret_arguments(index, source, file_ctx));
    issues.extend(check_trailing_comments(parsed, index, source, options));
    issues.extend(check_overwritten_collection_items(parsed, index, source));
    issues.extend(check_identical_sibling_functions(parsed, index, source));
    issues.extend(check_mutable_default_mutation(index, source, file_ctx));
    issues.extend(check_constant_conditions(index, source, file_ctx));
    issues.extend(check_imprecise_assertions(index, source, file_ctx));
    issues.extend(check_unconditional_assertions(index, source, file_ctx));
    issues.extend(check_unseeded_randomness(index, source, file_ctx));
    issues.extend(check_sync_os_calls_in_async(parsed, index, source));
}

/// Aggregates every regex-family check over one file.
pub(crate) fn check_regex_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let body = parsed.syntax().body.as_slice();
    let sites = collect_regex_sites(body, source);
    let mut issues = Vec::new();

    // python:S4784 — every regex entry point is security-sensitive.
    for site in &sites {
        issues.push(issue_at(
            "python:S4784",
            "Make sure that using a regular expression is safe here.",
            site.pattern_range,
            index,
            source,
        ));
    }

    // python:S6328 — replacement references must exist in the pattern.
    for site in &sites {
        check_replacement_references(site, index, source, &mut issues);
    }

    // python:S5860 — `.group("name")` references versus defined names.
    check_named_group_references(body, &sites, index, source, &mut issues);

    // Structural per-pattern checks.
    for site in &sites {
        let Some(units) = &site.pattern else {
            continue;
        };
        match parse_regex(units) {
            Err(err) => issues.push(issue_at(
                "python:S5856",
                "Fix the syntax error inside this regular expression.",
                err.span,
                index,
                source,
            )),
            Ok(ast) => {
                run_structural_regex_rules(
                    &ast,
                    units,
                    site.verbose,
                    options,
                    &mut issues,
                    index,
                    source,
                );
            }
        }
    }
    issues
}

// ---------------------------------------------------------------------------
// Battery aggregation: every Tier-B entry (symbol/flow/value/effect).
// ---------------------------------------------------------------------------

pub(crate) fn check_tier_b_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let table = build_symbol_table(parsed);
    let facts = collect_file_facts(parsed, source);
    let exports = module_all_exports(parsed);
    let mut issues = Vec::new();
    if !facts.dynamic_names {
        issues.extend(check_unused_imports(&table, &facts, index, source));
        issues.extend(check_unused_parameters(&table, &facts, index, source));
        issues.extend(check_unused_locals(
            &table, &facts, options, &exports, index, source,
        ));
        issues.extend(check_use_before_definition(&table, &facts, index, source));
        issues.extend(check_dead_stores(&table, &facts, options, index, source));
        issues.extend(check_overwritten_parameters(&table, &facts, index, source));
        issues.extend(check_known_value_comparisons(index, source, file_ctx));
        issues.extend(check_static_candidates(&table, index, source));
    }
    issues.extend(check_unused_private_methods(&table, &facts, index, source));
    issues.extend(check_unused_private_nested_classes(
        &table, &facts, index, source,
    ));
    issues.extend(check_unused_nested_definitions(
        &table, &facts, index, source,
    ));
    issues.extend(check_shadowed_builtins(&table, index, source));
    issues.extend(check_all_exports_exist(
        parsed, &table, &facts, index, source,
    ));
    issues.extend(check_undefined_names(&table, &facts, index, source));
    issues.extend(check_unread_private_attributes(
        &table, &facts, options, index, source,
    ));
    issues.extend(check_unreachable_except_blocks(index, source, file_ctx));
    issues.extend(check_single_iteration_loops(index, source, file_ctx));
    issues.extend(check_infinite_recursion(index, source, file_ctx));
    issues.extend(check_explicit_test_skips(index, source, file_ctx));
    issues.extend(check_tf_function_recursion(index, source, file_ctx));
    issues.extend(check_percent_argument_counts(index, source, file_ctx));
    issues.extend(check_percent_argument_types(index, source, file_ctx));
    issues.extend(check_invariant_returns(index, source, file_ctx));
    issues.extend(check_inconsistent_returns(index, source, file_ctx));
    issues.extend(check_confusing_type_checks(index, source, file_ctx));
    issues.extend(check_tf_function_global_captures(&table, index, source));
    issues.extend(check_tf_variable_creation(parsed, index, source));
    issues.extend(check_tf_function_side_effects(parsed, index, source));
    issues.extend(check_missing_eval_after_load(index, source, file_ctx));
    issues.extend(check_unreferenced_asyncio_tasks(index, source, file_ctx));
    issues.extend(check_sync_open_without_async_with(parsed, index, source));
    issues.extend(check_nested_estimator_parameters(
        parsed, &table, index, source, file_ctx,
    ));
    issues.extend(check_cancellation_scope_checkpoints(parsed, index, source));
    issues.extend(check_swallowed_cancellations(index, source, file_ctx));
    issues
}

/// Aggregates every Tier-C security-sensitive check over one file.
pub(crate) fn check_tier_c_security_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    tier_c_core_security_checks(parsed, index, source, file_ctx, &mut issues);
    tier_c_web_crypto_checks(parsed, index, source, file_ctx, &mut issues);
    tier_c_cloud_data_checks(parsed, index, source, file_ctx, &mut issues);
    issues
}

/// Tier-C battery: transport, auth, and protocol-level checks.
fn tier_c_core_security_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    issues.extend(check_s4792_logger_configuration(index, source, file_ctx));
    issues.extend(check_s4823_command_line_arguments(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_s4829_standard_input(index, source, file_ctx));
    issues.extend(check_s4787_encrypting_data(index, source, file_ctx));
    issues.extend(check_s5300_sending_emails(index, source, file_ctx));
    issues.extend(check_s4721_shell_commands(index, source, file_ctx));
    issues.extend(check_s4830_certificate_verification(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_s5527_hostname_verification(index, source, file_ctx));
    issues.extend(check_s4423_weak_ssl_protocols(parsed, index, source));
    issues.extend(check_s4426_weak_key_generation(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_cookie_flag(
        index,
        source,
        "python:S2092",
        "Add the \"secure\" flag to this cookie.",
        "secure",
        file_ctx,
    ));
    issues.extend(check_cookie_flag(
        index,
        source,
        "python:S3330",
        "Add the \"HttpOnly\" flag to this cookie.",
        "httponly",
        file_ctx,
    ));
}

/// Tier-C battery: injection, templating, cryptography, and secret checks.
fn tier_c_web_crypto_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    issues.extend(check_s4502_csrf_disabled(index, source, file_ctx));
    issues.extend(check_s5122_cors_wildcard(index, source, file_ctx));
    issues.extend(check_s5247_autoescaping_disabled(index, source, file_ctx));
    issues.extend(check_s5439_global_autoescape_disabled(
        parsed, index, source,
    ));
    issues.extend(check_s4433_ldap_unauthenticated(index, source, file_ctx));
    issues.extend(check_s2115_empty_database_password(index, source, file_ctx));
    issues.extend(check_s2077_sql_formatting(index, source, file_ctx));
    issues.extend(check_s2053_static_salt(index, source, file_ctx));
    issues.extend(check_s3329_static_cbc_iv(index, source, file_ctx));
    issues.extend(check_s5542_weak_modes_and_paddings(parsed, index, source));
    issues.extend(check_s5547_weak_ciphers(index, source, file_ctx));
    issues.extend(check_s5659_jwt_signing(index, source, file_ctx));
    issues.extend(check_s5344_plaintext_passwords(index, source, file_ctx));
    issues.extend(check_s2245_prng_security_contexts(index, source, file_ctx));
    issues.extend(check_s5443_public_temp_files(index, source, file_ctx));
    issues.extend(check_s2755_xxe_parsers(index, source, file_ctx));
    issues.extend(check_s6377_weak_xml_signature_transforms(
        parsed, index, source,
    ));
}

/// Tier-C battery: cloud/IAM posture plus collection and type-safety checks.
fn tier_c_cloud_data_checks(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    issues: &mut Vec<Issue>,
) {
    issues.extend(check_s4828_signal_parameters(index, source, file_ctx));
    issues.extend(check_s1523_dynamic_code_execution(index, source, file_ctx));
    issues.extend(check_s2257_custom_cryptography(index, source, file_ctx));
    issues.extend(check_s6785_graphql_depth_limiting(index, source, file_ctx));
    issues.extend(check_s6245_s3_encryption_configuration(
        index, source, file_ctx,
    ));
    issues.extend(check_s6252_s3_versioning(index, source, file_ctx));
    issues.extend(check_s6265_s3_public_acl(index, source, file_ctx));
    issues.extend(check_s6270_public_resource_policy(parsed, index, source));
    issues.extend(check_s6275_ebs_encryption(index, source, file_ctx));
    issues.extend(check_s6281_s3_public_access_block(index, source, file_ctx));
    issues.extend(check_s6302_all_privileges_policy(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_s6304_all_resources_policy(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_s6303_rds_encryption(index, source, file_ctx));
    issues.extend(check_s6308_opensearch_encryption(index, source, file_ctx));
    issues.extend(check_s6317_wildcard_action_scope(
        parsed, index, source, file_ctx,
    ));
    issues.extend(check_s6319_sagemaker_encryption(index, source, file_ctx));
    issues.extend(check_s6321_admin_ports_open_world(index, source, file_ctx));
    issues.extend(check_s6327_sns_encryption(index, source, file_ctx));
    issues.extend(check_s6329_public_network_access(index, source, file_ctx));
    issues.extend(check_s6330_sqs_encryption(index, source, file_ctx));
    issues.extend(check_s6332_efs_encryption(index, source, file_ctx));
    issues.extend(check_s6333_api_gateway_authorization(
        index, source, file_ctx,
    ));
    issues.extend(check_s6463_unrestricted_egress(index, source, file_ctx));
    issues.extend(check_s3752_route_methods(index, source, file_ctx));
    issues.extend(check_s5795_identity_cached_types(index, source, file_ctx));
    issues.extend(check_s3403_identity_dissimilar_types(
        index, source, file_ctx,
    ));
    issues.extend(check_s6663_sequence_index_type(index, source, file_ctx));
    issues.extend(check_s5642_membership_operands(index, source, file_ctx));
    issues.extend(check_s5644_literal_item_operations(index, source, file_ctx));
    issues.extend(check_s3862_iterating_non_iterables(index, source, file_ctx));
    issues.extend(check_s5607_incompatible_operator_pairs(
        index, source, file_ctx,
    ));
    issues.extend(check_s6662_unhashable_collection_literals(
        index, source, file_ctx,
    ));
    issues.extend(check_s5707_raise_from_non_exception(
        index, source, file_ctx,
    ));
    issues.extend(check_s5632_raising_non_exceptions(index, source, file_ctx));
    issues.extend(check_s5708_excepting_non_exceptions(
        index, source, file_ctx,
    ));
}

// ---------------------------------------------------------------------------
// Tier-C semantic family (file-local symbol tables plus conservative call,
// type-hint, and contract heuristics).
//
// Every rule restricts itself to targets resolvable inside the analyzed file;
// anything needing import resolution or full type inference is skipped.
// ---------------------------------------------------------------------------

/// Aggregates the Tier-C semantic checks over one file.
pub(crate) fn check_tier_c_semantic_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_s2201_ignored_pure_returns(index, source, file_ctx));
    issues.extend(check_s5756_non_callable_callees(parsed, index, source));
    issues.extend(check_s3699_used_void_outputs(parsed, index, source));
    issues.extend(check_s935_bare_returns(index, source, file_ctx));
    issues.extend(check_s5890_annotated_assignment_kinds(
        index, source, file_ctx,
    ));
    issues.extend(check_s5886_return_hint_mismatches(index, source, file_ctx));
    issues.extend(check_s930_arity_mismatches(parsed, index, source));
    issues.extend(check_s5655_argument_kind_mismatches(parsed, index, source));
    issues.extend(check_s2876_iter_returns(index, source, file_ctx));
    issues.extend(check_s2638_override_contracts(parsed, index, source));
    issues.extend(check_s5713_parent_child_except_pairs(parsed, index, source));
    issues
}

pub(crate) fn check_size_metric_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
    metrics: &hoonarqube_ir::FileMetrics,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_function_parameter_counts(
        parsed, index, source, options,
    ));
    issues.extend(check_function_return_counts(parsed, index, source, options));
    issues.extend(check_function_lengths(parsed, index, source, options));
    issues.extend(check_nesting_depths(parsed, index, source, options));
    issues.extend(check_lines_of_code(metrics, options));
    issues
}

pub(crate) fn check_naming_convention_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_method_and_function_names(parsed, index, source));
    issues.extend(check_class_names(index, source, file_ctx));
    issues.extend(check_class_field_names(index, source, file_ctx));
    issues.extend(check_parameter_and_local_names(parsed, index, source));
    issues
}

// ---------------------------------------------------------------------------
// Battery aggregation: the structural Tier-A gap rules (python:S1066 …
// python:S6799), each in its own per-rule module.
// ---------------------------------------------------------------------------

pub(crate) fn check_structural_battery(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_collapsible_ifs(parsed, index, source));
    issues.extend(check_empty_functions(parsed, index, source));
    issues.extend(check_missing_docstrings(parsed, index, source));
    issues.extend(check_similar_names_scope(parsed, index, source));
    issues.extend(check_empty_blocks(parsed, index, source));
    issues.extend(check_member_name_matches_class(parsed, index, source));
    issues.extend(check_old_style_classes(index, source, file_ctx));
    issues.extend(check_cognitive_complexity(parsed, index, source, options));
    issues.extend(check_function_complexity(parsed, index, source, options));
    issues.extend(check_file_complexity(parsed, index, source, options));
    issues.extend(check_class_complexity(parsed, index, source, options));
    issues.extend(check_f_string_nesting(parsed, index, source));
    issues.extend(check_redundant_parentheses(parsed, index, source));
    issues
}

mod all_exports_exist;

mod any_all_list_comprehension;

mod any_type_hints;

mod assertion_at_end_of_except;

pub(crate) mod assign_plus_minus;

mod async_timeout_parameters;

mod async_without_awaits;

mod autograd_variable_usage;

mod bare_generic_hints;

mod base_estimator_underscore_attributes;

mod blocking_sleep_in_async;

mod boolean_except_clauses;

mod boundary_slice_comparisons;

mod cancellation_scope_checkpoints;

mod collapsible_ifs;

mod class_field_names;

mod class_names;

mod classmethod_parameter_names;

pub(crate) mod cleartext_protocols;

mod closure_captures_loop_variable;

pub(crate) mod complexity;

pub(crate) mod commented_code;

mod confusing_type_checks;

mod confusing_walrus_placement;

mod constant_conditions;

mod constant_dict_comprehension_values;

mod constant_none_comparisons;

mod constant_populated_dict_loop;

mod control_flow_in_nurseries;

mod cookie_flag;

mod copy_only_comprehensions;

mod curly_quantifier;

mod dataframe_values_attribute;

mod dataloader_workers;

mod datetime_component_ranges;

mod dead_stores;

mod debug_features;

mod defaultdict_keyword_factory;

mod deprecated_numpy_aliases;

mod deprecated_utc_helpers;

mod disclosed_secret_keys;

mod django_model_str;

mod django_string_field_null;

mod doubled_prefix_operators;

mod dunder_all_strings;

mod duplicate_branches;

mod duplicate_call_arguments;

mod duplicate_conditions;

mod duplicate_dict_keys;

mod duplicate_set_elements;

mod duplicated_string_literals;
mod empty_blocks;

mod einops_patterns;

mod empty_collection_constructors;
mod empty_functions;

pub(crate) mod ends_with_newline;

mod estimator_hyperparameters;

mod except_star_groups;

mod exception_inheritance;

mod exit_reraises_argument;

mod exit_signatures;

mod explicit_test_skips;

mod float_equality_comparisons;

mod fresh_object_identity_checks;

mod function_lengths;

mod function_parameter_counts;

mod f_string_nesting;
mod function_return_counts;

mod gather_validate_indices;

mod generator_into_constructor;

mod generator_return_values;

pub(crate) mod hardcoded_credentials;

pub(crate) mod hardcoded_ips;

pub(crate) mod hardcoded_secrets;

mod identical_if_else_branches;

mod identical_operands;

mod identical_sibling_functions;

mod imprecise_assertions;

mod incompatible_assert_literals;

mod inconsistent_returns;

mod infinite_recursion;

mod init_return_values;

mod input_in_async;

mod insecure_temp_files;

mod instance_self_parameters;

pub(crate) mod invalid_string_escapes;

mod invalid_weekmask;

mod invariant_returns;

mod inverted_boolean_checks;

mod isclose_zero_tolerance;

pub(crate) mod issue_tags;

mod items_only_keys_needed;

mod json_response_safe_flag;

mod jwt_secret_arguments;

mod keras_model_input_shape;

pub(crate) mod keyword_parentheses;

mod known_value_comparisons;

mod lambda_assignments;

pub(crate) mod license_header;

pub(crate) mod line_length;

mod lines_of_code;

mod list_wrapped_iteration;

mod literal_re_sub_patterns;

mod long_dataframe_chains;

mod long_sleeps;

mod loop_else_without_break;

pub(crate) mod lowercase_long_suffix;

mod manual_key_iteration;

mod map_lambda_calls;

mod meaningless_size_comparisons;

mod method_and_function_names;

mod methods_missing_parameters;

mod missing_docstrings;
mod missing_eval_after_load;

mod missing_parameter_annotations;

mod missing_return_annotations;

pub(crate) mod mixed_string_concatenation;

mod modelform_meta_fields;

pub(crate) mod module_name;

mod mutable_default_mutation;

mod named_group_references;

mod named_steps_bypass;

mod nan_comparisons;

mod member_name_matches_class;

mod needless_pass;

mod nested_bodies;

mod nested_conditional_expressions;

mod nested_estimator_parameters;

mod nested_identical_constructors;

mod nesting_depths;

mod nn_module_super_init;

mod no_effect_statements;

pub(crate) mod no_sonar;

pub(crate) mod noqa_comments;

mod notimplemented_raises;

mod np_array_generator;

pub(crate) mod one_statement_per_line;

mod only_reraise_handlers;

mod old_style_classes;
mod open_modes;

mod overwritten_collection_items;

mod overwritten_parameters;

mod pandas_inplace;

mod parameter_and_local_names;

pub(crate) mod parsing_errors;

mod pep695_generic_classes;

mod percent_argument_counts;

mod percent_argument_types;

mod pipeline_memory_missing;

pub(crate) mod pre_increment_decrement;

mod property_accessor_arities;

pub(crate) mod py2_backticks;

pub(crate) mod py2_inequality;

mod pytz_timezone_usage;

mod pytz_tzinfo_kwarg;

mod raise_and_jump_flow;

mod random_state_usage;

mod read_without_dtype;

mod reduction_axis_missing;
mod redundant_parentheses;

mod redundant_jump_statements;

mod redundant_typevars;

mod render_locals;
mod similar_names_scope;

mod replacement_references;

mod route_decorator_ordering;

mod rx_alternation_nodes;

mod rx_alternation_shapes;

mod rx_anchor_order;

mod rx_class;

mod rx_empty_groups;

mod rx_lazy_quantifiers;

mod rx_overlapping_repeats;

mod rx_pointless_groups;

mod rx_possessive_deadlock;

mod rx_redundant_alternatives;

pub(crate) mod rx_repetition_hazards;

mod rx_space_runs;

pub(crate) mod rx_style_shapes;

pub(crate) mod rx_syntax_shapes;

mod s1523_dynamic_code_execution;

mod s2053_static_salt;

mod s2077_sql_formatting;

mod s2115_empty_database_password;

mod s2201_ignored_pure_returns;

mod s2245_prng_security_contexts;

mod s2257_custom_cryptography;

mod s2638_override_contracts;

mod s2755_xxe_parsers;

mod s2876_iter_returns;

mod s3329_static_cbc_iv;

mod s3403_identity_dissimilar_types;

mod s3699_used_void_outputs;

mod s3752_route_methods;

mod s3862_iterating_non_iterables;

mod s4423_weak_ssl_protocols;

mod s4426_weak_key_generation;

mod s4433_ldap_unauthenticated;

mod s4502_csrf_disabled;

mod s4721_shell_commands;

mod s4787_encrypting_data;

mod s4792_logger_configuration;

mod s4823_command_line_arguments;

mod s4828_signal_parameters;

mod s4829_standard_input;

mod s4830_certificate_verification;

mod s5122_cors_wildcard;

mod s5247_autoescaping_disabled;

mod s5300_sending_emails;

mod s5344_plaintext_passwords;

mod s5439_global_autoescape_disabled;

mod s5443_public_temp_files;

mod s5527_hostname_verification;

mod s5542_weak_modes_and_paddings;

mod s5547_weak_ciphers;

mod s5607_incompatible_operator_pairs;

mod s5632_raising_non_exceptions;

mod s5642_membership_operands;

mod s5644_literal_item_operations;

mod s5655_argument_kind_mismatches;

mod s5659_jwt_signing;

mod s5707_raise_from_non_exception;

mod s5708_excepting_non_exceptions;

mod s5713_parent_child_except_pairs;

mod s5756_non_callable_callees;

mod s5795_identity_cached_types;

mod s5886_return_hint_mismatches;

mod s5890_annotated_assignment_kinds;

mod s6245_s3_encryption_configuration;

mod s6252_s3_versioning;

mod s6265_s3_public_acl;

mod s6270_public_resource_policy;

mod s6275_ebs_encryption;

mod s6281_s3_public_access_block;

mod s6302_all_privileges_policy;

mod s6303_rds_encryption;

mod s6304_all_resources_policy;

mod s6308_opensearch_encryption;

mod s6317_wildcard_action_scope;

mod s6319_sagemaker_encryption;

mod s6321_admin_ports_open_world;

mod s6327_sns_encryption;

mod s6329_public_network_access;

mod s6330_sqs_encryption;

mod s6332_efs_encryption;

mod s6333_api_gateway_authorization;

mod s6377_weak_xml_signature_transforms;

mod s6463_unrestricted_egress;

mod s6662_unhashable_collection_literals;

mod s6663_sequence_index_type;

mod s6785_graphql_depth_limiting;

mod s930_arity_mismatches;

mod s935_bare_returns;

mod self_assignment;

mod shadowed_builtins;

mod single_arg_np_where;

mod single_iteration_loops;

mod single_task_nurseries;

mod skip_without_reason;

mod sleep_in_async_loop;

mod sleep_zero_checkpoint;

mod sorted_reversed_shapes;

mod special_method_arities;

mod static_candidates;

mod strftime_hour_markers;

pub(crate) mod suite;

mod swallowed_cancellations;

mod swallowed_system_exit;

mod sync_file_ops_in_async;

mod sync_http_in_async;

mod sync_open_without_async_with;

mod sync_os_calls_in_async;

mod sync_subprocess_in_async;

mod tf_function_global_captures;

mod tf_function_recursion;

mod tf_function_side_effects;

mod tf_variable_creation;

mod to_datetime_ambiguity;

mod torch_load_weights_only;

mod trailing_comments;

pub(crate) mod trailing_whitespace;

mod tuple_assertions;

mod type_equality_comparisons;

mod typealias_assignments;

mod typevar_annotated_functions;

mod typing_alias_hints;

mod typing_union_hints;

mod unbounded_archive_extraction;

mod unconditional_assertions;

mod undefined_names;

mod unqualified_merge;

mod unraised_exceptions;

mod unreachable_code;

mod unreachable_except_blocks;

mod unreachable_test_methods;

mod unread_private_attributes;

mod unreferenced_asyncio_tasks;

mod unseeded_randomness;

mod unused_imports;

mod unused_locals;

mod unused_nested_definitions;

mod unused_parameters;

mod unused_private_methods;

mod unused_private_nested_classes;

mod use_before_definition;

mod weak_hashing;

mod wildcard_imports;

mod world_writable_modes;

mod wrapping_collection_constructors;

mod yield_return_outside_function;
