//! LINQ/format/assertion patterns and receiver-type LINQ performance.
//! A15 — LINQ/format/assertion patterns & misc API heuristics

pub(crate) mod accessor_shaped_methods;
pub(crate) mod anonymous_unsubscriptions;
pub(crate) mod any_instead_of_count;
pub(crate) mod composite_format_usage;
pub(crate) mod concise_declarations;
pub(crate) mod double_element_writes;
pub(crate) mod duplicate_casts;
pub(crate) mod format_argument_counts;
mod linq_receivers;
pub(crate) mod regular_number_patterns;
pub(crate) mod setters_assign_value;
pub(crate) mod string_arguments_at_uri_overloads;
mod support;
pub(crate) mod trivial_base_forwarding_overrides;
pub(crate) mod uri_string_parameters;
pub(crate) mod uri_string_properties;
pub(crate) mod uri_string_returns;
mod walker;

pub(crate) use linq_receivers::check as check_linq_receivers;
pub(crate) use support::first_child_token_text;
pub(crate) use support::methods_grouped_by_name;
pub(crate) use walker::linq_api_issues;
