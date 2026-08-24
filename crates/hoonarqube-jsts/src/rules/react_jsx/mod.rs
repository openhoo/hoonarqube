// Family 'react_jsx' (generated).
pub(crate) mod collectors;
pub(crate) mod s6435_render_method_return;
pub(crate) mod s6438_empty_container;
pub(crate) mod s6439_literal_conditional_child;
pub(crate) mod s6440_hook_call_site;
pub(crate) mod s6442_s6754_use_state_pair;
pub(crate) mod s6443_noop_state_setter;
pub(crate) mod s6477_map_root_key;
pub(crate) mod s6478_nested_component;
pub(crate) mod s6479_index_key;
pub(crate) mod s6480_inline_function_values;
pub(crate) mod s6481_context_provider_value;
pub(crate) mod s6746_state_mutation_assignment;
pub(crate) mod s6747_unknown_attributes;
pub(crate) mod s6748_s6761_s6790_element_rules;
pub(crate) mod s6749_single_child_fragment;
pub(crate) mod s6750_s6788_s6789_s6957_deprecated_import;
pub(crate) mod s6756_set_state_argument;
pub(crate) mod s6757_s6757_this_expression;
pub(crate) mod s6763_pure_component_update;
pub(crate) mod s6766_unescaped_entities;
pub(crate) mod s6770_unknown_tag;
pub(crate) mod s6772_whitespace_only_gaps;
pub(crate) mod s6774_props_without_prop_types;
pub(crate) mod s6775_report_uncovered_defaults;
pub(crate) mod s6791_legacy_lifecycle;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
