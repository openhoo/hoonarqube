// Family 'react_jsx' (generated).
pub(crate) mod collectors;
mod s6435_render_method_return;
mod s6438_empty_container;
mod s6439_literal_conditional_child;
mod s6440_hook_call_site;
mod s6442_s6754_use_state_pair;
mod s6443_noop_state_setter;
mod s6477_map_root_key;
mod s6478_nested_component;
mod s6479_index_key;
mod s6480_inline_function_values;
mod s6481_context_provider_value;
pub(crate) mod s6746_state_mutation_assignment;
mod s6747_unknown_attributes;
mod s6748_s6761_s6790_element_rules;
mod s6749_single_child_fragment;
mod s6750_s6788_s6789_s6957_deprecated_import;
mod s6756_set_state_argument;
mod s6757_s6757_this_expression;
mod s6763_pure_component_update;
mod s6766_unescaped_entities;
mod s6770_unknown_tag;
mod s6772_whitespace_only_gaps;
mod s6774_props_without_prop_types;
mod s6775_report_uncovered_defaults;
mod s6791_legacy_lifecycle;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
