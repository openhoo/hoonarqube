// Family 'jsx_a11y' (generated).
pub(crate) mod collectors;
mod s1077_alt_text;
mod s1082_mouse_keyboard_pair;
mod s1090_iframe_title;
mod s4084_media_captions;
mod s5254_html_lang;
mod s5256_s5257_s5260_table_facts;
mod s5264_object_alternative;
mod s6793_aria_values;
mod s6807_required_owned;
mod s6811_supported_properties;
mod s6819_s6822_role_duplicates;
mod s6821_abstract_role;
mod s6823_activedescendant_focusable;
mod s6824_allowed_roles;
mod s6825_aria_hidden_focusable;
mod s6827_anchor_content;
mod s6840_autocomplete_value;
mod s6841_tab_index_value;
mod s6842_noninteractive_with_interactive_role;
mod s6843_interactive_with_noninteractive_role;
mod s6844_anchor_click_without_href;
mod s6845_noninteractive_tab_index;
mod s6846_accesskey;
mod s6847_noninteractive_handlers;
mod s6848_click_keyboard_pair;
mod s6850_heading_content;
mod s6851_redundant_alt;
mod s6852_interactive_role_focusable;
mod s6853_label_association;
mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
