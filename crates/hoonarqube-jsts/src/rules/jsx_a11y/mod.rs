// Family 'jsx_a11y' (generated).
pub(crate) mod collectors;
pub(crate) mod s1077_alt_text;
pub(crate) mod s1082_mouse_keyboard_pair;
pub(crate) mod s1090_iframe_title;
pub(crate) mod s4084_media_captions;
pub(crate) mod s5254_html_lang;
pub(crate) mod s5256_s5257_s5260_table_facts;
pub(crate) mod s5264_object_alternative;
pub(crate) mod s6793_aria_values;
pub(crate) mod s6807_required_owned;
pub(crate) mod s6811_supported_properties;
pub(crate) mod s6819_s6822_role_duplicates;
pub(crate) mod s6821_abstract_role;
pub(crate) mod s6823_activedescendant_focusable;
pub(crate) mod s6824_allowed_roles;
pub(crate) mod s6825_aria_hidden_focusable;
pub(crate) mod s6827_anchor_content;
pub(crate) mod s6840_autocomplete_value;
pub(crate) mod s6841_tab_index_value;
pub(crate) mod s6842_noninteractive_with_interactive_role;
pub(crate) mod s6843_interactive_with_noninteractive_role;
pub(crate) mod s6844_anchor_click_without_href;
pub(crate) mod s6845_noninteractive_tab_index;
pub(crate) mod s6846_accesskey;
pub(crate) mod s6847_noninteractive_handlers;
pub(crate) mod s6848_click_keyboard_pair;
pub(crate) mod s6850_heading_content;
pub(crate) mod s6851_redundant_alt;
pub(crate) mod s6852_interactive_role_focusable;
pub(crate) mod s6853_label_association;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
