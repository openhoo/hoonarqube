//! Literal-content scans (Tier A9).
//! A9 — literal-content scans

pub(crate) mod duplicate_string_literals;
pub(crate) mod hardcoded_credentials;
pub(crate) mod hardcoded_ip_addresses;
pub(crate) mod hardcoded_secrets;
pub(crate) mod hardcoded_uris;
pub(crate) mod numeric_suffix_case;
pub(crate) mod raw_control_characters;
pub(crate) mod regex_syntax;
pub(crate) mod regex_timeouts;
pub(crate) mod sql_keyword_delimiters;
mod support;
mod walker;

pub(crate) use support::argument_expression;
pub(crate) use support::argument_nodes;
pub(crate) use support::assignment_target_name;
pub(crate) use support::declarator_initializer;
pub(crate) use support::is_string_literal;
pub(crate) use support::literal_inner_offset;
pub(crate) use support::literal_inner_text;
pub(crate) use support::string_literals;
pub(crate) use walker::literal_content_issues;
