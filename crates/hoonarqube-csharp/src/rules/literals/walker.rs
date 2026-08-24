use super::duplicate_string_literals::check as check_duplicate_string_literals;
use super::hardcoded_credentials::check as check_hardcoded_credentials;
use super::hardcoded_ip_addresses::check as check_hardcoded_ip_addresses;
use super::hardcoded_secrets::check as check_hardcoded_secrets;
use super::hardcoded_uris::check as check_hardcoded_uris;
use super::numeric_suffix_case::check as check_numeric_suffix_case;
use super::raw_control_characters::check as check_raw_control_characters;
use super::regex_syntax::check as check_regex_syntax;
use super::regex_timeouts::check as check_regex_timeouts;
use super::sql_keyword_delimiters::check as check_sql_keyword_delimiters;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every Tier-A9 literal-content issue.
pub(crate) fn literal_content_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_duplicate_string_literals(
        root, source, language, options,
    ));
    issues.extend(check_hardcoded_credentials(root, source, language, options));
    issues.extend(check_hardcoded_secrets(root, source, language, options));
    issues.extend(check_hardcoded_ip_addresses(root, source, language));
    issues.extend(check_hardcoded_uris(root, source, language));
    issues.extend(check_sql_keyword_delimiters(root, source, language));
    issues.extend(check_regex_syntax(root, source, language));
    issues.extend(check_regex_timeouts(root, source, language));
    issues.extend(check_raw_control_characters(root, source, language));
    issues.extend(check_numeric_suffix_case(root, source, language));
    issues
}
