use super::async_naming::check as check_async_naming;
use super::enum_names::check as check_enum_names;
use super::enum_suffixes::check as check_enum_suffixes;
use super::exception_like_suffixes::check as check_exception_like_suffixes;
use super::getter_named_methods::check as check_getter_named_methods;
use super::logger_member_names::check as check_logger_member_names;
use super::method_property_names::check as check_method_property_names;
use super::overloads_grouped::check as check_overloads_grouped;
use super::parameter_shadows_method::check as check_parameter_shadows_method;
use super::type_name_matches_namespace::check as check_type_name_matches_namespace;
use super::type_names::check as check_type_names;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Gathers every issue contributed by this rule family.
pub(crate) fn naming_issues(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_method_property_names(root, source, language));
    issues.extend(check_type_names(root, source, language));
    issues.extend(check_enum_names(root, source, language, options));
    issues.extend(check_enum_suffixes(root, source, language));
    issues.extend(check_exception_like_suffixes(root, source, language));
    issues.extend(check_parameter_shadows_method(root, source, language));
    issues.extend(check_type_name_matches_namespace(root, source, language));
    issues.extend(check_getter_named_methods(root, source, language));
    issues.extend(check_overloads_grouped(root, source, language));
    issues.extend(check_async_naming(root, source, language));
    issues.extend(check_logger_member_names(root, source, language, options));
    issues
}
