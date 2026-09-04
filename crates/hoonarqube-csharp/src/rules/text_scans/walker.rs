use super::clause_on_new_line::check as check_clause_on_new_line;
use super::close_brace_column::check as check_close_brace_column;
use super::commented_out_code::check as check_commented_out_code;
use super::conditional_indentation::check as check_conditional_indentation;
use super::declarators_per_line::check as check_declarators_per_line;
use super::empty_comments::check as check_empty_comments;
use super::file_loc::check as check_file_loc;
use super::final_newline::check as check_final_newline;
use super::header::check as check_header;
use super::line_length::check as check_line_length;
use super::numeric_separators::check as check_numeric_separators;
use super::one_statement_per_line::check as check_one_statement_per_line;
use super::tabs::check as check_tabs;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use std::path::Path;
use tree_sitter::Node;

/// Gathers every issue contributed by this rule family.
pub(crate) fn text_issues(
    root: Node<'_>,
    path: &Path,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
    code_line_count: usize,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(check_line_length(source, language, options));
    issues.extend(check_file_loc(code_line_count, language, options));
    issues.extend(check_tabs(source, language));
    issues.extend(check_final_newline(path, source, language));
    issues.extend(check_header(source, language, options));
    issues.extend(check_close_brace_column(root, source, language));
    issues.extend(check_one_statement_per_line(root, source, language));
    issues.extend(check_clause_on_new_line(root, source, language));
    issues.extend(check_conditional_indentation(root, source, language));
    issues.extend(check_declarators_per_line(root, source, language));
    issues.extend(check_empty_comments(root, source, language));
    issues.extend(check_commented_out_code(root, source, language));
    issues.extend(check_numeric_separators(root, source, language));
    issues
}
