//! Raw text, token, and line scans (Tier A1).

pub(crate) mod clause_on_new_line;
pub(crate) mod close_brace_column;
pub(crate) mod commented_out_code;
pub(crate) mod conditional_indentation;
pub(crate) mod declarators_per_line;
pub(crate) mod empty_comments;
pub(crate) mod file_loc;
pub(crate) mod final_newline;
pub(crate) mod header;
pub(crate) mod line_length;
pub(crate) mod numeric_separators;
pub(crate) mod one_statement_per_line;
mod support;
pub(crate) mod tabs;
mod walker;

pub(crate) use walker::text_issues;
