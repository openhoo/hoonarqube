use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_literal_re_sub_patterns(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !dotted_name_in(&call.func, &["re.sub", "re.subn"]) {
            continue;
        }
        if let Some(pattern) = call.arguments.args.first().and_then(string_literal_text)
            && !pattern.chars().any(|c| REGEX_METACHARACTERS.contains(&c))
        {
            issues.push(issue_at(
                "python:S5361",
                "Replace this regular-expression pattern with a plain string.",
                call.arguments.args[0].range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S5361 — re.sub with a metacharacter-free pattern --------------------

const REGEX_METACHARACTERS: [char; 14] = [
    '\\', '^', '$', '.', '|', '?', '*', '+', '(', ')', '[', ']', '{', '}',
];
