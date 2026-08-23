use crate::support::REGEX_METACHARACTERS;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_literal_re_sub_patterns(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if !matches!(
            dotted_name(&call.func).as_deref(),
            Some("re.sub" | "re.subn")
        ) {
            return;
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
    });
    issues
}
