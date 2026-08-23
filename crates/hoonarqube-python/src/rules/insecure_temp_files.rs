use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5445 — insecure temporary files ----------------------------------

pub(crate) fn check_insecure_temp_files(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let insecure = ["tempfile.mktemp", "os.tempnam", "os.tmpnam"];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if dotted_name(&call.func).is_some_and(|path| insecure.contains(&path.as_str())) {
            issues.push(issue_at(
                "python:S5445",
                "Remove this usage of the deprecated insecure temporary file API.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
