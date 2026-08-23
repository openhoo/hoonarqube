use crate::support::called_name;
use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::int_literal_value;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2612 — world/group-writable file modes -----------------------------

pub(crate) fn check_world_writable_modes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let os_chmods = ["os.chmod", "os.fchmod", "os.lchmod"];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let path = dotted_name(&call.func);
        let mode_index = if path.is_some_and(|p| os_chmods.contains(&p.as_str())) {
            Some(1)
        } else if called_name(&call.func) == Some("chmod") {
            Some(0)
        } else {
            None
        };
        let Some(position) = mode_index else {
            return;
        };
        let Some(mode) = call
            .arguments
            .args
            .get(position)
            .and_then(int_literal_value)
        else {
            return;
        };
        if mode & 0o022 != 0 {
            issues.push(issue_at(
                "python:S2612",
                "Remove group and other write permission from this file mode.",
                call.arguments.args[position].range(),
                index,
                source,
            ));
        }
    });
    issues
}
