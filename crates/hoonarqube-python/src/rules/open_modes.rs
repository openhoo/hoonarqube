use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_open_modes(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let Some(path) = dotted_name(&call.func) else {
            return;
        };
        if path != "open" && path != "io.open" {
            return;
        }
        let Some(mode_expr) =
            keyword_value(&call.arguments, "mode").or_else(|| call.arguments.args.get(1))
        else {
            return;
        };
        let Some(mode) = string_literal_text(mode_expr) else {
            return;
        };
        if !open_mode_is_valid(&mode) {
            issues.push(issue_at(
                "python:S5828",
                &format!("Fix this invalid open mode '{mode}'."),
                mode_expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S5828) ---
// --- python:S5828 — invalid open modes ---------------------------------------

pub(crate) fn open_mode_is_valid(mode: &str) -> bool {
    let mut primary = 0;
    let mut plus = 0;
    let mut binary = 0;
    let mut textual = 0;
    for ch in mode.chars() {
        match ch {
            'r' | 'w' | 'a' | 'x' => primary += 1,
            '+' => plus += 1,
            'b' => binary += 1,
            't' => textual += 1,
            'U' => {}
            _ => return false,
        }
    }
    primary == 1 && plus <= 1 && binary <= 1 && textual <= 1
}
