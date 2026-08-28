use crate::engine::file_context::FileContext;
use crate::support::dotted_name;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_open_modes(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let Some(path) = dotted_name(&call.func) else {
            continue;
        };
        if path != "open" && path != "io.open" {
            continue;
        }
        let Some(mode_expr) =
            keyword_value(&call.arguments, "mode").or_else(|| call.arguments.args.get(1))
        else {
            continue;
        };
        let Some(mode) = string_literal_text(mode_expr) else {
            continue;
        };
        if open_mode_is_known_but_invalid(&mode) {
            issues.push(issue_at(
                "python:S5828",
                "Fix this invalid mode string.",
                mode_expr.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S5828 — invalid open modes ---------------------------------------

fn open_mode_is_known_but_invalid(mode: &str) -> bool {
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
    primary != 1 || plus > 1 || binary > 1 || textual > 1
}
