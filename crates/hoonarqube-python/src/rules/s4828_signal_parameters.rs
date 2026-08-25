use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::int_literal_value;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4828 — OS process signal parameters validated ----------------------

pub(crate) fn check_s4828_signal_parameters(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let raw_signal = match called_name(&call.func) {
            Some("signal") => call.arguments.args.first().and_then(int_literal_value),
            Some("kill") => call.arguments.args.get(1).and_then(int_literal_value),
            _ => None,
        }
        .is_some();
        if raw_signal {
            issues.push(issue_at(
                "python:S4828",
                "Validate this signal parameter against the symbolic SIG constants.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4828_flags_raw_numeric_signal_parameters() {
        let flagged = "signal.signal(9, handler)\nos.kill(pid, 15)\n";
        assert_eq!(findings(&scan(flagged), "python:S4828").len(), 2);
        let clean = "signal.signal(signal.SIGTERM, handler)\nos.kill(pid, signal.SIGKILL)\n";
        assert!(findings(&scan(clean), "python:S4828").is_empty());
    }
}
