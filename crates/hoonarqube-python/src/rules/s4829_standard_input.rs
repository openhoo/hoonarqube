use crate::engine::file_context::FileContext;
use crate::support::call_path_matches;
use crate::support::is_call_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4829 — reading the Standard Input is security-sensitive ---------

pub(crate) fn check_s4829_standard_input(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const STDIN_READERS: [&str; 3] = [
        "sys.stdin.read",
        "sys.stdin.readline",
        "sys.stdin.readlines",
    ];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let reads_input = is_call_method(call, "input")
            && matches!(call.func.as_ref(), Expr::Name(_))
            || call_path_matches(call, &STDIN_READERS, &[], &[]);
        if reads_input {
            let range = if matches!(call.func.as_ref(), Expr::Name(_)) {
                call.range()
            } else {
                call.func.range()
            };
            issues.push(issue_at(
                "python:S4829",
                "Make sure that reading the standard input is safe here.",
                range,
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
    fn s4829_flags_standard_input_reads() {
        let flagged = "name = input()\ndata = sys.stdin.read()\n";
        assert_eq!(findings(&scan(flagged), "python:S4829").len(), 2);
        assert!(
            findings(
                &scan("sys.stdout.write(\"x\")\nsys.stderr.flush()\n"),
                "python:S4829"
            )
            .is_empty()
        );
    }
}
