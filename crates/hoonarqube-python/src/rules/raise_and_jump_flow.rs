use crate::context::FlowState;
use crate::engine::scope::RaiseContext;
use crate::support::scan_flow_statements;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_raise_and_jump_flow(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    scan_flow_statements(
        parsed.syntax().body.as_slice(),
        FlowState {
            context: RaiseContext::Outside,
            finally_depth: 0,
            loop_depth: 0,
        },
        &mut issues,
        index,
        source,
    );
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5704_and_s5747_classify_bare_raise_by_context() {
        let in_finally = scan(
            "def f():\n    try:\n        work()\n    finally:\n        cleanup()\n        raise\n",
        );
        assert_eq!(findings(&in_finally, "python:S5704").len(), 1);
        let outside = scan("def f():\n    if ready:\n        raise\n");
        assert_eq!(findings(&outside, "python:S5747").len(), 1);
        let in_except = scan("try:\n    work()\nexcept ValueError:\n    raise\n");
        assert!(findings(&in_except, "python:S5704").is_empty());
        assert!(findings(&in_except, "python:S5747").is_empty());
    }

    #[test]
    fn s5747_exempts_bare_raise_in_functions_called_from_except_or_finally() {
        // Issue #637 — Sonar's RaiseOutsideExceptCheck exempts a bare
        // `raise` inside a function whose symbol is called within an
        // except/finally clause: the raise re-throws the handled error.
        let called_from_except = scan(
            "def handle_uncaught(request, exc_info):\n    if True:\n        raise\n\ndef outer():\n    try:\n        risky()\n    except Exception:\n        handle_uncaught(req, info)\n",
        );
        assert!(findings(&called_from_except, "python:S5747").is_empty());
        let called_from_finally = scan(
            "def reraise():\n    raise\n\ndef outer():\n    try:\n        risky()\n    finally:\n        reraise()\n",
        );
        assert!(findings(&called_from_finally, "python:S5747").is_empty());
        // A bare raise in a function never called from an except/finally
        // clause stays flagged, even alongside an exempted function.
        let not_called = scan(
            "def handle_uncaught(request, exc_info):\n    raise\n\ndef other():\n    raise\n\ndef outer():\n    try:\n        risky()\n    except Exception:\n        handle_uncaught(req, info)\n",
        );
        let hits = findings(&not_called, "python:S5747");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 5);
    }

    #[test]
    fn s1143_flags_jump_statements_inside_finally() {
        let flagged = scan("def f():\n    try:\n        load()\n    finally:\n        return 1\n");
        assert_eq!(findings(&flagged, "python:S1143").len(), 1);
        let clean = "def f():\n    try:\n        load()\n    finally:\n        release()\n";
        assert!(findings(&scan(clean), "python:S1143").is_empty());
    }

    #[test]
    fn s1716_flags_break_continue_without_enclosing_loop() {
        assert_eq!(
            findings(&scan("def f():\n    break\n"), "python:S1716").len(),
            1
        );
        let clean = "for _ in xs:\n    break\n";
        assert!(findings(&scan(clean), "python:S1716").is_empty());
    }
}
