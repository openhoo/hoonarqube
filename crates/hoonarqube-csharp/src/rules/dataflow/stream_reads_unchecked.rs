use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2674 — a stream read's return value says how many bytes
/// landed; discarding it invites stale-buffer bugs. Bound: only fully
/// discarded results are flagged — comparing the count correctly needs
/// value-flow this pass does not model.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(first_named_child)
        .filter(|expression| {
            expression.kind() == "invocation_expression"
                && STREAM_READ_METHODS.contains(&callee_name(*expression, source).unwrap_or(""))
        })
        .map(|call| {
            let method = callee_name(call, source).unwrap_or("Read");
            issue(
                language,
                "S2674",
                format!(
                    "Check the return value of the '{method}' call to see how many bytes were read."
                ),
                range_of(call, source),
            )
        })
        .collect()
}

/// Stream reads whose returned length matters.
const STREAM_READ_METHODS: [&str; 3] = ["Read", "ReadBlock", "ReadAsync"];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S2674";

    #[test]
    fn s2674_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2674_discarded_read_return_flags() {
        let report = analyze_default(
            "class C {\n    void M(System.IO.Stream stream) {\n        stream.Read(buffer, 0, len);\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s2674_read_block_counts_but_awaited_form_is_out_of_scope() {
        // `await stream.ReadAsync(...)` sits under an await_expression,
        // so this pass only sees bare invocation statements.
        let report = analyze_default(
            "class C {\n    async Task M(System.IO.Stream stream) {\n        reader.ReadBlock(sink, 0, len);\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s2674_checked_result_stays_clean() {
        let report = analyze_default(
            "class C {\n    void M(System.IO.Stream stream) {\n        int landed = stream.Read(buffer, 0, len);\n        Log(landed);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2674_unrelated_discarded_calls_are_ignored() {
        let report = analyze_default(
            "class C {\n    void M() {\n        Flush();\n        Seek(0);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s2674_read_inside_expression_is_out_of_scope() {
        let report = analyze_default(
            "class C {\n    void M(System.IO.Stream stream) {\n        Log(stream.Read(buffer, 0, len));\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
