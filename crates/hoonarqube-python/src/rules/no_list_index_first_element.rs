use crate::engine::file_context::FileContext;
use crate::support::int_literal_value;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8519";
const MESSAGE: &str =
    "Replace \"list(...)[0]\" with \"next(iter(...))\" to avoid materializing the entire iterable.";

/// python:S8519 — `list(iterable)[0]` builds the whole list to read one
/// element; `next(iter(iterable))` is O(1). Only the `list` callee anchors
/// the finding, and only a single plain argument qualifies: `list()` with
/// zero or several arguments, starred arguments, and non-`list` receivers
/// stay silent.
pub(crate) fn check_no_list_index_first_element(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Subscript(subscript) = expr else {
            continue;
        };
        // A tuple slice (`x[0, 1]`) is not a single index; only a bare `0`.
        if int_literal_value(&subscript.slice) != Some(0) {
            continue;
        }
        let Expr::Call(call) = subscript.value.as_ref() else {
            continue;
        };
        if !matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "list")
            || !single_plain_argument(call)
        {
            continue;
        }
        issues.push(issue_at(
            RULE_KEY,
            MESSAGE,
            call.func.range(),
            index,
            source,
        ));
    }
    issues
}

/// Whether the call carries exactly one argument and that argument is a
/// regular (non-starred) positional or a named keyword value.
fn single_plain_argument(call: &ruff_python_ast::ExprCall) -> bool {
    match (
        call.arguments.args.as_ref(),
        call.arguments.keywords.as_slice(),
    ) {
        ([arg], []) => !matches!(arg, Expr::Starred(_)),
        ([], [keyword]) => keyword.arg.is_some(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8519")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8519_flags_sonar_noncompliant_example() {
        // Sonar's own Noncompliant example; the finding anchors the `list`
        // callee, not the whole subscript.
        let flagged = found(concat!(
            "def get_first_user(users):\n",
            "    return list(users)[0]\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Replace \"list(...)[0]\" with \"next(iter(...))\" to avoid materializing the entire iterable."
        );
        assert_eq!(flagged[0].range.start, pos(2, 11));
        assert_eq!(flagged[0].range.end, pos(2, 15));
    }

    #[test]
    fn s8519_flags_keyword_and_generator_arguments() {
        let flagged = found(concat!(
            "first = list(iterable=users)[0]\n",
            "head = list(x * 2 for x in stream)[0]\n",
        ));
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s8519_stays_silent_on_compliant_and_other_shapes() {
        // Sonar's Compliant solution plus controls: other indexes, slices,
        // zero/multi/starred arguments, and non-`list` receivers.
        let clean = concat!(
            "def get_first_user(users):\n",
            "    return next(iter(users))\n",
            "second = list(users)[1]\n",
            "tail = list(users)[-1]\n",
            "window = list(users)[0:2]\n",
            "pair = list(users)[0, 1]\n",
            "empty = list()[0]\n",
            "spread = list(*users)[0]\n",
            "multi = list(a, b)[0]\n",
            "plain = users[0]\n",
            "other = tuple(users)[0]\n",
        );
        assert!(found(clean).is_empty());
    }
}
