use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8520";
const MESSAGE: &str =
    "Use \"itertools.chain.from_iterable()\" instead of \"sum()\" to flatten or concatenate lists.";

/// python:S8520 — `sum(list_of_lists, [])` concatenates lists with quadratic
/// copying; `itertools.chain.from_iterable()` stays linear. The `start`
/// argument may arrive positionally or as the `start=` keyword and must be
/// the empty list literal `[]`; `list()`, tuples, and other start values
/// stay silent. The whole `sum(...)` call anchors the finding.
pub(crate) fn check_no_sum_empty_list_concat(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if !matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "sum") {
            continue;
        }
        let Some(start) = call.arguments.find_argument_value("start", 1) else {
            continue;
        };
        if !matches!(start, Expr::List(list) if list.elts.is_empty()) {
            continue;
        }
        issues.push(issue_at(RULE_KEY, MESSAGE, call.range(), index, source));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8520")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8520_flags_sonar_noncompliant_example() {
        // Sonar's own Noncompliant example; the whole call anchors.
        let flagged = found(concat!(
            "list_of_lists = [[1, 2], [3, 4], [5, 6]]\n",
            "result = sum(list_of_lists, [])\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Use \"itertools.chain.from_iterable()\" instead of \"sum()\" to flatten or concatenate lists."
        );
        assert_eq!(flagged[0].range.start, pos(2, 9));
        assert_eq!(flagged[0].range.end, pos(2, 31));
    }

    #[test]
    fn s8520_flags_keyword_start_and_nested_sites() {
        let flagged = found(concat!(
            "flat = sum(rows, start=[])\n",
            "total = sum([x] for x in rows) + sum(rows, [])\n",
        ));
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s8520_stays_silent_on_compliant_and_other_starts() {
        // Sonar's Compliant solution plus controls: numeric starts, non-empty
        // lists, `list()`, tuples, missing start, and non-`sum` calls.
        let clean = concat!(
            "import itertools\n",
            "result = list(itertools.chain.from_iterable(list_of_lists))\n",
            "total = sum(numbers, 0)\n",
            "seeded = sum(rows, [1])\n",
            "built = sum(rows, list())\n",
            "tupled = sum(rows, ())\n",
            "plain = sum(rows)\n",
            "other = combine(rows, [])\n",
        );
        assert!(found(clean).is_empty());
    }
}
