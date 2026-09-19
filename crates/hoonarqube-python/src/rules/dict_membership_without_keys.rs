use crate::engine::file_context::FileContext;
use crate::rules::items_only_keys_needed::receiver_is_known_dict;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{CmpOp, Expr};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8521";
const MESSAGE: &str = "Remove this unnecessary \"keys()\" call.";

/// python:S8521 — `key in dict.keys()` spells out what `key in dict` already
/// means; the explicit `.keys()` call is redundant. Only `in` comparisons
/// qualify — the reference subscribes to `in` expressions, so `not in`
/// stays silent — and the receiver must provably hold a dict (a dict
/// literal, a `dict(...)` call, or a name assigned exactly one of those).
/// The `.keys()` call anchors the finding.
pub(crate) fn check_dict_membership_without_keys(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        for (op, comparator) in compare.ops.iter().zip(&compare.comparators) {
            if *op != CmpOp::In {
                continue;
            }
            let Expr::Call(call) = comparator else {
                continue;
            };
            if !call.arguments.is_empty() {
                continue;
            }
            let Expr::Attribute(attribute) = call.func.as_ref() else {
                continue;
            };
            if attribute.attr.as_str() != "keys"
                || !receiver_is_known_dict(&attribute.value, file_ctx)
            {
                continue;
            }
            issues.push(issue_at(RULE_KEY, MESSAGE, call.range(), index, source));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8521")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8521_flags_sonar_noncompliant_example() {
        // Sonar's own Noncompliant example; the `.keys()` call anchors.
        let flagged = found(concat!(
            "my_dict = {'a': 1, 'b': 2, 'c': 3}\n",
            "if 'a' in my_dict.keys():\n",
            "    print('Found')\n",
        ));
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Remove this unnecessary \"keys()\" call."
        );
        assert_eq!(flagged[0].range.start, pos(2, 10));
        assert_eq!(flagged[0].range.end, pos(2, 24));
    }

    #[test]
    fn s8521_flags_literal_and_dict_call_receivers() {
        let flagged = found(concat!(
            "hit = 'a' in {'a': 1}.keys()\n",
            "other = 'b' in dict(a=1).keys()\n",
        ));
        assert_eq!(flagged.len(), 2);
    }

    #[test]
    fn s8521_stays_silent_on_compliant_and_unknown_receivers() {
        // Sonar's Compliant solution plus controls: `not in`, unproven
        // receivers, `.keys()` with arguments, and non-`keys` calls.
        let clean = concat!(
            "my_dict = {'a': 1, 'b': 2, 'c': 3}\n",
            "if 'a' in my_dict:\n",
            "    print('Found')\n",
            "if 'a' not in my_dict.keys():\n",
            "    print('Missing')\n",
            "def f(param):\n",
            "    return 'a' in param.keys()\n",
            "def g(param):\n",
            "    param = {}\n",
            "    param = other\n",
            "    return 'a' in param.keys()\n",
            "with_args = 'a' in my_dict.keys('x')\n",
            "values = 'a' in my_dict.values()\n",
        );
        assert!(found(clean).is_empty());
    }
}
