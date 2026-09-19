use crate::engine::file_context::FileContext;
use crate::support::{flow_location, for_each_expr, issue_at};
use hoonarqube_ir::{Issue, IssueFlow};
use ruff_python_ast::{Expr, Operator};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S7943";
const MESSAGE: &str = "Template strings should not be concatenated with regular strings.";
const TEMPLATE_FLOW: &str = "Template string";
const REGULAR_FLOW: &str = "Regular string";

/// python:S7943 — PEP 750 prohibits `Template + str` concatenation: whether
/// the `str` should join the static parts or become an interpolation is
/// ambiguous, so the operation fails at runtime. Scope `MAIN`.
///
/// Mirrors `TemplateAndStrConcatenationCheck`: only `+` between two string
/// literals is flagged, exactly one of them a t-string (`t"..." + "..."` or
/// `"..." + t"..."`). Concatenating two t-strings or two regular strings is
/// legal and stays silent, as does concatenation with non-literal operands.
/// The issue anchors on the binary expression with each operand as a
/// labelled secondary location.
pub(crate) fn check_template_str_concatenation(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        for expr in crate::support::stmt_exprs(stmt) {
            for_each_expr(expr, &mut |node| {
                if let Expr::BinOp(binop) = node
                    && matches!(binop.op, Operator::Add)
                {
                    report_concat(&mut issues, binop, index, source);
                }
            });
        }
    }
    issues
}

fn report_concat(
    issues: &mut Vec<Issue>,
    binop: &ruff_python_ast::ExprBinOp,
    index: &LineIndex,
    source: &str,
) {
    let Some(left_template) = string_literal_kind(&binop.left) else {
        return;
    };
    let Some(right_template) = string_literal_kind(&binop.right) else {
        return;
    };
    if left_template == right_template {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, binop.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: vec![
            flow_location(
                if left_template {
                    TEMPLATE_FLOW
                } else {
                    REGULAR_FLOW
                },
                binop.left.range(),
                index,
                source,
            ),
            flow_location(
                if right_template {
                    TEMPLATE_FLOW
                } else {
                    REGULAR_FLOW
                },
                binop.right.range(),
                index,
                source,
            ),
        ],
    });
    issues.push(issue);
}

/// `Some(true)` for a t-string literal, `Some(false)` for a regular string
/// literal, `None` for anything else.
fn string_literal_kind(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::TString(_) => Some(true),
        Expr::StringLiteral(_) => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S7943";

    /// Sonar's own shape: a t-string concatenated with a regular string is
    /// flagged on the binary expression; wrapping the string in `Template()`
    /// is clean.
    #[test]
    fn s7943_flags_sonar_example() {
        let flagged = scan("template = t\"Hello \" + \"World\"\n");
        let hits = findings(&flagged, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 1);
        assert_eq!(hits[0].flows.len(), 1);
        assert_eq!(hits[0].flows[0].locations.len(), 2);
        let clean = scan("template = t\"Hello \" + Template(\"World\")\n");
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Both operand orders flag; same-kind and non-literal operands do not.
    #[test]
    fn s7943_operands() {
        let report = scan(concat!("a = \"x\" + t\"y\"\n", "b = t\"x\" + \"y\"\n",));
        assert_eq!(findings(&report, KEY).len(), 2);
        let clean = scan(concat!(
            "a = t\"x\" + t\"y\"\n",
            "b = \"x\" + \"y\"\n",
            "name = \"World\"\n",
            "c = t\"Hello \" + name\n",
            "d = t\"x\" - \"y\"\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }
}
