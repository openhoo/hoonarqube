use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::sql_statement_shape;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2077 — SQL queries built through string formatting ----------------

pub(crate) fn check_s2077_sql_formatting(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    // CE stays silent unless the formatted SQL actually reaches an execution
    // sink; formatting alone never raises.
    const EXECUTE_SINKS: [&str; 3] = ["execute", "executemany", "executescript"];
    let mut has_sink = false;
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        has_sink |= EXECUTE_SINKS.contains(&called_name(&call.func).unwrap_or_default());
    });
    if !has_sink {
        return Vec::new();
    }
    let mut issues = Vec::new();
    let sql_shape = |text: &str| sql_statement_shape(&text.to_lowercase());
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::BinOp(binop) => {
            let sql_left = match binop.left.as_ref() {
                Expr::StringLiteral(literal) => sql_shape(&string_value_text(&literal.value)),
                _ => false,
            };
            if matches!(binop.op, ruff_python_ast::Operator::Mod) && sql_left {
                issues.push(issue_at(
                    "python:S2077",
                    "Use parameterized queries instead of formatting SQL strings.",
                    expr.range(),
                    index,
                    source,
                ));
            }
        }
        Expr::Call(call) => {
            let format_receiver = match call.func.as_ref() {
                Expr::Attribute(attribute) => match attribute.value.as_ref() {
                    Expr::StringLiteral(literal) => Some(string_value_text(&literal.value)),
                    _ => None,
                },
                _ => None,
            };
            if !call.arguments.args.is_empty()
                && format_receiver.is_some_and(|text| sql_shape(&text))
            {
                issues.push(issue_at(
                    "python:S2077",
                    "Use parameterized queries instead of formatting SQL strings.",
                    call.range(),
                    index,
                    source,
                ));
            }
        }
        Expr::FString(_) => {
            let range = expr.range();
            let raw = source
                .get(range.start().to_usize()..range.end().to_usize())
                .unwrap_or_default();
            if raw.contains('{') && raw.contains('}') && sql_shape(&raw.to_lowercase()) {
                issues.push(issue_at(
                    "python:S2077",
                    "Use parameterized queries instead of formatting SQL strings.",
                    range,
                    index,
                    source,
                ));
            }
        }
        _ => {}
    });
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s2077_flags_formatted_sql_reaching_execute() {
        let flagged = concat!(
            "q = \"SELECT * FROM t WHERE id=%s\" % uid\n",
            "q2 = \"SELECT * FROM u WHERE n='{}'\".format(name)\n",
            "cursor.execute(q)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2077").len(), 2);
        // Formatting without any execution sink stays silent (CE parity).
        let no_sink = concat!(
            "q = \"SELECT * FROM t WHERE id=%s\" % uid\n",
            "q2 = \"SELECT * FROM u WHERE n='{}'\".format(name)\n",
            "q3 = f\"SELECT * FROM t WHERE id={uid}\"\n"
        );
        assert!(findings(&scan(no_sink), "python:S2077").is_empty());
        let clean = concat!(
            "cursor.execute(\"SELECT * FROM t\")\n",
            "msg = \"hi %s\" % name\n"
        );
        assert!(findings(&scan(clean), "python:S2077").is_empty());
    }
}
