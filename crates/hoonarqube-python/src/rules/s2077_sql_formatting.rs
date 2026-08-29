use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::sql_statement_shape;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

// --- python:S2077 — SQL queries built through string formatting ----------------

pub(crate) fn check_s2077_sql_formatting(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    // CE stays silent unless the formatted SQL actually reaches an execution
    // sink; formatting alone never raises.
    const EXECUTE_SINKS: [&str; 3] = ["execute", "executemany", "executescript"];
    if !file_ctx
        .calls
        .iter()
        .any(|call| EXECUTE_SINKS.contains(&called_name(&call.func).unwrap_or_default()))
    {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Some(range) = formatted_sql_range(expr, source) {
            issues.push(issue_at(
                "python:S2077",
                "Use parameterized queries instead of formatting SQL strings.",
                range,
                index,
                source,
            ));
        }
    }
    issues
}

fn formatted_sql_range(expr: &Expr, source: &str) -> Option<TextRange> {
    match expr {
        Expr::BinOp(binop) if matches!(binop.op, ruff_python_ast::Operator::Mod) => {
            let Expr::StringLiteral(literal) = binop.left.as_ref() else {
                return None;
            };
            is_sql_shape(&string_value_text(&literal.value)).then(|| expr.range())
        }
        Expr::Call(call) if !call.arguments.args.is_empty() => {
            let Expr::Attribute(attribute) = call.func.as_ref() else {
                return None;
            };
            let Expr::StringLiteral(literal) = attribute.value.as_ref() else {
                return None;
            };
            is_sql_shape(&string_value_text(&literal.value)).then(|| expr.range())
        }
        Expr::FString(_) => {
            let range = expr.range();
            let raw = source
                .get(range.start().to_usize()..range.end().to_usize())
                .unwrap_or_default();
            (raw.contains('{') && raw.contains('}') && is_sql_shape(raw)).then_some(range)
        }
        _ => None,
    }
}

fn is_sql_shape(text: &str) -> bool {
    sql_statement_shape(&text.to_lowercase())
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
