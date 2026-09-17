use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7498 — literal syntax for empty collections ----------------------

pub(crate) fn check_empty_collection_constructors(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Call(call) = expr else { continue };
        // Sonar type-checks the callee against the builtin constructors, so
        // `list`/`tuple`/`dict` must be the bare callee name (`set()` has no
        // literal equivalent and the reference never flags it); instance
        let Expr::Name(callee) = call.func.as_ref() else {
            continue;
        };
        if !call.arguments.args.is_empty() {
            continue;
        }
        let name = callee.id.as_str();
        let literal_shaped = matches!(name, "list" | "tuple" | "dict")
            && (call.arguments.keywords.is_empty()
                || name == "dict"
                    && call
                        .arguments
                        .keywords
                        .iter()
                        .all(|keyword| keyword.arg.is_some()));
        if literal_shaped {
            issues.push(issue_at(
                "python:S7498",
                "Replace this call with the equivalent collection literal.",
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
    fn s7498_spares_attribute_method_calls() {
        // `ev.set()` is an instance method call, not a builtin constructor.
        let flagged = scan(concat!(
            "class Event:\n",
            "    def set(self):\n",
            "        return None\n",
            "\n",
            "ev = Event()\n",
            "ev.set()\n",
            "counts = dict(a=1)\n",
        ));
        let found = findings(&flagged, "python:S7498");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 7);
    }
}
