use crate::support::child_exprs;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::FStringPart;
use ruff_python_ast::InterpolatedStringElement;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6799 — deeply nested f-strings ------------------------------------
//
// An f-string inside another f-string's replacement field already hurts
// readability; three or more levels (`f"{f"{f"{x}"}"}"`) cross the line.
// Every f-string whose nesting depth reaches 3 is flagged.

pub(crate) fn check_f_string_nesting(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visit = |stmt: &ruff_python_ast::Stmt| {
        for expr in stmt_exprs(stmt) {
            visit_expr(expr, 0, &mut issues, index, source);
        }
    };
    for_each_stmt(parsed.syntax().body.as_slice(), &mut visit);
    issues
}

fn visit_expr(expr: &Expr, depth: u32, issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    match expr {
        Expr::FString(f_string) => {
            let nested = depth + 1;
            if nested >= 3 {
                issues.push(issue_at(
                    "python:S6799",
                    "Reduce the nesting depth of this f-string.",
                    f_string.range(),
                    index,
                    source,
                ));
            }
            for part in &f_string.value {
                if let FStringPart::FString(inner) = part {
                    visit_elements(&inner.elements, nested, issues, index, source);
                }
            }
        }
        other => {
            for child in child_exprs(other) {
                visit_expr(child, depth, issues, index, source);
            }
        }
    }
}

/// Replacement fields (and their format specs) carry the next level's
/// expressions without changing the enclosing f-string's own range.
fn visit_elements(
    elements: &ruff_python_ast::InterpolatedStringElements,
    depth: u32,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    for element in elements {
        if let InterpolatedStringElement::Interpolation(interpolation) = element {
            visit_expr(&interpolation.expression, depth, issues, index, source);
            if let Some(spec) = &interpolation.format_spec {
                visit_elements(&spec.elements, depth, issues, index, source);
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6799_flags_f_strings_nested_three_levels_deep() {
        let flagged = scan("deep = f\"{f\"{f\"{x}\"}\"}\"\n");
        assert_eq!(findings(&flagged, "python:S6799").len(), 1);
    }

    #[test]
    fn s6799_spares_single_and_double_level_nesting() {
        for clean in [
            "flat = f\"value {x}\"\n",
            "once = f\"outer {f\"inner {x}\"} end\"\n",
            "plain = \"no interpolation at all\"\n",
        ] {
            assert!(findings(&scan(clean), "python:S6799").is_empty());
        }
    }
}
