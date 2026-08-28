use crate::engine::file_context::FileContext;
use crate::support::for_each_attr_load;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// --- python:S4823 — using command line arguments is security-sensitive -------

pub(crate) fn check_s4823_command_line_arguments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_attr_load(parsed.syntax().body.as_slice(), "argv", |attr| {
        if matches!(attr.value.as_ref(), Expr::Name(name) if name.id.as_str() == "sys") {
            issues.push(issue_at(
                "python:S4823",
                "Make sure that command line arguments are used safely here.",
                TextRange::new(
                    attr.end() - TextSize::from(to_u32(attr.attr.len())),
                    attr.end(),
                ),
                index,
                source,
            ));
        }
    });
    for expr in &file_ctx.exprs {
        if let Expr::Name(name) = expr
            && name.id.as_str() == "argv"
        {
            issues.push(issue_at(
                "python:S4823",
                "Make sure that command line arguments are used safely here.",
                name.range(),
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
    fn s4823_flags_command_line_argument_access() {
        let flagged = "import sys\nprint(sys.argv[1])\nfrom sys import argv\nprint(argv[0])\n";
        assert_eq!(findings(&scan(flagged), "python:S4823").len(), 2);
        assert!(findings(&scan("print(sys.version)\n"), "python:S4823").is_empty());
    }
}
