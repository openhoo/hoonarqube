use crate::support::for_each_function_def;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtFunctionDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1186 — empty functions -------------------------------------------
//
// Functions holding nothing but `pass`/`...` placeholders are flagged.
// `@abstractmethod`/`@overload` stubs are legitimate empty by contract; a
// docstring already fills the function and is not an empty body.

pub(crate) fn check_empty_functions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut visit = |function: &StmtFunctionDef, in_class_body: bool| {
        // The reference exempts the ABC decorator family by dotted suffix.
        let is_abstract = function.decorator_list.iter().any(|decorator| {
            decorator_name(&decorator.expression).is_some_and(|name| {
                name.split('.')
                    .any(|part| ABC_DECORATORS.contains(&part))
            })
        });
        if is_abstract {
            return;
        }
        // Only a lone `pass` body is empty; `...` and docstrings count as
        // content, and any comment inside the function or directly above it
        // explains the emptiness.
        if function.body.len() == 1
            && matches!(function.body[0], Stmt::Pass(_))
            && !function_has_comment(function, parsed)
        {
            issues.push(issue_at(
                "python:S1186",
                if in_class_body {
                    "Add a nested comment explaining why this method is empty, or complete the implementation."
                } else {
                    "Add a nested comment explaining why this function is empty, or complete the implementation."
                },
                function.name.range(),
                index,
                source,
            ));
        }
    };
    for_each_function_def(parsed.syntax().body.as_slice(), false, &mut visit);
    issues
}

/// ABC decorators that legitimately leave a method body empty.
const ABC_DECORATORS: [&str; 4] = [
    "abstractmethod",
    "abstractstaticmethod",
    "abstractproperty",
    "abstractclassmethod",
];

/// Dotted name of a decorator expression (`name` or `a.b.c`), `None` for
/// calls and other shapes.
fn decorator_name(expr: &ruff_python_ast::Expr) -> Option<&str> {
    match expr {
        ruff_python_ast::Expr::Name(name) => Some(name.id.as_str()),
        ruff_python_ast::Expr::Attribute(attribute) => Some(attribute.attr.as_str()),
        _ => None,
    }
}

/// Whether any comment token sits inside the function's range or in the gap
/// between the previous non-trivia token and the function start (comments
/// directly above `def`/decorators explain the empty body).
fn function_has_comment(
    function: &StmtFunctionDef,
    parsed: &Parsed<ModModule>,
) -> bool {
    let mut previous_end = ruff_text_size::TextSize::new(0);
    for token in parsed.tokens() {
        if token.range().start() >= function.range().start() {
            break;
        }
        if !token.kind().is_trivia() {
            previous_end = token.range().end();
        }
    }
    parsed.tokens().iter().any(|token| {
        token.kind() == ruff_python_ast::token::TokenKind::Comment
            && token.range().start() >= previous_end
            && token.range().end() <= function.range().end()
    })
}
