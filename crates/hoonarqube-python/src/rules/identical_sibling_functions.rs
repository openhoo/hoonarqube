use crate::support::flag_identical_function_pairs;
use crate::support::for_each_stmt;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_identical_sibling_functions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let module_body = parsed.syntax().body.as_slice();
    let mut issues = Vec::new();
    flag_identical_function_pairs(module_body, &mut issues, index, source);
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::ClassDef(class) = stmt {
            flag_identical_function_pairs(class.body.as_slice(), &mut issues, index, source);
        }
    });
    issues
}
