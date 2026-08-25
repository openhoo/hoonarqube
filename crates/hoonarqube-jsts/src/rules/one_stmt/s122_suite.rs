// Rule module s122_suite (generated).
use crate::support::LineIndex;
use crate::{JstsLanguage, check_class_methods, check_one};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{Declaration, ExportDefaultDeclarationKind, ModuleDeclaration, Statement};
use oxc_span::GetSpan;

/// Groups consecutive statements sharing a start line; every additional
/// statement on that line gets one issue, then nesting is walked.
pub(crate) fn check_suite(
    body: &[Statement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    let line_of = |stmt: &Statement<'_>| index.pos(GetSpan::span(stmt).start).line;

    let mut start = 0;
    while start < body.len() {
        let first_line = line_of(&body[start]);
        let mut end = start + 1;
        while end < body.len() && line_of(&body[end]) == first_line {
            end += 1;
        }
        for stmt in &body[start + 1..end] {
            issues.push(Issue {
                rule_key: format!("{}:S122", language.prefix()),
                message: "Only one statement per line is allowed.".to_string(),
                range: index.range(stmt.span()),
            });
        }
        for stmt in &body[start..end] {
            check_nested_bodies(stmt, index, language, issues);
        }
        start = end;
    }
}

fn check_nested_bodies(
    stmt: &Statement<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    // Concrete variants first; `Declaration` and `ModuleDeclaration` are
    // inherited variant groups on `Statement` in oxc 0.146, reached through
    // the generated `as_*` helpers in the final fallback arm.
    match stmt {
        Statement::BlockStatement(block) => {
            check_suite(block.body.as_slice(), index, language, issues);
        }
        Statement::IfStatement(statement) => {
            check_one(&statement.consequent, index, language, issues);
            if let Some(alternate) = &statement.alternate {
                check_one(alternate, index, language, issues);
            }
        }
        Statement::ForStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::ForInStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::ForOfStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::WhileStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::DoWhileStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::SwitchStatement(statement) => {
            for case in &statement.cases {
                check_suite(case.consequent.as_slice(), index, language, issues);
            }
        }
        Statement::TryStatement(statement) => {
            check_suite(statement.block.body.as_slice(), index, language, issues);
            if let Some(handler) = &statement.handler {
                check_suite(handler.body.body.as_slice(), index, language, issues);
            }
            if let Some(finalizer) = &statement.finalizer {
                check_suite(finalizer.body.as_slice(), index, language, issues);
            }
        }
        Statement::LabeledStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        Statement::WithStatement(statement) => {
            check_one(&statement.body, index, language, issues);
        }
        _ => {
            if let Some(declaration) = stmt.as_declaration() {
                match declaration {
                    Declaration::FunctionDeclaration(function) => {
                        if let Some(body) = &function.body {
                            check_suite(body.statements.as_slice(), index, language, issues);
                        }
                    }
                    Declaration::ClassDeclaration(class) => {
                        check_class_methods(&class.body.body, index, language, issues);
                    }
                    _ => {}
                }
            } else if let Some(ModuleDeclaration::ExportDefaultDeclaration(declaration)) =
                stmt.as_module_declaration()
            {
                match &declaration.declaration {
                    ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                        if let Some(body) = &function.body {
                            check_suite(body.statements.as_slice(), index, language, issues);
                        }
                    }
                    ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                        check_class_methods(&class.body.body, index, language, issues);
                    }
                    _ => {}
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s122_flags_extra_statements_sharing_one_line() {
        let findings = js_keys("let a = 1; let b = 2; let c = 3;\n");
        assert_eq!(count_key(&findings, "javascript:S122"), 2);
    }

    #[test]
    fn s122_allows_one_statement_per_line() {
        let findings = js_keys("let a = 1;\nlet b = 2;\n");
        assert_eq!(count_key(&findings, "javascript:S122"), 0);
    }

    #[test]
    fn s122_counts_each_additional_expression_statement() {
        let findings = js_keys("f(); g(); h(); i();\n");
        assert_eq!(count_key(&findings, "javascript:S122"), 3);
    }
}
