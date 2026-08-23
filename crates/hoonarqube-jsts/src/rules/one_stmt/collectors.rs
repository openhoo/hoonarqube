// Residual rule machinery for 'one_stmt' (extracted from lib.rs).
use crate::JstsLanguage;
use crate::rules::one_stmt::s122_suite::check_suite;
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use oxc_ast::ast::{ClassElement, Statement};

pub(crate) fn check_one(
    stmt: &Statement<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    check_suite(std::slice::from_ref(stmt), index, language, issues);
}

pub(crate) fn check_class_methods(
    elements: &[ClassElement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
    issues: &mut Vec<Issue>,
) {
    for element in elements {
        if let ClassElement::MethodDefinition(method) = element
            && let Some(body) = &method.value.body
        {
            check_suite(body.statements.as_slice(), index, language, issues);
        }
    }
}
