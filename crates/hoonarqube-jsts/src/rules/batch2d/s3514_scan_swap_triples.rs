// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::support::RuleScope;
use crate::support::assignment_target_name;
use crate::support::binding_identifier_name;
use crate::support::identifier_name;
use crate::support::unparenthesized;
use oxc_ast::ast::AssignmentExpression;
use oxc_ast::ast::AssignmentOperator;
use oxc_ast::ast::Expression;
use oxc_ast::ast::Statement;
use oxc_span::GetSpan;

/// The plain `=` assignment expression of an expression statement, if any
/// (`S3514`).
pub(crate) fn swap_assignment<'a>(
    statement: &'a Statement<'a>,
) -> Option<&'a AssignmentExpression<'a>> {
    match statement {
        Statement::ExpressionStatement(expression_statement) => {
            match unparenthesized(&expression_statement.expression) {
                Expression::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign =>
                {
                    Some(assignment)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// The `temp = saved` seed of a swap triple: either a plain assignment
/// statement or a single-declarator declaration (`let t = a;`) with plain
/// identifier sides (`S3514`).
pub(crate) fn swap_seed<'a>(statement: &'a Statement<'a>) -> Option<(&'a str, &'a str)> {
    match statement {
        Statement::ExpressionStatement(expression_statement) => {
            match unparenthesized(&expression_statement.expression) {
                Expression::AssignmentExpression(assignment)
                    if assignment.operator == AssignmentOperator::Assign =>
                {
                    Some((
                        assignment_target_name(&assignment.left)?,
                        identifier_name(&assignment.right)?,
                    ))
                }
                _ => None,
            }
        }
        Statement::VariableDeclaration(declaration) => {
            let [declarator] = declaration.declarations.as_slice() else {
                return None;
            };
            let name = binding_identifier_name(&declarator.id)?;
            Some((name, identifier_name(declarator.init.as_ref()?)?))
        }
        _ => None,
    }
}

impl EsIdiomCollector<'_> {
    /// `S3514`: consecutive `t = a; … ; a = t` statements hide a swap that
    /// destructuring expresses directly.
    pub(crate) fn scan_swap_triples(&mut self, statements: &[Statement<'_>]) {
        for window in statements.windows(3) {
            // First saves `saved` into `temp`, either through an assignment
            // or a single declarator; the third restores it.
            let Some((temp, saved)) = swap_seed(&window[0]) else {
                continue;
            };
            let Some(third) = swap_assignment(&window[2]) else {
                continue;
            };
            if identifier_name(&third.right) != Some(temp) {
                continue;
            }
            let Some(counterpart) = assignment_target_name(&third.left) else {
                continue;
            };
            let Some(middle) = swap_assignment(&window[1]) else {
                continue;
            };
            let links_saved_to_counterpart = (assignment_target_name(&middle.left) == Some(saved)
                && identifier_name(&middle.right) == Some(counterpart))
                || (assignment_target_name(&middle.left) == Some(counterpart)
                    && identifier_name(&middle.right) == Some(saved));
            if counterpart != temp && links_saved_to_counterpart {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S3514",
                    "Swap these variables with destructuring instead of this temporary.",
                    window[0].span(),
                );
            }
        }
    }
}
