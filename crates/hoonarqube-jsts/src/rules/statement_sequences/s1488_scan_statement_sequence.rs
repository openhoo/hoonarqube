// Rule module s1488_scan_statement_sequence (generated).
use crate::support::{IssueSink, RuleScope, binding_identifier_name, identifier_name};
use oxc_ast::ast::{Declaration, Statement};
use oxc_span::GetSpan;

/// Scans one statement list for `S1763` (the first statement after an
/// unconditional jump is unreachable) and `S1488` (a sole variable declarator
/// immediately returned or thrown under its own name).
pub(crate) fn scan_statement_sequence(sink: &mut IssueSink<'_>, statements: &[Statement<'_>]) {
    let mut jumped = false;
    for statement in statements {
        if jumped {
            sink.emit_span(
                RuleScope::Both,
                "S1763",
                "Remove this unreachable code.",
                statement.span(),
            );
            break;
        }
        jumped = statement_ends_with_jump(statement);
    }

    for pair in statements.windows(2) {
        let Some(Declaration::VariableDeclaration(variables)) = pair[0].as_declaration() else {
            continue;
        };
        if variables.declarations.len() != 1 || variables.declarations[0].init.is_none() {
            continue;
        }
        let declarator = &variables.declarations[0];
        let Some(name) = binding_identifier_name(&declarator.id) else {
            continue;
        };
        let message = match &pair[1] {
            Statement::ReturnStatement(returned) => {
                let returned_name = returned.argument.as_ref().and_then(identifier_name);
                (returned_name == Some(name)).then(|| {
                    format!(
                        "Immediately return this expression instead of assigning it to '{name}'."
                    )
                })
            }
            Statement::ThrowStatement(thrown) => (identifier_name(&thrown.argument) == Some(name))
                .then(|| {
                    format!(
                        "Immediately throw this expression instead of assigning it to '{name}'."
                    )
                }),
            _ => None,
        };
        if let Some(message) = message {
            sink.emit_span(RuleScope::Both, "S1488", &message, declarator.span());
        }
    }
}

/// Whether a statement terminates unconditionally for `S128`: a direct
/// jump, a block whose last statement jumps, or an `if/else` where both
/// branches jump.
pub(crate) fn statement_ends_with_jump(stmt: &Statement<'_>) -> bool {
    match stmt {
        Statement::BreakStatement(_)
        | Statement::ContinueStatement(_)
        | Statement::ReturnStatement(_)
        | Statement::ThrowStatement(_) => true,
        Statement::BlockStatement(block) => block.body.last().is_some_and(statement_ends_with_jump),
        Statement::IfStatement(if_statement) => {
            statement_ends_with_jump(&if_statement.consequent)
                && if_statement
                    .alternate
                    .as_ref()
                    .is_some_and(statement_ends_with_jump)
        }
        _ => false,
    }
}
