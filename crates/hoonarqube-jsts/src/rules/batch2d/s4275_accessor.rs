use super::collectors::{
    ClassAccessorCollector, accessor_has_matching_field, accessor_names_field,
};
use crate::support::RuleScope;
use oxc_ast::ast::{Expression, FunctionBody, SimpleAssignmentTarget, Statement};
use oxc_span::Span;
use std::collections::BTreeSet;

impl ClassAccessorCollector<'_> {
    /// `S4275`: accessors should touch the field their name declares, and a
    /// getter must return a value on every path. The field-name aspect
    /// requires a same-named data field to exist (field-existence gate)
    /// plus a single-statement body whose `this.<field>` reference points
    /// elsewhere; the getter-return aspect fires whenever control flow can
    /// complete the getter without a valued `return`.
    pub(crate) fn check_accessor(
        &mut self,
        name: Option<&str>,
        key_span: Span,
        is_setter: bool,
        body: Option<&FunctionBody<'_>>,
        fields: &BTreeSet<String>,
    ) {
        let Some(body) = body else {
            return;
        };
        if !is_setter {
            let flow = statements_flow(&body.statements);
            if flow.end || flow.bare {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4275",
                    "Refactor this getter to always return a value.",
                    key_span,
                );
            }
        }
        let Some(name) = name else {
            return;
        };
        if !accessor_has_matching_field(name, fields) {
            return;
        }
        if body.statements.len() != 1 {
            return;
        }
        let statement = &body.statements[0];
        let used_field = match (is_setter, statement) {
            (true, Statement::ExpressionStatement(expression_statement)) => {
                match &expression_statement.expression {
                    Expression::AssignmentExpression(assignment) => {
                        match assignment.left.as_simple_assignment_target() {
                            Some(SimpleAssignmentTarget::StaticMemberExpression(member)) => {
                                matches!(&member.object, Expression::ThisExpression(_))
                                    .then(|| member.property.name.as_str())
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                }
            }
            (false, Statement::ReturnStatement(return_statement)) => return_statement
                .argument
                .as_ref()
                .and_then(this_static_property_name),
            _ => None,
        };
        let Some(used_field) = used_field else {
            return;
        };
        if accessor_names_field(name, used_field) {
            return;
        }
        let message = if is_setter {
            format!("Verify that this setter assigns the \"{name}\" field.")
        } else {
            format!("Verify that this getter accesses the \"{name}\" field.")
        };
        self.sink
            .emit_span(RuleScope::Both, "S4275", &message, key_span);
    }
}

/// How control may leave a statement sequence (`S4275` getter-return
/// aspect): `end` — reach the end and continue; `brk` — exit the enclosing
/// loop or switch; `bare` — leave the function through a valueless
/// `return`.
#[derive(Default, Clone, Copy)]
struct StatementFlow {
    end: bool,
    brk: bool,
    bare: bool,
}

impl StatementFlow {
    /// Ordinary statements fall off their end and continue.
    const END: StatementFlow = StatementFlow {
        end: true,
        brk: false,
        bare: false,
    };

    /// Alternative paths: either side's exits are reachable.
    fn union(self, other: StatementFlow) -> StatementFlow {
        StatementFlow {
            end: self.end || other.end,
            brk: self.brk || other.brk,
            bare: self.bare || other.bare,
        }
    }

    /// Sequential composition: `other` runs only where `self` ends.
    fn then(self, other: StatementFlow) -> StatementFlow {
        StatementFlow {
            end: self.end && other.end,
            brk: self.brk || (self.end && other.brk),
            bare: self.bare || (self.end && other.bare),
        }
    }
}

/// Flow of a statement list: each statement is reachable only while the
/// previous one can end.
fn statements_flow(statements: &[Statement<'_>]) -> StatementFlow {
    let mut flow = StatementFlow::END;
    for statement in statements {
        flow = flow.then(statement_flow(statement));
    }
    flow
}

/// Flow of one statement. `return`/`throw` never end; a bare `return`
/// additionally exits the function without a value. Nested function units
/// are expressions or declarations and are never entered.
fn statement_flow(statement: &Statement<'_>) -> StatementFlow {
    match statement {
        Statement::ReturnStatement(return_statement) => StatementFlow {
            end: false,
            brk: false,
            bare: return_statement.argument.is_none(),
        },
        Statement::ThrowStatement(_) => StatementFlow::default(),
        Statement::BreakStatement(_) | Statement::ContinueStatement(_) => StatementFlow {
            end: false,
            brk: true,
            bare: false,
        },
        Statement::BlockStatement(block) => statements_flow(&block.body),
        Statement::IfStatement(if_statement) => {
            let consequent = statement_flow(&if_statement.consequent);
            match &if_statement.alternate {
                Some(alternate) => consequent.union(statement_flow(alternate)),
                None => consequent.union(StatementFlow::END),
            }
        }
        Statement::SwitchStatement(switch) => switch_flow(switch),
        Statement::TryStatement(try_statement) => try_flow(try_statement),
        Statement::WhileStatement(while_statement) => loop_flow(
            &while_statement.body,
            !is_constant_true(&while_statement.test),
        ),
        Statement::DoWhileStatement(do_while) => {
            loop_flow(&do_while.body, !is_constant_true(&do_while.test))
        }
        Statement::ForStatement(for_statement) => loop_flow(
            &for_statement.body,
            for_statement
                .test
                .as_ref()
                .is_some_and(|test| !is_constant_true(test)),
        ),
        Statement::ForInStatement(for_in) => loop_flow(&for_in.body, true),
        Statement::ForOfStatement(for_of) => loop_flow(&for_of.body, true),
        Statement::LabeledStatement(labeled) => statement_flow(&labeled.body),
        _ => StatementFlow::END,
    }
}

/// A switch completes when no case matches without a `default`, or when a
/// matched case's tail can end or `break` out.
fn switch_flow(switch: &oxc_ast::ast::SwitchStatement<'_>) -> StatementFlow {
    let mut flow = StatementFlow {
        end: !switch.cases.iter().any(|case| case.test.is_none()),
        brk: false,
        bare: false,
    };
    for case in &switch.cases {
        let case_flow = statements_flow(&case.consequent);
        flow = flow.union(StatementFlow {
            end: case_flow.end || case_flow.brk,
            brk: false,
            bare: case_flow.bare,
        });
    }
    flow
}

/// A `try` completes where its block or handler completes; the finalizer
/// always runs, so its exits are always reachable and it must end for the
/// `try` to end.
fn try_flow(try_statement: &oxc_ast::ast::TryStatement<'_>) -> StatementFlow {
    let mut flow = statements_flow(&try_statement.block.body);
    if let Some(handler) = &try_statement.handler {
        flow = flow.union(statements_flow(&handler.body.body));
    }
    if let Some(finalizer) = &try_statement.finalizer {
        let finalizer_flow = statements_flow(&finalizer.body);
        flow = StatementFlow {
            end: flow.end && finalizer_flow.end,
            brk: flow.brk || finalizer_flow.brk,
            bare: flow.bare || finalizer_flow.bare,
        };
    }
    flow
}

/// A loop ends through its condition (when it can be false) or a `break`;
/// `continue` and the body's own exits stay inside the loop.
fn loop_flow(body: &Statement<'_>, condition_can_end: bool) -> StatementFlow {
    let body_flow = statement_flow(body);
    StatementFlow {
        end: condition_can_end || body_flow.brk,
        brk: false,
        bare: body_flow.bare,
    }
}

/// `true` and non-zero numeric literals make a loop condition constant.
fn is_constant_true(expression: &Expression<'_>) -> bool {
    match expression {
        Expression::BooleanLiteral(literal) => literal.value,
        Expression::NumericLiteral(literal) => literal.value != 0.0,
        _ => false,
    }
}

/// Name of a direct `this.<field>` member expression (`S4275`); member
/// chains, computed accessors, and non-`this` receivers have none.
fn this_static_property_name<'a>(expression: &'a Expression<'a>) -> Option<&'a str> {
    match expression {
        Expression::StaticMemberExpression(member) => {
            matches!(&member.object, Expression::ThisExpression(_))
                .then(|| member.property.name.as_str())
        }
        _ => None,
    }
}
