// Rule module s1488_scan_statement_sequence (generated).
use crate::rules::shared::statement_ends_with_jump;
use crate::support::{IssueSink, RuleScope, binding_identifier_name, identifier_name};
use oxc_ast::ast::{Declaration, Statement, VariableDeclarationKind};
use oxc_span::GetSpan;

/// Scans one statement list for `S1763` (the first statement after an
/// unconditional jump is unreachable) and `S1488` (a sole variable declarator
/// immediately returned or thrown under its own name).
pub(crate) fn scan_statement_sequence(sink: &mut IssueSink<'_>, statements: &[Statement<'_>]) {
    let mut jumped = false;
    for statement in statements {
        // Statements ESLint `no-unreachable` never registers (hoisted
        // function declarations, imports, type-only declarations, bare
        // `var`s, empty statements) stay transparent: they are neither
        // reported nor do they consume the first-unreachable slot.
        if statement_is_transparent_to_reachability(statement) {
            continue;
        }
        if jumped {
            sink.emit_span(
                RuleScope::Both,
                "S1763",
                "Unreachable code.",
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
                        "Immediately return this expression instead of assigning it to the temporary variable \"{name}\"."
                    )
                })
            }
            Statement::ThrowStatement(thrown) => (identifier_name(&thrown.argument) == Some(name))
                .then(|| {
                    format!(
                        "Immediately throw this expression instead of assigning it to the temporary variable \"{name}\"."
                    )
                }),
            _ => None,
        };
        if let Some(message) = message {
            sink.emit_span(
                RuleScope::Both,
                "S1488",
                &message,
                declarator
                    .init
                    .as_ref()
                    .map_or(declarator.span(), GetSpan::span),
            );
        }
    }
}

/// Whether `no-unreachable` treats the statement as invisible: hoisted
/// function declarations, `import` declarations, TypeScript-only
/// declarations, `var` declarations without any initializer, and empty
/// statements are never reported and never break the unreachable run.
fn statement_is_transparent_to_reachability(statement: &Statement<'_>) -> bool {
    match statement {
        Statement::EmptyStatement(_)
        | Statement::ImportDeclaration(_)
        | Statement::TSExportAssignment(_) => true,
        _ => match statement.as_declaration() {
            Some(Declaration::VariableDeclaration(declaration)) => {
                declaration.kind == VariableDeclarationKind::Var
                    && declaration
                        .declarations
                        .iter()
                        .all(|declarator| declarator.init.is_none())
            }
            Some(Declaration::ClassDeclaration(_)) | None => false,
            Some(_) => true,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1763_flags_first_statement_after_unconditional_jump() {
        let findings = js_keys("function f() {\n  return 1;\n  console.log(2);\n}\n");
        assert_eq!(count_key(&findings, "javascript:S1763"), 1);
    }

    #[test]
    fn s1763_allows_hoisted_function_declaration_after_return() {
        let findings = js_keys(
            "function transform(source) {\n  return applyEdits(source);\n\n  function applyEdits(s) {\n    return s.trim();\n  }\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S1763"), 0);
    }

    #[test]
    fn s1763_still_flags_non_declaration_after_transparent_statements() {
        // A hoisted function declaration must not consume the
        // first-unreachable slot: the expression statement after it is the
        // first genuinely unreachable statement.
        let findings =
            js_keys("function f() {\n  return 1;\n  function hoisted() {}\n  console.log(2);\n}\n");
        assert_eq!(count_key(&findings, "javascript:S1763"), 1);
    }

    #[test]
    fn s1763_allows_bare_var_and_type_declarations_but_flags_initialized_var() {
        let bare_var = js_keys("function f() {\n  return 1;\n  var x;\n}\n");
        assert_eq!(count_key(&bare_var, "javascript:S1763"), 0);

        let initialized = js_keys("function f() {\n  return 1;\n  var x = 2;\n}\n");
        assert_eq!(count_key(&initialized, "javascript:S1763"), 1);

        let type_only = ts_keys(
            "function f(): number {\n  return 1;\n  interface Later { x: number }\n  type T = number;\n}\n",
        );
        assert_eq!(count_key(&type_only, "typescript:S1763"), 0);
    }

    #[test]
    fn s1488_flags_sole_declarator_immediately_thrown_under_own_name() {
        let findings = js_keys("function g() {\n  const e = new Error(\"boom\");\n  throw e;\n}\n");
        assert_eq!(count_key(&findings, "javascript:S1488"), 1);
    }

    #[test]
    fn s1488_allows_transformed_returns_and_direct_throws() {
        let findings = js_keys(
            "function h(a) {\n  const b = wrap(a);\n  return b + 1;\n}\nfunction i() {\n  throw new Error(\"x\");\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S1488"), 0);
        assert_eq!(count_key(&findings, "javascript:S1763"), 0);
    }

    #[test]
    fn s1763_requires_both_if_branches_to_jump_before_dead_code() {
        let both = js_keys(
            "function j(c) {\n  if (c) { return 1; } else { return 2; }\n  console.log(3);\n}\n",
        );
        assert_eq!(count_key(&both, "javascript:S1763"), 1);

        let one_sided = js_keys("function k(c) {\n  if (c) { return 1; }\n  console.log(2);\n}\n");
        assert_eq!(count_key(&one_sided, "javascript:S1763"), 0);
    }
}
