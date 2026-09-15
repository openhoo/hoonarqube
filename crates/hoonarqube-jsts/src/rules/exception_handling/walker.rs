// Family walker for 'exception_handling' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope, binding_identifier_name, identifier_name};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    ArrowFunctionBody, ArrowFunctionExpression, BindingPattern, BlockStatement, CatchClause, Class,
    Declaration, Expression, ForInStatement, ForOfStatement, ForStatement, ForStatementInit,
    ForStatementLeft, FormalParameters, Function, FunctionBody, IdentifierReference,
    MethodDefinition, MethodDefinitionKind, ReturnStatement, Statement, StaticBlock, TryStatement,
    VariableDeclaration, VariableDeclarationKind,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_arrow_function_expression, walk_block_statement, walk_catch_clause, walk_class,
    walk_declaration, walk_expression, walk_for_in_statement, walk_for_of_statement,
    walk_for_statement, walk_function, walk_method_definition, walk_static_block,
    walk_try_statement,
};
use oxc_span::{GetSpan, Span};
use oxc_syntax::scope::ScopeFlags;

fn check_exception_handling(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ExceptionHandlingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S2486`, `S2737`, and `S2432` in one traversal.
struct ExceptionHandlingCollector<'index> {
    sink: IssueSink<'index>,
}

impl<'a> Visit<'a> for ExceptionHandlingCollector<'a> {
    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        // `S2737`: exactly one statement rethrowing the caught binding.
        if it.body.body.len() == 1
            && let Statement::ThrowStatement(thrown) = &it.body.body[0]
        {
            let caught = it
                .param
                .as_ref()
                .and_then(|param| binding_identifier_name(&param.pattern));
            if caught.is_some() && identifier_name(&thrown.argument) == caught {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2737",
                    "Add logic to this catch clause or eliminate it and rethrow the exception automatically.",
                    Span::new(it.span.start, it.span.start.saturating_add(5)),
                );
            }
        }
        walk_catch_clause(self, it);
    }

    fn visit_try_statement(&mut self, it: &TryStatement<'a>) {
        if let Some(handler) = &it.handler {
            self.check_s2486(handler, &it.block.body);
        }
        walk_try_statement(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        // `S2432`: setters returning a value.
        if it.kind == MethodDefinitionKind::Set {
            let mut scanner = ReturnValueScanner::default();
            if let Some(body) = &it.value.body {
                scanner.visit_function_body(body);
            }
            if let Some(span) = scanner.found {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S2432",
                    "Setter cannot return a value.",
                    span,
                );
            }
        }
        walk_method_definition(self, it);
    }
}

impl<'index> ExceptionHandlingCollector<'index> {
    /// `S2486` pins the upstream `no-ignored-exceptions` semantics: a catch
    /// clause with a simple identifier parameter that is never referenced
    /// inside the catch body silently ignores the exception. It is reported
    /// with the pinned Sonar way message unless the `try` body is a single
    /// simple statement, which the pinned server keeps clean. The catch
    /// body's shape is irrelevant: empty, comment-only, and lone dummy
    /// `return` bodies all report, handled catches stay clean, and
    /// parameter-less or destructured catches are never reported.
    fn check_s2486(&mut self, handler: &CatchClause<'index>, try_body: &[Statement<'index>]) {
        let Some(param) = &handler.param else {
            return;
        };
        let Some(name) = binding_identifier_name(&param.pattern) else {
            return;
        };
        let mut references = CatchBindingReferences {
            name,
            shadowed: Vec::new(),
            found: false,
        };
        references.visit_block_statement(&handler.body);
        if references.found {
            return;
        }
        if is_single_simple_statement(try_body) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S2486",
            "Handle this exception or don't catch it at all.",
            handler.span(),
        );
    }
}

/// Whether a statement run is a single "simple" statement: exactly one
/// statement that is not a block, loop, or `switch` (labels are unwrapped).
fn is_single_simple_statement(body: &[Statement<'_>]) -> bool {
    if body.len() != 1 {
        return false;
    }
    let mut statement = &body[0];
    while let Statement::LabeledStatement(labeled) = statement {
        statement = &labeled.body;
    }
    !matches!(
        statement,
        Statement::BlockStatement(_)
            | Statement::DoWhileStatement(_)
            | Statement::ForInStatement(_)
            | Statement::ForOfStatement(_)
            | Statement::ForStatement(_)
            | Statement::SwitchStatement(_)
            | Statement::WhileStatement(_)
    )
}

/// Scans a catch body for identifier references that still resolve to the
/// catch binding. Scopes that redeclare the name (functions, arrows,
/// classes, blocks, `for` heads, nested catches) shadow it for their
/// contents.
struct CatchBindingReferences<'n> {
    name: &'n str,
    shadowed: Vec<bool>,
    found: bool,
}

impl CatchBindingReferences<'_> {
    fn enter_scope(&mut self, binds: bool) {
        let outer = self.shadowed.last().copied().unwrap_or(false);
        self.shadowed.push(outer || binds);
    }

    fn leave_scope(&mut self) {
        self.shadowed.pop();
    }

    fn shadowed(&self) -> bool {
        self.shadowed.last().copied().unwrap_or(false)
    }
}

impl<'a> Visit<'a> for CatchBindingReferences<'_> {
    fn visit_identifier_reference(&mut self, it: &IdentifierReference<'a>) {
        if !self.shadowed() && it.name == self.name {
            self.found = true;
        }
    }

    fn visit_block_statement(&mut self, it: &BlockStatement<'a>) {
        self.enter_scope(direct_block_declarations(&it.body, self.name));
        walk_block_statement(self, it);
        self.leave_scope();
    }

    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        let binds = it.id.as_ref().is_some_and(|id| id.name == self.name)
            || parameters_bind_name(&it.params, self.name)
            || it
                .body
                .as_ref()
                .is_some_and(|body| function_body_binds_name(body, self.name));
        self.enter_scope(binds);
        walk_function(self, it, flags);
        self.leave_scope();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        let binds = parameters_bind_name(&it.params, self.name)
            || match &it.body {
                ArrowFunctionBody::FunctionBody(body) => function_body_binds_name(body, self.name),
                _ => false,
            };
        self.enter_scope(binds);
        walk_arrow_function_expression(self, it);
        self.leave_scope();
    }

    fn visit_class(&mut self, it: &Class<'a>) {
        self.enter_scope(it.id.as_ref().is_some_and(|id| id.name == self.name));
        walk_class(self, it);
        self.leave_scope();
    }

    fn visit_catch_clause(&mut self, it: &CatchClause<'a>) {
        let binds = it
            .param
            .as_ref()
            .is_some_and(|param| pattern_binds_name(&param.pattern, self.name));
        self.enter_scope(binds);
        walk_catch_clause(self, it);
        self.leave_scope();
    }

    fn visit_static_block(&mut self, it: &StaticBlock<'a>) {
        self.enter_scope(false);
        walk_static_block(self, it);
        self.leave_scope();
    }

    fn visit_for_statement(&mut self, it: &ForStatement<'a>) {
        let binds = it.init.as_ref().is_some_and(|init| match init {
            ForStatementInit::VariableDeclaration(declaration) => {
                declaration_binds_name(declaration, self.name)
            }
            _ => false,
        });
        self.enter_scope(binds);
        walk_for_statement(self, it);
        self.leave_scope();
    }

    fn visit_for_in_statement(&mut self, it: &ForInStatement<'a>) {
        let binds = match &it.left {
            ForStatementLeft::VariableDeclaration(declaration) => {
                declaration_binds_name(declaration, self.name)
            }
            _ => false,
        };
        self.enter_scope(binds);
        walk_for_in_statement(self, it);
        self.leave_scope();
    }

    fn visit_for_of_statement(&mut self, it: &ForOfStatement<'a>) {
        let binds = match &it.left {
            ForStatementLeft::VariableDeclaration(declaration) => {
                declaration_binds_name(declaration, self.name)
            }
            _ => false,
        };
        self.enter_scope(binds);
        walk_for_of_statement(self, it);
        self.leave_scope();
    }
}

/// Whether any identifier in the parameter list binds `name`.
fn parameters_bind_name(parameters: &FormalParameters<'_>, name: &str) -> bool {
    parameters
        .items
        .iter()
        .any(|parameter| pattern_binds_name(&parameter.pattern, name))
}

/// Whether the declaration binds `name` in its scope.
fn declaration_binds_name(declaration: &VariableDeclaration<'_>, name: &str) -> bool {
    declaration
        .declarations
        .iter()
        .any(|declarator| pattern_binds_name(&declarator.id, name))
}

/// Whether the pattern binds `name` anywhere in its shape.
fn pattern_binds_name(pattern: &BindingPattern<'_>, name: &str) -> bool {
    match pattern {
        BindingPattern::BindingIdentifier(identifier) => identifier.name == name,
        BindingPattern::AssignmentPattern(assignment) => pattern_binds_name(&assignment.left, name),
        BindingPattern::ArrayPattern(array) => {
            array
                .elements
                .iter()
                .flatten()
                .any(|element| pattern_binds_name(element, name))
                || array
                    .rest
                    .as_ref()
                    .is_some_and(|rest| pattern_binds_name(&rest.argument, name))
        }
        BindingPattern::ObjectPattern(object) => {
            object
                .properties
                .iter()
                .any(|property| pattern_binds_name(&property.value, name))
                || object
                    .rest
                    .as_ref()
                    .is_some_and(|rest| pattern_binds_name(&rest.argument, name))
        }
    }
}

/// Whether a block's own statements declare `name` (any declaration kind).
fn direct_block_declarations(statements: &[Statement<'_>], name: &str) -> bool {
    statements.iter().any(|statement| match statement {
        Statement::VariableDeclaration(declaration) => declaration_binds_name(declaration, name),
        Statement::LabeledStatement(labeled) => {
            direct_block_declarations(std::slice::from_ref(&labeled.body), name)
        }
        Statement::FunctionDeclaration(function) => {
            function.id.as_ref().is_some_and(|id| id.name == name)
        }
        Statement::ClassDeclaration(class) => class.id.as_ref().is_some_and(|id| id.name == name),
        _ => false,
    })
}

/// Whether a function-like body declares `name`: hoisted `var` and function
/// declarations at any block depth plus top-level `let`/`const` bindings.
fn function_body_binds_name(body: &FunctionBody<'_>, name: &str) -> bool {
    hoists_name(&body.statements, name)
        || body.statements.iter().any(|statement| match statement {
            Statement::VariableDeclaration(declaration) => {
                declaration.kind != VariableDeclarationKind::Var
                    && declaration_binds_name(declaration, name)
            }
            _ => false,
        })
}

/// Whether a `var` or function declaration of `name` hoists to the
/// enclosing function scope from any block depth (nested functions and
/// classes start their own scopes and are not crossed).
fn hoists_name(statements: &[Statement<'_>], name: &str) -> bool {
    statements.iter().any(|statement| match statement {
        Statement::VariableDeclaration(declaration) => {
            declaration.kind == VariableDeclarationKind::Var
                && declaration_binds_name(declaration, name)
        }
        Statement::FunctionDeclaration(function) => {
            function.id.as_ref().is_some_and(|id| id.name == name)
        }
        Statement::BlockStatement(block) => hoists_name(&block.body, name),
        Statement::IfStatement(if_statement) => {
            hoists_name(std::slice::from_ref(&if_statement.consequent), name)
                || if_statement
                    .alternate
                    .as_ref()
                    .is_some_and(|alternate| hoists_name(std::slice::from_ref(alternate), name))
        }
        Statement::ForStatement(for_statement) => {
            hoists_name(std::slice::from_ref(&for_statement.body), name)
        }
        Statement::ForInStatement(for_in_statement) => {
            hoists_name(std::slice::from_ref(&for_in_statement.body), name)
        }
        Statement::ForOfStatement(for_of_statement) => {
            hoists_name(std::slice::from_ref(&for_of_statement.body), name)
        }
        Statement::WhileStatement(while_statement) => {
            hoists_name(std::slice::from_ref(&while_statement.body), name)
        }
        Statement::DoWhileStatement(do_while_statement) => {
            hoists_name(std::slice::from_ref(&do_while_statement.body), name)
        }
        Statement::LabeledStatement(labeled) => {
            hoists_name(std::slice::from_ref(&labeled.body), name)
        }
        Statement::WithStatement(with_statement) => {
            hoists_name(std::slice::from_ref(&with_statement.body), name)
        }
        Statement::TryStatement(try_statement) => {
            hoists_name(&try_statement.block.body, name)
                || try_statement
                    .handler
                    .as_ref()
                    .is_some_and(|handler| hoists_name(&handler.body.body, name))
                || try_statement
                    .finalizer
                    .as_ref()
                    .is_some_and(|finalizer| hoists_name(&finalizer.body, name))
        }
        Statement::SwitchStatement(switch_statement) => switch_statement
            .cases
            .iter()
            .any(|case| hoists_name(&case.consequent, name)),
        _ => false,
    })
}

/// Finds `return <value>` statements outside nested functions; used to skip
/// function subtrees while scanning setter bodies.
#[derive(Default)]
struct ReturnValueScanner {
    found: Option<Span>,
}

impl<'a> Visit<'a> for ReturnValueScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if it.argument.is_some() {
            self.found.get_or_insert(it.span());
        }
    }

    fn visit_expression(&mut self, it: &Expression<'a>) {
        if !matches!(
            it,
            Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)
        ) {
            walk_expression(self, it);
        }
    }

    fn visit_declaration(&mut self, it: &Declaration) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_exception_handling(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn exception_handling_rules_flag_ignored_rethrow_and_setter_returns() {
        let source = "\
function rethrowOnly() {
  try {
    a();
  } catch (e) {
    throw e;
  }
}
function meaningful() {
  try {
    b();
  } catch (e) {
    log(e);
    throw e;
  }
}
function silent() {
  try {
    c();
    d();
  } catch (error) {
  }
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S2737"), 1);
        // The unused catch binding over a two-statement try is reported.
        assert_eq!(count_key(&keys, "javascript:S2486"), 1);

        // A setter returning a value is flagged only for JavaScript files.
        let setter_source = "class A {\n  set value(next) {\n    return next;\n  }\n}\n";
        assert_eq!(
            js(setter_source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S2432"))
                .count(),
            1
        );
        assert_eq!(
            ts(setter_source)
                .issues
                .iter()
                .filter(|issue| issue.rule_key.ends_with(":S2432"))
                .count(),
            0
        );
    }

    #[test]
    fn s2737_requires_rethrowing_the_caught_binding() {
        // A different binding is a meaningful rethrow target.
        assert_eq!(
            count_key(
                &js_keys("try {\n  a();\n} catch (e) {\n  throw err;\n}\n"),
                "javascript:S2737"
            ),
            0
        );
        // Without a catch binding there is nothing to rethrow.
        assert_eq!(
            count_key(
                &js_keys("try {\n  b();\n} catch {\n  throw err;\n}\n"),
                "javascript:S2737"
            ),
            0
        );
    }

    #[test]
    fn s2486_tolerates_handled_catches_and_single_statement_tries() {
        // Same-server probes: a handled catch stays clean, and a single
        // simple statement in the try body keeps an ignored catch clean.
        assert_eq!(
            count_key(
                &js_keys("try {\n  b();\n} catch (e) {\n  log(e);\n}\n"),
                "javascript:S2486"
            ),
            0
        );
        assert_eq!(
            count_key(
                &js_keys("try {\n  a();\n} catch (e) {\n  return undefined;\n}\n"),
                "javascript:S2486"
            ),
            0
        );
        assert_eq!(
            count_key(
                &js_keys("try {\n  a();\n} catch (e) {\n  /* noop */\n}\n"),
                "javascript:S2486"
            ),
            0
        );
    }

    #[test]
    fn s2432_spares_getters_bare_returns_and_nested_functions() {
        let getter = js_keys("class A {\n  get value() {\n    return 1;\n  }\n}\n");
        assert_eq!(count_key(&getter, "javascript:S2432"), 0);

        let bare_return = js_keys("class A {\n  set value(next) {\n    return;\n  }\n}\n");
        assert_eq!(count_key(&bare_return, "javascript:S2432"), 0);

        // A value return inside a nested arrow is not the setter's own.
        let nested = js_keys(
            "class A {\n  set value(next) {\n    const f = () => {\n      return next;\n    };\n  }\n}\n",
        );
        assert_eq!(count_key(&nested, "javascript:S2432"), 0);
    }

    #[test]
    fn s2486_reports_pinned_axios_comment_only_catch() {
        // #253: verbatim axios/axios@18e7dfedf30c96e58652887f930642ae82e0130c
        // lib/helpers/deprecatedMethod.js (MIT). SonarQube 26.8.0.126808
        // (Sonar way) reports the comment-only catch at lines 28-30 because
        // its unused catch parameter sits over a two-statement try body.
        let report = js(include_str!(
            "../../../fixtures/shapes/axios-deprecated-method.js"
        ));
        let sites: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S2486")
            .map(|issue| {
                (
                    (issue.range.start.line, issue.range.start.column),
                    (issue.range.end.line, issue.range.end.column),
                    issue.message.as_str(),
                )
            })
            .collect();
        assert_eq!(
            sites,
            vec![(
                (28, 4),
                (30, 3),
                "Handle this exception or don't catch it at all."
            )]
        );
    }

    #[test]
    fn s2486_reports_dummy_return_catches_over_multi_statement_tries() {
        // #393: verbatim exceljs@5bed18b shapes. The pinned server reports
        // catches that swallow the exception behind a lone literal return.
        let defined_name = js_keys(
            "function isValidRange(range) {\n  try {\n    colCache.decodeEx(range);\n    return true;\n  } catch (err) {\n    return false;\n  }\n}\n",
        );
        assert_eq!(count_key(&defined_name, "javascript:S2486"), 1);

        let bare = js_keys(
            "function maybe(value) {\n  try {\n    parse(value);\n    return true;\n  } catch (err) {\n    return;\n  }\n}\n",
        );
        assert_eq!(count_key(&bare, "javascript:S2486"), 1);

        // Returning the caught binding is handling, not ignoring.
        let propagated = js_keys(
            "function maybe(value) {\n  try {\n    parse(value);\n    return true;\n  } catch (err) {\n    return err;\n  }\n}\n",
        );
        assert_eq!(count_key(&propagated, "javascript:S2486"), 0);

        // A single-statement try keeps the dummy-return catch clean
        // (express lib/view.js tryStat control).
        let single = js_keys(
            "function tryStat(path) {\n  try {\n    return fs.statSync(path);\n  } catch (e) {\n    return undefined;\n  }\n}\n",
        );
        assert_eq!(count_key(&single, "javascript:S2486"), 0);
    }

    #[test]
    fn s2486_ignores_parameterless_and_destructured_catches() {
        // Without a simple identifier parameter there is no ignored binding.
        let no_param = js_keys(
            "function run() {\n  try {\n    work();\n    more();\n  } catch {\n    return false;\n  }\n}\n",
        );
        assert_eq!(count_key(&no_param, "javascript:S2486"), 0);

        let destructured = js_keys(
            "function run() {\n  try {\n    work();\n    more();\n  } catch ({ message }) {\n    return false;\n  }\n}\n",
        );
        assert_eq!(count_key(&destructured, "javascript:S2486"), 0);
    }

    #[test]
    fn s2486_counts_nested_scopes_when_checking_parameter_usage() {
        // The binding used inside a nested closure still counts as handled.
        let closure = js_keys(
            "function run() {\n  try {\n    work();\n    more();\n  } catch (error) {\n    return () => error;\n  }\n}\n",
        );
        assert_eq!(count_key(&closure, "javascript:S2486"), 0);

        // A nested function redeclaring the binding shadows the catch
        // parameter, so the outer catch stays ignored.
        let shadowed = js_keys(
            "function run() {\n  try {\n    work();\n    more();\n  } catch (error) {\n    g((error) => error);\n    return false;\n  }\n}\n",
        );
        assert_eq!(count_key(&shadowed, "javascript:S2486"), 1);

        // Trivially empty and comment-only catches over multi-statement
        // try bodies report exactly like the pinned server; an empty try
        // body is not a single simple statement, so its catch reports too.
        let empty = js_keys(
            "function run() {\n  try {\n    work();\n    more();\n  } catch (error) {\n  }\n}\n",
        );
        assert_eq!(count_key(&empty, "javascript:S2486"), 1);

        let commented =
            js_keys("function run() {\n  try {\n  } catch (error) {\n    /* Ignore */\n  }\n}\n");
        assert_eq!(count_key(&commented, "javascript:S2486"), 1);
    }
}
