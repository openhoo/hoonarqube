// Family walker for 'exception_handling' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, ScannedComment, binding_identifier_name, identifier_name,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    CatchClause, Declaration, Expression, MethodDefinition, MethodDefinitionKind, ReturnStatement,
    Statement,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{
    walk_catch_clause, walk_declaration, walk_expression, walk_method_definition,
};
use oxc_span::{GetSpan, Span};

fn check_exception_handling(
    program: &oxc_ast::ast::Program<'_>,
    comments: &[ScannedComment],
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = ExceptionHandlingCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        comments,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S2486`, `S2737`, and `S2432` in one traversal.
struct ExceptionHandlingCollector<'index> {
    sink: IssueSink<'index>,
    comments: &'index [ScannedComment],
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
                    "This catch clause does nothing but rethrow the caught exception.",
                    thrown.span(),
                );
            }
        }
        // `S2486`: an empty catch is flagged unless it carries a comment
        // explaining why the exception is ignored.
        if it.body.body.is_empty() {
            let inner = Span::new(it.body.span.start + 1, it.body.span.end.saturating_sub(1));
            if !span_contains_comment(self.comments, inner) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S2486",
                    "Handle this exception or remove this empty catch clause.",
                    it.body.span(),
                );
            }
        }
        walk_catch_clause(self, it);
    }

    fn visit_method_definition(&mut self, it: &MethodDefinition<'a>) {
        // `S2432`: setters returning a value.
        if it.kind == MethodDefinitionKind::Set {
            let mut scanner = ReturnValueScanner::default();
            if let Some(body) = &it.value.body {
                scanner.visit_function_body(body);
            }
            if scanner.found {
                self.sink.emit_span(
                    RuleScope::JsOnly,
                    "S2432",
                    "Setters should not return values.",
                    it.key.span(),
                );
            }
        }
        walk_method_definition(self, it);
    }
}

/// Finds `return <value>` statements outside nested functions; used to skip
/// function subtrees while scanning setter bodies.
#[derive(Default)]
struct ReturnValueScanner {
    found: bool,
}

impl<'a> Visit<'a> for ReturnValueScanner {
    fn visit_return_statement(&mut self, it: &ReturnStatement<'a>) {
        if it.argument.is_some() {
            self.found = true;
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

    fn visit_declaration(&mut self, it: &Declaration<'a>) {
        if !matches!(it, Declaration::FunctionDeclaration(_)) {
            walk_declaration(self, it);
        }
    }
}

/// Whether any scanned comment lies inside `span` (overlap counts).
fn span_contains_comment(comments: &[ScannedComment], span: Span) -> bool {
    comments
        .iter()
        .any(|comment| comment.token.start < span.end && span.start < comment.token.end)
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_exception_handling(ctx.program, &ctx.comments, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn exception_handling_rules_flag_empty_rethrow_and_setter_returns() {
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
  } catch {
  }
}
";
        let keys = js_keys(source);
        assert_eq!(count_key(&keys, "javascript:S2737"), 1);
        // The comment-only catch is tolerated by `S2486`.
        let with_comment = js_keys(
            "function f() {\n  try {\n    d();\n  } catch {\n    // ignored on purpose\n  }\n}\n",
        );
        assert_eq!(count_key(&with_comment, "javascript:S2486"), 0);
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
    fn s2486_tolerates_inline_comments_and_non_empty_catches() {
        assert_eq!(
            count_key(
                &js_keys("try {\n  a();\n} catch (e) { /* noop */ }\n"),
                "javascript:S2486"
            ),
            0
        );
        assert_eq!(
            count_key(
                &js_keys("try {\n  b();\n} catch (e) {\n  log(e);\n}\n"),
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
}
