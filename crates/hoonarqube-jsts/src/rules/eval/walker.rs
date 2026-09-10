// Family walker for 'eval' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::rules::shared::{argument_expression, is_literal_expression};
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use oxc_ast::ast::{CallExpression, Expression, NewExpression};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::{walk_call_expression, walk_new_expression};
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};

fn check_eval_usage(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
    semantic: Option<&Semantic<'_>>,
) -> Vec<Issue> {
    let mut collector = EvalUsageCollector {
        index,
        language,
        semantic,
        issues: Vec::new(),
    };
    collector.visit_program(program);
    collector.issues
}

/// Collects global `eval(...)` calls and `new Function(...)` expressions
/// anywhere in the tree, anchored at the callee span.
///
/// A direct identifier is only the built-in surface when its semantic
/// reference is global. This keeps local parameters/declarations named
/// `eval` or `Function` out of the hotspot; without semantic provenance the
/// collector remains silent rather than guessing from a name alone.
struct EvalUsageCollector<'a> {
    index: &'a LineIndex<'a>,
    language: JstsLanguage,
    semantic: Option<&'a Semantic<'a>>,
    issues: Vec<Issue>,
}

impl<'a> Visit<'a> for EvalUsageCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && matches!(callee.name.as_str(), "eval" | "Function")
            && self.is_global(callee)
            && has_dynamic_argument(&it.arguments)
        {
            let message = if callee.name == "eval" {
                "Remove this usage of 'eval'."
            } else {
                "Remove this usage of 'Function'."
            };
            self.push(message, callee.span());
        }
        walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && callee.name == "Function"
            && self.is_global(callee)
            && has_dynamic_argument(&it.arguments)
        {
            self.push("Remove this usage of 'Function'.", callee.span());
        }
        walk_new_expression(self, it);
    }
}

fn has_dynamic_argument(arguments: &[oxc_ast::ast::Argument<'_>]) -> bool {
    arguments.iter().any(|argument| {
        argument_expression(argument).is_none_or(|expression| !is_constant_code(expression))
    })
}

fn is_constant_code(expression: &Expression<'_>) -> bool {
    is_literal_expression(expression)
        || matches!(
            expression,
            Expression::TemplateLiteral(template) if template.expressions.is_empty()
        )
}

impl EvalUsageCollector<'_> {
    fn is_global(&self, identifier: &oxc_ast::ast::IdentifierReference<'_>) -> bool {
        self.semantic
            .is_some_and(|semantic| semantic.is_reference_to_global_variable(identifier))
    }
}

impl EvalUsageCollector<'_> {
    fn push(&mut self, message: &str, span: Span) {
        self.issues.push(Issue {
            rule_key: format!("{}:S1523", self.language.prefix()),
            message: message.to_string(),
            range: self.index.range(span),
            fix: None,
            flows: Vec::new(),
            alternatives: Vec::new(),
        });
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_eval_usage(ctx.program, ctx.index, ctx.language, ctx.semantic)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn rule_keys_follow_file_language_prefix() {
        let javascript = js("eval(source);");
        assert_eq!(javascript.issues[0].rule_key, "javascript:S1523");

        let typescript = ts("eval(source);");
        assert_eq!(typescript.issues[0].rule_key, "typescript:S1523");
        assert_eq!(typescript.language, "typescript");
    }

    #[test]
    fn s1523_flags_dynamic_function_constructor_and_clean_code_passes() {
        let function_ctor = js_keys("new Function(source);\n");
        assert_eq!(count_key(&function_ctor, "javascript:S1523"), 1);

        let function_call = js_keys("Function(source);\n");
        assert_eq!(count_key(&function_call, "javascript:S1523"), 1);

        let literal_ctor = js_keys("new Function('return 1');\n");
        assert_eq!(count_key(&literal_ctor, "javascript:S1523"), 0);

        let literal_call = js_keys("Function('return 1');\n");
        assert_eq!(count_key(&literal_call, "javascript:S1523"), 0);

        let clean = js_keys("compute('x');\nconst made = new Maker();\n");
        assert_eq!(count_key(&clean, "javascript:S1523"), 0);
    }
    #[test]
    fn s1523_exempts_constant_eval_code_but_keeps_dynamic_code_in_js_and_ts() {
        let javascript = js_keys("eval('work()');\neval(`handle_${role}()`);\n");
        assert_eq!(count_key(&javascript, "javascript:S1523"), 1);

        let typescript = ts_keys("eval('handle_user()');\neval(`handle_${role}()`);\n");
        assert_eq!(count_key(&typescript, "typescript:S1523"), 1);
    }

    #[test]
    fn s1523_uses_global_eval_and_function_provenance() {
        let global = js_keys("eval(source);\nnew Function(source);\nFunction(source);\n");
        assert_eq!(count_key(&global, "javascript:S1523"), 3);

        let shadowed = js_keys(
            "function run(eval, Function) {\n\
             eval(source);\n\
             new Function(source);\n\
             Function(source);\n\
             }\n",
        );
        assert_eq!(count_key(&shadowed, "javascript:S1523"), 0);
    }

    #[test]
    fn s1523_member_callee_is_not_flagged_but_nested_direct_eval_is() {
        let member = js_keys("window.eval('x');\nnew window.Function('return 1');\n");
        assert_eq!(count_key(&member, "javascript:S1523"), 0);
        let nested_direct = js_keys("setTimeout(() => eval(value), 0);\n");
        assert_eq!(count_key(&nested_direct, "javascript:S1523"), 1);
    }
}
