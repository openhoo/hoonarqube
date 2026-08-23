// Family walker for 'eval' (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{CallExpression, Expression, Function, NewExpression};
use oxc_ast_visit::{Visit};
use oxc_ast_visit::walk::{walk_call_expression, walk_new_expression};
use oxc_span::{GetSpan, Span};
use crate::{JstsLanguage};
use crate::context::{AnalysisContext};
use crate::support::{LineIndex};


pub(crate) fn check_eval_usage(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = EvalUsageCollector {
        index,
        language,
        issues: Vec::new(),
    };
    collector.visit_program(program);
    collector.issues
}


/// Collects `eval(...)` calls and `new Function(...)` expressions anywhere in
/// the tree, anchored at the callee span.
pub(crate) struct EvalUsageCollector<'index> {
    pub(crate) index: &'index LineIndex,
    pub(crate) language: JstsLanguage,
    pub(crate) issues: Vec<Issue>,
}


impl<'a> Visit<'a> for EvalUsageCollector<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && callee.name == "eval"
        {
            self.push("Remove this usage of 'eval'.", callee.span());
        }
        walk_call_expression(self, it);
    }

    fn visit_new_expression(&mut self, it: &NewExpression<'a>) {
        if let Expression::Identifier(callee) = &it.callee
            && callee.name == "Function"
        {
            self.push("Remove this usage of 'Function'.", callee.span());
        }
        walk_new_expression(self, it);
    }
}


impl EvalUsageCollector<'_> {
    pub(crate) fn push(&mut self, message: &str, span: Span) {
        self.issues.push(Issue {
            rule_key: format!("{}:S1523", self.language.prefix()),
            message: message.to_string(),
            range: self.index.range(span),
        });
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_eval_usage(
        ctx.program,
        ctx.index,
        ctx.language,
    )
}
