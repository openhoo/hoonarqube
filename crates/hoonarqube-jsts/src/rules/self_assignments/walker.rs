// Family walker for 'self_assignments' (generated).
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::{
    IssueSink, LineIndex, RuleScope, assignment_target_name, identifier_name, source_slice,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{AssignmentExpression, AssignmentOperator};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_assignment_expression;
use oxc_span::GetSpan;

pub(crate) fn check_self_assignments(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = SelfAssignmentCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
        source,
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// `S1656`: assignments whose both sides are identical.
pub(crate) struct SelfAssignmentCollector<'a, 'index> {
    pub(crate) sink: IssueSink<'index>,
    pub(crate) source: &'a str,
}

impl<'a> Visit<'a> for SelfAssignmentCollector<'a, '_> {
    fn visit_assignment_expression(&mut self, it: &AssignmentExpression<'a>) {
        if it.operator == AssignmentOperator::Assign {
            let names_match = assignment_target_name(&it.left)
                .is_some_and(|target| identifier_name(&it.right) == Some(target));
            let text_matches = source_slice(self.source, it.left.span())
                == source_slice(self.source, it.right.span());
            if names_match || text_matches {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1656",
                    "Remove this self-assignment.",
                    it.span(),
                );
            }
        }
        walk_assignment_expression(self, it);
    }
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_self_assignments(ctx.program, ctx.source, ctx.index, ctx.language)
}
