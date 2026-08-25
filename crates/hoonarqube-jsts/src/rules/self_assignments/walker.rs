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

fn check_self_assignments(
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
struct SelfAssignmentCollector<'a, 'index> {
    sink: IssueSink<'index>,
    source: &'a str,
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn self_assignments_are_flagged_for_names_and_chains() {
        let source = "\
a = a;
obj.x = obj.x;
b = c;
";
        let report = js(source);
        let s1656_lines: Vec<u32> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key.ends_with(":S1656"))
            .map(|issue| issue.range.start.line)
            .collect();
        assert_eq!(s1656_lines, vec![1, 2]);
    }

    #[test]
    fn s1656_matches_computed_member_text_and_skips_compound_ops() {
        // Computed members are not plain names but identical text matches.
        assert_eq!(count_key(&js_keys("a[i] = a[i];\n"), "javascript:S1656"), 1);
        // Compound assignment operators are not self-assignments.
        assert_eq!(count_key(&js_keys("a += a;\n"), "javascript:S1656"), 0);
        // Only the inner link of an assignment chain self-assigns.
        assert_eq!(count_key(&js_keys("a = b = b;\n"), "javascript:S1656"), 1);
    }
}
