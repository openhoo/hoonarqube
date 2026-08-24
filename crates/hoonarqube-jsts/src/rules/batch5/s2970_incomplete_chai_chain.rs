use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::support::RuleScope;
use crate::support::callee_name;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

/// Chai language chains (properties that assert nothing by themselves).
pub(crate) const CHAI_LANGUAGE_PROPS: [&str; 14] = [
    "to", "be", "been", "is", "that", "which", "and", "has", "have", "with", "at", "of", "same",
    "not",
];

impl TestFrameworkCollector<'_, '_> {
    /// `S2970`: chai language chains that assert nothing.
    pub(crate) fn check_incomplete_chai_chain(&mut self, expression: &Expression<'_>) {
        let mut current = expression;
        let mut links: Vec<&str> = Vec::new();
        while let Expression::StaticMemberExpression(member) = current {
            let name: &str = &member.property.name;
            links.push(name);
            current = &member.object;
        }
        let rooted_at_expect = matches!(current, Expression::CallExpression(call) if callee_name(call) == Some("expect"));
        if rooted_at_expect
            && links.len() >= 2
            && links.iter().all(|link| CHAI_LANGUAGE_PROPS.contains(link))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2970",
                "Complete this assertion; these chai properties assert nothing.",
                expression.span(),
            );
        }
    }
}
