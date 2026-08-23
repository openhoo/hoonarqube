// Rule module s3003_relational_strings (generated).
use hoonarqube_ir::{Issue};
use oxc_ast::ast::{BinaryExpression, BinaryOperator, Expression, StringLiteral};
use oxc_span::{GetSpan};
use crate::context::{AnalysisContext};
use crate::support::{IssueSink, RuleScope};


/// `S3003`: relational operators on two string literals.
pub(crate) fn check_relational_strings(sink: &mut IssueSink, it: &BinaryExpression<'_>) {
    if matches!(
        it.operator,
        BinaryOperator::LessThan
            | BinaryOperator::LessEqualThan
            | BinaryOperator::GreaterThan
            | BinaryOperator::GreaterEqualThan
    ) && matches!(&it.left, Expression::StringLiteral(_))
        && matches!(&it.right, Expression::StringLiteral(_))
    {
        sink.emit_span(
            RuleScope::Both,
            "S3003",
            "Do not compare string literals relationally.",
            it.span(),
        );
    }
}

pub(crate) fn check(ctx: &AnalysisContext) -> Vec<Issue> {
    const KEYS: &[&str] = &["S3003"];
    let mut issues = super::walker::run(ctx);
    issues.retain(|i| {
        i.rule_key.rsplit(':').next().is_some_and(|k| KEYS.contains(&k))
    });
    issues
}
