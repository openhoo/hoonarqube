use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSPropertySignature;
use oxc_ast::ast::TSType;
use oxc_span::GetSpan;

/// `S4782` helper: does the type union contain the `undefined` keyword?
fn union_contains_undefined(ts_type: &TSType<'_>) -> bool {
    match ts_type {
        TSType::TSUnionType(union) => union
            .types
            .iter()
            .any(|member| matches!(member, TSType::TSUndefinedKeyword(_))),
        _ => false,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4782` logic extracted from `visit_ts_property_signature`.
    pub(crate) fn check_s4782_ts_property_signature(&mut self, it: &TSPropertySignature<'_>) {
        if let Some(annotation) = &it.type_annotation
            && it.optional
            && union_contains_undefined(&annotation.type_annotation)
        {
            let question = self
                .source
                .get(it.key.span().end as usize..annotation.span.start as usize)
                .and_then(|gap| gap.find('?'))
                .map_or(it.key.span().end, |offset| {
                    it.key
                        .span()
                        .end
                        .saturating_add(u32::try_from(offset).unwrap_or(u32::MAX))
                });
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4782",
                "Consider removing 'undefined' type or '?' specifier, one of them is redundant.",
                oxc_span::Span::new(question, question.saturating_add(1)),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn redundant_optional_marker_anchors_actual_question_token_after_unicode() {
        let source = "interface X { café\u{00a0}?: string | undefined }\n";
        let report = ts(source);
        let finding = report
            .issues
            .iter()
            .find(|issue| issue.rule_key.ends_with(":S4782"))
            .expect("redundant optional marker finding");
        let question = source.find('?').expect("question mark");
        assert_eq!(
            finding.range.start.column,
            u32::try_from(source[..question].chars().count()).expect("column")
        );
        assert_eq!(finding.range.end.column, finding.range.start.column + 1);
    }
}
