// Residual rule machinery for 'batch2d' (extracted from lib.rs).
use crate::rules::batch2d::s3512_es_idioms::EsIdiomCollector;
use crate::support::RuleScope;
use crate::support::identifier_name;
use crate::support::property_key_name;
use oxc_ast::ast::ObjectExpression;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_ast::ast::PropertyKind;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl EsIdiomCollector<'_> {
    /// `S3498, S3499` logic extracted from `visit_object_expression`.
    pub(crate) fn check_s3498_s3499_object_expression(&mut self, it: &ObjectExpression<'_>) {
        let mut non_shorthand_seen = false;

        for property in &it.properties {
            let ObjectPropertyKind::ObjectProperty(inner) = property else {
                continue;
            };
            if inner.kind != PropertyKind::Init {
                continue;
            }
            if inner.shorthand {
                // `S3499`: shorthand properties come first.
                if non_shorthand_seen {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3499",
                        "Group all shorthand properties at either the beginning or end of this object declaration.",
                        oxc_span::Span::new(it.span.start, it.span.start.saturating_add(1)),
                    );
                }
            } else {
                non_shorthand_seen = true;
                // `S3498`: `{ a: a }` should use the shorthand form.
                if let (Some(key), Some(value)) =
                    (property_key_name(&inner.key), identifier_name(&inner.value))
                    && key == value
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S3498",
                        "Expected property shorthand.",
                        inner.key.span(),
                    );
                }
            }
        }
    }
}
