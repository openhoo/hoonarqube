// Rule module s3686_tb_mixed_construction (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};
use oxc_span::Span;

/// S3686 (JS only) — the same file-local function both called and
/// constructed; the minority form is flagged (ties flag the plain calls).
pub(crate) fn check_tb_mixed_construction(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for id in 0..model.bindings.len() {
        if model.bindings[id].kind != TbKind::Function {
            continue;
        }
        let news: Vec<Span> = model
            .news
            .iter()
            .filter(|(owner, _)| *owner == id)
            .map(|(_, span)| *span)
            .collect();
        let calls: Vec<Span> = model
            .calls
            .iter()
            .filter(|site| site.binding == id)
            .map(|site| site.span)
            .collect();
        if news.is_empty() || calls.is_empty() {
            continue;
        }
        let (flagged, message) = if news.len() >= calls.len() {
            (calls, "invoked")
        } else {
            (news, "constructed with 'new'")
        };
        let name = model.bindings[id].name;
        for span in flagged {
            sink.emit_span(
                RuleScope::JsOnly,
                "S3686",
                &format!("'{name}' is also {message} elsewhere; pick one form."),
                span,
            );
        }
    }
}
