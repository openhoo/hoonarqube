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
        let (flagged, reference, form) = if news.len() >= calls.len() {
            (calls, news[0], "new")
        } else {
            (news, calls[0], "without \"new\"")
        };
        let line = sink.index.pos(reference.start).line;
        for span in flagged {
            sink.emit_span(
                RuleScope::JsOnly,
                "S3686",
                &format!(
                    "Correct the use of this function; on line {line} it was called with \"{form}\"."
                ),
                span,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn mixed_call_and_new_sites_flag_minority_form() {
        let flagged = js("function Thing() {}\nnew Thing();\nThing();\n");
        assert_eq!(filtered(&flagged, "S3686").len(), 1);
        let clean = js("function plain() {}\nplain();\nplain();\n");
        assert_eq!(filtered(&clean, "S3686").len(), 0);
    }
}
