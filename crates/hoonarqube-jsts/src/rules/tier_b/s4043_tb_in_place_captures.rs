// Rule module s4043_tb_in_place_captures (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S4043`: in-place method result captured while the original is reused.
pub(crate) fn check_tb_in_place_captures(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = InPlaceCaptureCollector::default();
    collector.visit_program(program);
    for (base_name, method, call_span) in &collector.captures {
        let original_reused_later = collector
            .references
            .iter()
            .any(|(name, span)| *name == *base_name && span.start > call_span.end);
        if original_reused_later {
            sink.emit_span(
                RuleScope::Both,
                "S4043",
                &format!(
                    "'{method}()' mutates '{base_name}' in place; the captured value aliases it."
                ),
                *call_span,
            );
        }
    }
}

/// Captured results of in-place array methods whose base is reused (`S4043`).
#[derive(Default)]
pub(crate) struct InPlaceCaptureCollector<'p> {
    /// `(base name, method, call span)` of captured in-place calls.
    pub(crate) captures: Vec<(&'p str, &'p str, Span)>,
    pub(crate) references: Vec<(&'p str, Span)>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn in_place_capture_needs_later_original_use() {
        let flagged = js(
            "function f(list) {\n  const sorted = list.sort();\n  return list.length + sorted.length;\n}\nf(items);\n",
        );
        assert_eq!(filtered(&flagged, "S4043").len(), 1);
        let clean = js("const ordered = items.sort();\nreturn ordered;\n");
        assert_eq!(filtered(&clean, "S4043").len(), 0);
    }
}
