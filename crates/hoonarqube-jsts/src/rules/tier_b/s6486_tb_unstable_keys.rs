// Rule module s6486_tb_unstable_keys (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S6486`: `key={Math.random()}` / `key={Date.now()}`.
pub(crate) fn check_tb_unstable_keys(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = UnstableKeyCollector::default();
    collector.visit_program(program);
    for span in collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S6486",
            "Use a stable identifier as the key; random values recreate elements on every render.",
            span,
        );
    }
}

/// Unstable values used as list keys (`S6486`).
#[derive(Default)]
pub(crate) struct UnstableKeyCollector {
    pub(crate) sites: Vec<Span>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn unstable_jsx_keys_flagged() {
        let flagged =
            jsx("const rows = items.map((item) => (\n  <li key={Math.random()}>{item}</li>\n));\n");
        assert_eq!(filtered(&flagged, "S6486").len(), 1);
        let date_key = jsx("<li key={Date.now()}>{item}</li>\n");
        assert_eq!(filtered(&date_key, "S6486").len(), 1);
        let stable =
            jsx("const rows = items.map((item) => (\n  <li key={item.id}>{item}</li>\n));\n");
        assert_eq!(filtered(&stable, "S6486").len(), 0);
    }
}
