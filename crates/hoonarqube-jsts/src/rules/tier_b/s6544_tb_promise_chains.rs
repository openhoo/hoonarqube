// Rule module s6544_tb_promise_chains (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S6544`: value-less `.then()` callbacks inside longer chains.
pub(crate) fn check_tb_promise_chains(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = PromiseChainCollector::default();
    collector.visit_program(program);
    for span in collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S6544",
            "This '.then()' callback returns nothing although its result is chained further.",
            span,
        );
    }
}

/// `.then(callback)` results consumed without a returned value (`S6544`).
#[derive(Default)]
pub(crate) struct PromiseChainCollector {
    pub(crate) sites: Vec<Span>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn valueless_then_callback_in_chain_flagged() {
        let flagged =
            js("fetchData().then((response) => {\n  console.log(response);\n}).catch(fail);\n");
        assert_eq!(filtered(&flagged, "S6544").len(), 1);
        let returns_value =
            js("fetchData().then((response) => {\n  return response.json();\n}).catch(fail);\n");
        assert_eq!(filtered(&returns_value, "S6544").len(), 0);
        let unchained = js("fetchData().then((response) => {\n  console.log(response);\n});\n");
        assert_eq!(filtered(&unchained, "S6544").len(), 0);
    }
}
