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
    for (start, end) in collector.sites {
        sink.emit_span(
            RuleScope::Both,
            "S6544",
            "This '.then()' callback returns nothing although its result is chained further.",
            Span::new(start, end),
        );
    }
}

/// `.then(callback)` results consumed without a returned value (`S6544`).
/// Sites are keyed by span because nested chain decompositions can reach
/// the same `.then()` link more than once.
#[derive(Default)]
pub(crate) struct PromiseChainCollector {
    pub(crate) sites: std::collections::BTreeSet<(u32, u32)>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn valueless_then_callback_in_chain_flagged() {
        // A void `.then()` followed by another `.then()` that consumes the
        // fulfillment value stays reportable.
        let flagged =
            js("fetchData().then((response) => {\n  console.log(response);\n}).then(fail);\n");
        assert_eq!(filtered(&flagged, "S6544").len(), 1);
        let returns_value =
            js("fetchData().then((response) => {\n  return response.json();\n}).then(fail);\n");
        assert_eq!(filtered(&returns_value, "S6544").len(), 0);
        let unchained = js("fetchData().then((response) => {\n  console.log(response);\n});\n");
        assert_eq!(filtered(&unchained, "S6544").len(), 0);
    }

    /// #826: `.catch()` consumes the rejection reason and `.finally()`
    /// passes the fulfillment value through, so a void `.then()` followed
    /// only by error handling or chain end is never observed.
    #[test]
    fn valueless_then_followed_only_by_error_handling_is_clean() {
        // The reported fixture shape: terminal consumer plus `.catch()`.
        let fixture = js(concat!(
            "fetch(\"/data.json\")\n",
            "  .then((response) => response.json())\n",
            "  .then((data) => {\n",
            "    useData(data);\n",
            "  })\n",
            "  .catch((reason) => showError(String(reason)));\n",
        ));
        assert_eq!(filtered(&fixture, "S6544").len(), 0);

        // `.catch()`-only and `.finally()`-only continuations are clean.
        let catch_only =
            js("fetchData().then((response) => {\n  console.log(response);\n}).catch(fail);\n");
        assert_eq!(filtered(&catch_only, "S6544").len(), 0);
        let finally_only = js(
            "fetchData().then((response) => {\n  console.log(response);\n}).finally(cleanup);\n",
        );
        assert_eq!(filtered(&finally_only, "S6544").len(), 0);
        let catch_finally = js(
            "fetchData().then((response) => {\n  console.log(response);\n}).catch(fail).finally(cleanup);\n",
        );
        assert_eq!(filtered(&catch_finally, "S6544").len(), 0);
    }

    /// #826: a void `.then()` remains reportable whenever a later `.then()`
    /// can observe its fulfillment value, even across `.catch()`/`.finally()`
    /// pass-through links.
    #[test]
    fn valueless_then_before_value_consuming_then_still_flagged() {
        // Mid-chain producer: the second `.then()` reads the value.
        let mid_chain = js(concat!(
            "fetchData()\n",
            "  .then((response) => {\n",
            "    console.log(response);\n",
            "  })\n",
            "  .then((data) => useData(data));\n",
        ));
        assert_eq!(filtered(&mid_chain, "S6544").len(), 1);

        // `.catch()`/`.finally()` between the void `.then()` and the
        // consuming `.then()` do not hide the observation.
        let through_catch = js(concat!(
            "fetchData()\n",
            "  .then((response) => {\n",
            "    console.log(response);\n",
            "  })\n",
            "  .catch(fail)\n",
            "  .then((data) => useData(data));\n",
        ));
        assert_eq!(filtered(&through_catch, "S6544").len(), 1);
        let through_finally = js(concat!(
            "fetchData()\n",
            "  .then((response) => {\n",
            "    console.log(response);\n",
            "  })\n",
            "  .finally(cleanup)\n",
            "  .then((data) => useData(data));\n",
        ));
        assert_eq!(filtered(&through_finally, "S6544").len(), 1);

        // A trailing void `.then()` is a terminal consumer: only the
        // earlier void link is flagged, exactly once.
        let trailing_void = js(concat!(
            "fetchData()\n",
            "  .then((response) => {\n",
            "    console.log(response);\n",
            "  })\n",
            "  .then((data) => {\n",
            "    useData(data);\n",
            "  });\n",
        ));
        assert_eq!(filtered(&trailing_void, "S6544").len(), 1);
    }
}
