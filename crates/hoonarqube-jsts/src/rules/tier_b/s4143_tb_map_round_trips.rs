// Rule module s4143_tb_map_round_trips (generated).
use crate::support::{IssueSink, RuleScope, source_slice};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S4143`: values read from a map and written straight back into it.
pub(crate) fn check_tb_map_round_trips(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = MapRoundTripCollector::default();
    collector.visit_program(program);
    // Any `set` on the same map invalidates earlier reads of its keys.
    let mut mutations: Vec<(&str, Span)> = collector.mutations.clone();
    mutations.extend(collector.sets.iter().map(|(map, _, _, span)| (*map, *span)));
    for (map_name, key_span, value_variable, set_span) in &collector.sets {
        let Some(variable) = value_variable else {
            continue;
        };
        let matching_get = collector
            .gets
            .iter()
            .rev()
            .find(|(var, get_map, key, call)| {
                var == variable
                    && get_map == map_name
                    && call.end <= set_span.start
                    && source_slice(source, *key) == source_slice(source, *key_span)
            });
        let Some((_, _, _, get_call)) = matching_get else {
            continue;
        };
        let interrupted = mutations.iter().any(|(name, span)| {
            *name == *map_name && span.start > get_call.end && span.end < set_span.start
        }) || collector.variable_writes.iter().any(|(name, span)| {
            *name == *variable && span.start > get_call.end && span.end < set_span.start
        });
        if !interrupted {
            sink.emit_span(
                RuleScope::Both,
                "S4143",
                "This 'set' stores the value just read from the same key; drop the round trip.",
                *set_span,
            );
        }
    }
}

/// `m.get(k)` results immediately stored back via `m.set(k, v)` (`S4143`).
#[derive(Default)]
pub(crate) struct MapRoundTripCollector<'p> {
    /// `(variable, map name, key span, get-call span)`.
    pub(crate) gets: Vec<(&'p str, &'p str, Span, Span)>,
    /// `(map name, key span, value variable, set-call span)`.
    pub(crate) sets: Vec<(&'p str, Span, Option<&'p str>, Span)>,
    /// Other mutations (`delete`, `clear`, any other `set`) on a map name.
    pub(crate) mutations: Vec<(&'p str, Span)>,
    /// Writes to variables, used to detect re-binding between get and set.
    pub(crate) variable_writes: Vec<(&'p str, Span)>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn map_set_after_get_round_trip_flagged() {
        let flagged = js(
            "function f(map) {\n  const current = map.get('key');\n  map.set('key', current);\n}\nf(m);\n",
        );
        assert_eq!(filtered(&flagged, "S4143").len(), 1);
        let other_key = js("const v = map.get('a');\nmap.set('b', v);\n");
        assert_eq!(filtered(&other_key, "S4143").len(), 0);
        let deleted_between = js("const v = map.get('k');\nmap.delete('k');\nmap.set('k', v);\n");
        assert_eq!(filtered(&deleted_between, "S4143").len(), 0);
    }
}
