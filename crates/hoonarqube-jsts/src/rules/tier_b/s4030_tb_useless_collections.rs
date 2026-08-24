// Rule module s4030_tb_useless_collections (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;
use std::collections::HashSet;

/// `S4030`: collections only ever mutated through write methods.
pub(crate) fn check_tb_useless_collections(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = UselessCollectionCollector::default();
    collector.visit_program(program);
    for (name, decl_span) in &collector.candidates {
        let mut uses = 0;
        let mut all_writes = true;
        for (reference_name, reference_span) in &collector.references {
            if *reference_name != *name {
                continue;
            }
            uses += 1;
            all_writes &= collector.write_receivers.contains(&reference_span.start);
        }
        if uses > 0 && all_writes {
            sink.emit_span(
                RuleScope::Both,
                "S4030",
                &format!("'{name}' is written to but never read; remove this collection."),
                *decl_span,
            );
        }
    }
}

/// Collects collections that are only ever written to (`S4030`).
#[derive(Default)]
pub(crate) struct UselessCollectionCollector<'p> {
    pub(crate) candidates: Vec<(&'p str, Span)>,
    pub(crate) references: Vec<(&'p str, Span)>,
    /// Receiver spans of `push`/`set`/`add`-family calls.
    pub(crate) write_receivers: HashSet<u32>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn write_only_collections_flagged() {
        let map = js("const cache = new Map();\ncache.set('a', 1);\n");
        assert_eq!(filtered(&map, "S4030").len(), 1);
        let array = js("const out = [];\nout.push(2);\nout.unshift(3);\n");
        assert_eq!(filtered(&array, "S4030").len(), 1);
        let read = js("const kept = [];\nkept.push(1);\nuse(kept);\n");
        assert_eq!(filtered(&read, "S4030").len(), 0);
        let indexed = js("const mixed = [];\nmixed[0] = 1;\n");
        assert_eq!(filtered(&indexed, "S4030").len(), 0);
    }
}
