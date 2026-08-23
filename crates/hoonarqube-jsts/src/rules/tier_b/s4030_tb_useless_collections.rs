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
