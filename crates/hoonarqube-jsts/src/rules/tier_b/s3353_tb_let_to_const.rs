// Rule module s3353_tb_let_to_const (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;
use std::collections::{HashMap, HashSet};

/// `S3353`: `let` variables that are never reassigned become `const`.
pub(crate) fn check_tb_let_to_const(
    model: &TbModel<'_>,
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = LetToConstCollector::default();
    collector.visit_program(program);
    let candidates: HashMap<u32, &str> = collector
        .candidates
        .into_iter()
        .map(|(name, span)| (span.start, name))
        .collect();
    for binding in &model.bindings {
        if binding.kind != TbKind::Let
            || !binding.writes.is_empty()
            || binding.reads.is_empty()
            || collector.excluded.contains(&binding.decl.start)
            || collector.exported.contains(&binding.decl.start)
        {
            continue;
        }
        if let Some(name) = candidates.get(&binding.decl.start) {
            sink.emit_span(
                RuleScope::Both,
                "S3353",
                &format!("Change this 'let' declaration to 'const'; '{name}' is never reassigned."),
                binding.decl,
            );
        }
    }
}

/// Plain `let` declarators plus exclusions for `S3353`.
#[derive(Default)]
pub(crate) struct LetToConstCollector<'a> {
    pub(crate) candidates: Vec<(&'a str, Span)>,
    pub(crate) excluded: HashSet<u32>,
    pub(crate) exported: HashSet<u32>,
    pub(crate) in_let: bool,
    pub(crate) in_export: bool,
}
