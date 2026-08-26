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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn never_reassigned_let_suggested_as_const() {
        let flagged = js("let fixed = compute();\nuse(fixed);\n");
        assert_eq!(filtered(&flagged, "S3353").len(), 1);
        let reassigned = js("let moving = 1;\nmoving = 2;\nuse(moving);\n");
        assert_eq!(filtered(&reassigned, "S3353").len(), 0);
        let for_head = js("for (let item of list) {\n  use(item);\n}\n");
        assert_eq!(filtered(&for_head, "S3353").len(), 0);
        let exported = js("export let exportedValue = compute();\nuse(exportedValue);\n");
        assert_eq!(filtered(&exported, "S3353").len(), 0);
        let late_init = js("let late;\nlate = 1;\nuse(late);\n");
        assert_eq!(filtered(&late_init, "S3353").len(), 0);
    }

    #[test]
    fn lets_inside_initializer_subtrees_are_still_candidates() {
        let flagged = js(
            "let outer = () => {\n  let inner = compute();\n  use(inner);\n};\nouter = wrap(outer);\nuse(outer);\n",
        );
        assert_eq!(filtered(&flagged, "S3353").len(), 1);
    }

    #[test]
    fn destructuring_defaults_do_not_write_their_helpers() {
        let flagged = js("let helper = () => 2;\nlet o = {};\n({a = helper()} = o);\n");
        assert!(
            filtered(&flagged, "S3353")
                .iter()
                .any(|message| message.contains("'helper'")),
            "helper should keep its const suggestion"
        );
    }
}
