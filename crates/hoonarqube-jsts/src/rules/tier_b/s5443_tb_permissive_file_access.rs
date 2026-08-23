// Rule module s5443_tb_permissive_file_access (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S5443`: permissive file modes or temp paths without exclusive flags.
pub(crate) fn check_tb_permissive_file_access(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = PermissiveAccessCollector::default();
    collector.visit_program(program);
    for (span, kind) in collector.sites {
        let message = match kind {
            "mode" => {
                "This file mode grants group/other write permission; tighten it (e.g. '0o644')."
            }
            _ => {
                "Writing into a world-writable temp path needs an exclusive flag against symlink attacks."
            }
        };
        sink.emit_span(RuleScope::Both, "S5443", message, span);
    }
}

/// Permissive file modes and unprotected temp-dir writes (`S5443`).
#[derive(Default)]
pub(crate) struct PermissiveAccessCollector {
    pub(crate) sites: Vec<(Span, &'static str)>,
}
