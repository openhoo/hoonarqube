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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn permissive_modes_and_tmp_paths_flagged() {
        let modes = js("fs.open(path, 'w', 0o777);\nfs.writeFile(file, data, 511);\n");
        assert_eq!(filtered(&modes, "S5443").len(), 2);
        let safe_mode = js("fs.open(path, 'w', 0o644);\n");
        assert_eq!(filtered(&safe_mode, "S5443").len(), 0);
        let tmp = js("fs.writeFile(os.tmpdir() + '/out.txt', data);\n");
        assert_eq!(filtered(&tmp, "S5443").len(), 1);
        let exclusive =
            js("fs.writeFile('/tmp/out.txt', data, { flag: 'wx' });\nfs.open('/tmp/x', 'ax');\n");
        assert_eq!(filtered(&exclusive, "S5443").len(), 0);
    }
}
