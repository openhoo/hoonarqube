// Rule module s5725_tb_shell_commands (generated).
use crate::support::{IssueSink, RuleScope};
use oxc_ast_visit::Visit;
use oxc_span::Span;

/// `S5725`: `http://` downloads and unpinned installs in shell commands.
pub(crate) fn check_tb_shell_commands(
    program: &oxc_ast::ast::Program<'_>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = ShellCommandCollector::default();
    collector.visit_program(program);
    for (span, kind) in collector.sites {
        let message = match kind {
            "http" => {
                "Download over 'http://' allows tampering; use 'https://' and verify checksums."
            }
            _ => "Pin dependency versions in install commands to make builds reproducible.",
        };
        sink.emit_span(RuleScope::Both, "S5725", message, span);
    }
}

/// Insecure commands passed to shell-execution functions (`S5725`).
#[derive(Default)]
pub(crate) struct ShellCommandCollector {
    pub(crate) sites: Vec<(Span, &'static str)>,
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn shell_commands_flag_http_downloads_and_unpinned_installs() {
        let flagged =
            js("exec('curl http://example.com/install.sh');\nspawn('npm install lodash');\n");
        assert_eq!(filtered(&flagged, "S5725").len(), 2);
        let clean = js(
            "exec('curl https://example.com/install.sh');\nspawn('npm install lodash@4.17.21');\nexecFile('git', ['status']);\n",
        );
        assert_eq!(filtered(&clean, "S5725").len(), 0);
    }
}
