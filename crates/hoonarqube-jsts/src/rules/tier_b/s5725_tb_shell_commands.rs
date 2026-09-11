// S5725 is the JavaScript external-script integrity rule. Shell command
// heuristics must not emit this key; keeping the generated entry point as a
// no-op preserves the family wiring while avoiding a rule-ID collision.
pub(crate) fn check_tb_shell_commands(
    _program: &oxc_ast::ast::Program<'_>,
    _sink: &mut crate::support::IssueSink<'_>,
) {
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn shell_commands_do_not_use_script_integrity_rule_key() {
        let source =
            js("exec('curl http://example.com/install.sh');\nspawn('npm install lodash');\n");
        assert_eq!(filtered(&source, "S5725").len(), 0);
    }
}
