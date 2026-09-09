use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::keyword_value;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4721 — OS commands should not run through a shell interpreter ---

pub(crate) fn check_s4721_shell_commands(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const SHELL_LAUNCHERS: [KnownBinding; 6] = [
        KnownBinding::SubprocessRun,
        KnownBinding::SubprocessPopen,
        KnownBinding::SubprocessCall,
        KnownBinding::SubprocessCheckCall,
        KnownBinding::SubprocessCheckOutput,
        KnownBinding::SubprocessGetoutput,
    ];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let identity = file_ctx.known_bindings.resolve_call(call);
        let shells_out = matches!(identity, KnownBinding::OsSystem | KnownBinding::OsPopen);
        let always_uses_shell = matches!(
            identity,
            KnownBinding::SubprocessGetoutput | KnownBinding::SubprocessGetstatusoutput
        );
        let forces_shell = SHELL_LAUNCHERS.contains(&identity)
            && keyword_value(&call.arguments, "shell").is_some_and(is_true_literal);
        if shells_out || always_uses_shell || forces_shell {
            issues.push(issue_at(
                "python:S4721",
                "Make sure that executing this OS command is safe here.",
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s4721_flags_shell_interpreter_usage() {
        let flagged = concat!(
            "subprocess.run(cmd, shell=True)\n",
            "os.system(cmd)\n",
            "os.popen(cmd)\n",
            "subprocess.Popen(cmd, shell=True)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S4721").len(), 4);
        assert!(
            findings(
                &scan(concat!(
                    "subprocess.run([\"ls\"], shell=False)\n",
                    "os.getcwd()\n"
                )),
                "python:S4721"
            )
            .is_empty()
        );
    }
    #[test]
    fn s4721_resolves_shell_api_aliases_and_status_output() {
        let flagged = concat!(
            "from subprocess import run as execute\n",
            "execute(input(), shell=True)\n",
            "subprocess.getoutput(input())\n",
            "subprocess.getstatusoutput(input())\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S4721").len(), 3);
        let clean = concat!(
            "def run(value, *, shell):\n",
            "    return value\n",
            "run(input(), shell=True)\n",
            "class Runner:\n",
            "    def getoutput(self, value):\n",
            "        return value\n",
            "Runner().getoutput(input())\n",
            "from subprocess import run as execute\n",
            "execute(input(), shell=False)\n"
        );
        assert!(findings(&scan(clean), "python:S4721").is_empty());
    }
}
