use crate::engine::file_context::FileContext;
use crate::support::call_path_matches;
use crate::support::has_keyword;
use crate::support::is_call_method;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S4792 — configuring loggers is security-sensitive ----------------

pub(crate) fn check_s4792_logger_configuration(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    const LOGGER_CONFIG_APIS: [&str; 3] = [
        "logging.config.dictConfig",
        "logging.config.fileConfig",
        "logging.config.listen",
    ];
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let configured = call_path_matches(call, &LOGGER_CONFIG_APIS, &[], &[])
            || (is_call_method(call, "basicConfig") && has_keyword(&call.arguments, "handlers"));
        if configured {
            issues.push(issue_at(
                "python:S4792",
                "Make sure that this logger's configuration is safe.",
                call.range(),
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
    fn s4792_flags_logger_configuration_apis() {
        let flagged = concat!(
            "import logging.config\n",
            "logging.config.dictConfig({})\n",
            "logging.config.fileConfig(\"log.ini\")\n",
            "logging.basicConfig(handlers=[h])\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S4792").len(), 3);
        let clean = concat!(
            "import logging\n",
            "logging.basicConfig(level=\"INFO\")\n",
            "logging.info(\"hello\")\n"
        );
        assert!(findings(&scan(clean), "python:S4792").is_empty());
    }
}
