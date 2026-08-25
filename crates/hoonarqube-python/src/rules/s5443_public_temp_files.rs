use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5443_public_temp_files(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        let public_temp = called_name(&call.func) == Some("open")
            && call
                .arguments
                .args
                .first()
                .and_then(string_literal_text)
                .is_some_and(|path| {
                    PUBLIC_TEMP_PREFIXES
                        .iter()
                        .any(|prefix| path.starts_with(prefix))
                });
        if public_temp {
            issues.push(issue_at(
                "python:S5443",
                "Create this temporary file in a directory with restricted permissions.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S5443 — temporary files in publicly writable directories -----------

const PUBLIC_TEMP_PREFIXES: [&str; 3] = ["/tmp/", "/var/tmp/", "/dev/shm"];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5443_flags_temp_files_in_public_directories() {
        let flagged = concat!(
            "open(\"/tmp/app.log\", \"w\")\n",
            "open(\"/var/tmp/data.csv\")\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S5443").len(), 2);
        let clean = concat!("open(\"app.log\")\n", "tempfile.NamedTemporaryFile()\n");
        assert!(findings(&scan(clean), "python:S5443").is_empty());
    }
}
