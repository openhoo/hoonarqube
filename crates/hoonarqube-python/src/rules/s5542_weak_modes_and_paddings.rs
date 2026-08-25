use crate::support::for_each_attr_load;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s5542_weak_modes_and_paddings(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for name in WEAK_MODE_OR_PADDING_NAMES {
        for_each_attr_load(parsed.syntax().body.as_slice(), name, |attr| {
            issues.push(issue_at(
                "python:S5542",
                "Replace this weak cipher mode or padding scheme.",
                attr.range(),
                index,
                source,
            ));
        });
    }
    issues
}

// --- migrated from support/mod.rs (S5542) ---
// --- python:S5542 — weak cipher modes and paddings -----------------------------

const WEAK_MODE_OR_PADDING_NAMES: [&str; 2] = ["MODE_ECB", "PKCS1v15"];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5542_flags_ecb_mode_and_weak_padding() {
        let flagged = "c = AES.new(k, AES.MODE_ECB)\np = padding.PKCS1v15()\n";
        assert_eq!(findings(&scan(flagged), "python:S5542").len(), 2);
        let clean = "g = AES.new(k, AES.MODE_GCM)\no = padding.OAEP(mgf=mgf1)\n";
        assert!(findings(&scan(clean), "python:S5542").is_empty());
    }
}
