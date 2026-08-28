use crate::engine::file_context::FileContext;
use crate::support::for_each_attr_load;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// --- python:S4830 — server certificates verified during SSL/TLS --------------

pub(crate) fn check_s4830_certificate_verification(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    _file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_attr_load(parsed.syntax().body.as_slice(), "CERT_NONE", |attr| {
        if matches!(attr.value.as_ref(), Expr::Name(name) if name.id.as_str() == "ssl") {
            issues.push(issue_at(
                "python:S4830",
                "Enable server certificate validation on this SSL/TLS connection.",
                TextRange::new(
                    attr.end() - TextSize::from(to_u32(attr.attr.len())),
                    attr.end(),
                ),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4830_flags_disabled_certificate_verification() {
        let flagged = concat!(
            "requests.get(url, verify=False)\n",
            "ctx = ssl._create_unverified_context()\n",
            "ctx.verify_mode = ssl.CERT_NONE\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S4830").len(), 1);
        assert!(findings(&scan("requests.get(url)\n"), "python:S4830").is_empty());
    }
}
