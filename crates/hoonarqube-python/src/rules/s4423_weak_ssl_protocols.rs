use crate::support::for_each_attr_load;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s4423_weak_ssl_protocols(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for protocol in WEAK_PROTOCOL_CONSTANTS {
        for_each_attr_load(parsed.syntax().body.as_slice(), protocol, |attr| {
            issues.push(issue_at(
                "python:S4423",
                "Replace this weak SSL/TLS protocol with a modern alternative.",
                attr.range(),
                index,
                source,
            ));
        });
    }
    issues
}

// --- migrated from support/mod.rs (S4423) ---
// --- python:S4423 — weak SSL/TLS protocols ------------------------------------

pub(crate) const WEAK_PROTOCOL_CONSTANTS: [&str; 4] = [
    "PROTOCOL_SSLv2",
    "PROTOCOL_SSLv3",
    "PROTOCOL_TLSv1",
    "PROTOCOL_TLSv1_1",
];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4423_flags_weak_ssl_protocol_constants() {
        let flagged = concat!(
            "ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)\n",
            "wrap(sock, ssl_version=ssl.PROTOCOL_TLSv1)\n",
            "v = ssl.PROTOCOL_SSLv2\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S4423").len(), 3);
        let clean = concat!(
            "ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)\n",
            "v2 = ssl.PROTOCOL_TLSv1_2\n"
        );
        assert!(findings(&scan(clean), "python:S4423").is_empty());
    }
}
