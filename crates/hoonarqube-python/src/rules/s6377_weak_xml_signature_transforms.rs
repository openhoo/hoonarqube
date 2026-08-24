use crate::support::collect_string_contents;
use crate::support::for_each_attr_load;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s6377_weak_xml_signature_transforms(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_attr_load(parsed.syntax().body.as_slice(), "TransformMd5", |attr| {
        issues.push(issue_at(
            "python:S6377",
            "Validate this XML signature with a strong digest algorithm.",
            attr.range(),
            index,
            source,
        ));
    });
    for (text, range) in collect_string_contents(parsed.syntax().body.as_slice()) {
        if text == WEAK_XML_DIGEST_URI {
            issues.push(issue_at(
                "python:S6377",
                "Validate this XML signature with a strong digest algorithm.",
                range,
                index,
                source,
            ));
        }
    }
    issues
}

// --- migrated from support/mod.rs (S6377) ---
// --- python:S6377 — XML signatures validated securely ---------------------------

pub(crate) const WEAK_XML_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6377_flags_weak_xml_signature_digests() {
        let flagged = concat!(
            "t = xmlsec.constants.TransformMd5\n",
            "uri = \"http://www.w3.org/2001/04/xmldsig-more#md5\"\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S6377").len(), 2);
        let clean = concat!(
            "t2 = xmlsec.constants.TransformSha256\n",
            "uri2 = \"http://www.w3.org/2001/04/xmlenc#sha256\"\n"
        );
        assert!(findings(&scan(clean), "python:S6377").is_empty());
    }
}
