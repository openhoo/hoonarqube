use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::collect_string_contents;
use crate::support::for_each_attr_load;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const TRUST_MESSAGE: &str =
    "Change this code to only accept signatures computed from a trusted party.";

pub(crate) fn check_s6377_weak_xml_signature_transforms(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
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
    for call in &file_ctx.calls {
        if file_ctx.known_bindings.resolve_call(call) != KnownBinding::SignxmlVerify
            || has_trusted_certificate(call)
        {
            continue;
        }
        issues.push(issue_at(
            "python:S6377",
            TRUST_MESSAGE,
            call.func.range(),
            index,
            source,
        ));
    }
    issues
}

fn has_trusted_certificate(call: &ExprCall) -> bool {
    call.arguments.keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|name| name.as_str() == "x509_cert")
            && !matches!(&keyword.value, Expr::NoneLiteral(_))
    })
}

// --- python:S6377 — XML signatures validated securely ---------------------------

const WEAK_XML_DIGEST_URI: &str = "http://www.w3.org/2001/04/xmldsig-more#md5";

#[cfg(test)]
mod tests {

    use super::TRUST_MESSAGE;
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

    #[test]
    fn s6377_requires_a_trusted_certificate_on_signxml_verify() {
        let attack = concat!(
            "from signxml import XMLVerifier\n",
            "XMLVerifier().verify(xml)\n",
        );
        let report = scan(attack);
        let found = findings(&report, "python:S6377");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].message, TRUST_MESSAGE);

        let safe = concat!(
            "from signxml import XMLVerifier\n",
            "XMLVerifier().verify(xml, x509_cert=cert)\n",
        );
        assert!(findings(&scan(safe), "python:S6377").is_empty());

        let local_impostor = concat!(
            "class XMLVerifier:\n",
            "    def verify(self, xml):\n",
            "        return True\n",
            "XMLVerifier().verify(xml)\n",
        );
        assert!(findings(&scan(local_impostor), "python:S6377").is_empty());
    }
}
