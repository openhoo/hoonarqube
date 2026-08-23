use crate::support::WEAK_XML_DIGEST_URI;
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
