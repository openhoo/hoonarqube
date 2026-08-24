use crate::support::dotted_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_s2755_xxe_parsers(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const XXE_ALIASES: [&str; 6] = [
        ("etree.parse"),
        ("etree.fromstring"),
        ("minidom.parse"),
        ("minidom.parseString"),
        ("sax.parse"),
        ("sax.parseString"),
    ];
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let unsafe_parser = dotted_name(&call.func).is_some_and(|path| {
            XXE_PARSER_CALLS.contains(&path.as_str())
                || XXE_ALIASES.iter().any(|alias| path.ends_with(alias))
        });
        if unsafe_parser {
            issues.push(issue_at(
                "python:S2755",
                "Disable external entity resolution or use a defused XML parser here.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S2755) ---
// --- python:S2755 — XML parsers vulnerable to XXE -------------------------------

pub(crate) const XXE_PARSER_CALLS: [&str; 12] = [
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.XMLParser",
    "lxml.etree.parse",
    "lxml.etree.fromstring",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",
    "xml.sax.parse",
    "xml.sax.parseString",
    "ET.parse",
    "ET.fromstring",
    "ET.XMLParser",
];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2755_flags_unsafe_xml_parsers() {
        let flagged = concat!(
            "doc = ET.parse(path)\n",
            "node = lxml.etree.fromstring(text)\n",
            "xml.sax.parse(file, handler)\n"
        );
        assert_eq!(findings(&scan(flagged), "python:S2755").len(), 3);
        let clean = concat!(
            "doc = defusedxml.ElementTree.parse(path)\n",
            "data = json.load(file)\n"
        );
        assert!(findings(&scan(clean), "python:S2755").is_empty());
    }
}
