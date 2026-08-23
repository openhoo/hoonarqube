use crate::support::XXE_PARSER_CALLS;
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
