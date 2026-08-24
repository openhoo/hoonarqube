use crate::engine::rx::RegexSite;
use crate::engine::rx::parse_regex;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S5860 — `.group("name")` references versus named groups defined in
/// any literal pattern of the file.
pub(crate) fn check_named_group_references(
    body: &[Stmt],
    sites: &[RegexSite],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let defined: std::collections::BTreeSet<String> = sites
        .iter()
        .filter_map(|site| site.pattern.as_ref())
        .filter_map(|units| parse_regex(units).ok())
        .flat_map(|parsed| parsed.names.into_iter())
        .collect();
    if defined.is_empty() {
        return;
    }
    for_each_call(body, &mut |call| {
        if called_name(&call.func) == Some("group")
            && let Some(argument) = call.arguments.args.first()
            && let Expr::StringLiteral(literal) = argument
        {
            let name = string_value_text(&literal.value);
            if !defined.contains(&name) {
                issues.push(issue_at(
                    "python:S5860",
                    "Reference an existing named group instead of a number or an unknown name.",
                    literal.range(),
                    index,
                    source,
                ));
            }
        }
    });
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s5860_flags_unknown_named_group_references() {
        let flagged = concat!(
            "import re\n",
            "pattern = re.compile(r'(?P<a>.)')\n",
            "matches = pattern.match(s)\n",
            "g = matches.group('b')\n"
        );
        assert!(regex_finds(flagged, "python:S5860"));
        let compliant = concat!(
            "import re\n",
            "pattern = re.compile(r'(?P<a>.)')\n",
            "matches = pattern.match(s)\n",
            "g = matches.group('a')\n"
        );
        assert!(!regex_finds(compliant, "python:S5860"));
        // Without any named groups in the file there is no signal.
        assert!(!regex_finds("matches.group('anything')\n", "python:S5860"));
    }
}
