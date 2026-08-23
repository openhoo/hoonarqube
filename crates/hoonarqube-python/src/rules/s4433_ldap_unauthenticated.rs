use crate::support::LDAP_BIND_METHODS;
use crate::support::LDAP_SEARCH_METHODS;
use crate::support::called_name;
use crate::support::for_each_call;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

pub(crate) fn check_s4433_ldap_unauthenticated(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let mut has_bind = false;
    let mut pending: Vec<(bool, TextRange)> = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        let method = called_name(&call.func).unwrap_or_default();
        if LDAP_BIND_METHODS.contains(&method) {
            has_bind = true;
            let empty_credentials = call.arguments.args.iter().take(2).count() == 2
                && call
                    .arguments
                    .args
                    .iter()
                    .take(2)
                    .all(|arg| string_literal_text(arg).is_some_and(|text| text.is_empty()));
            pending.push((empty_credentials, call.range()));
        } else if LDAP_SEARCH_METHODS.contains(&method) {
            pending.push((false, call.range()));
        }
    });
    for (empty_credentials, range) in pending {
        let method = source
            .get(range.start().to_usize()..range.end().to_usize())
            .unwrap_or_default();
        let unbound_search = LDAP_SEARCH_METHODS.iter().any(|m| method.contains(m)) && !has_bind;
        if empty_credentials || unbound_search {
            issues.push(issue_at(
                "python:S4433",
                "Bind this LDAP connection with credentials before searching.",
                range,
                index,
                source,
            ));
        }
    }
    issues
}
