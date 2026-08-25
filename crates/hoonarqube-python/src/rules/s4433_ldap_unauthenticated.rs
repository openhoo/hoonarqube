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

// --- migrated from support/mod.rs (S4433) ---
// --- python:S4433 — LDAP connections should be authenticated -------------------

const LDAP_BIND_METHODS: [&str; 4] = ["simple_bind", "simple_bind_s", "bind", "bind_s"];

const LDAP_SEARCH_METHODS: [&str; 3] = ["search_s", "search_ext_s", "search_st"];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s4433_flags_unauthenticated_ldap_searches() {
        let flagged = "con = ldap.initialize(url)\ncon.search_s(base, scope)\n";
        assert_eq!(findings(&scan(flagged), "python:S4433").len(), 1);
        let clean = concat!(
            "con = ldap.initialize(url)\n",
            "con.simple_bind_s(\"user\", \"secret\")\n",
            "con.search_s(base, scope)\n"
        );
        assert!(findings(&scan(clean), "python:S4433").is_empty());
        assert_eq!(
            findings(&scan("ldap.simple_bind(\"\", \"\")\n"), "python:S4433").len(),
            1
        );
    }
}
