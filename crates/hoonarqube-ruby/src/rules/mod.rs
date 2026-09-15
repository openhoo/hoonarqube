//! Cataloged Sonar-rule detectors backing the Ruby sonar-parity route.
//!
//! Every detector here implements a rule frozen in `hoonarqube-catalog`
//! (`ruby:...` external key). The route runs only on parseable sources:
//! recovered trees fail closed, mirroring the other language frontends.

mod duplicate_string_literals;

use crate::AnalyzerOptions;
use hoonarqube_ir::Issue;
use tree_sitter::Tree;

/// Sonar rule keys implemented by this route, in catalog external-key form.
pub(crate) const RULE_KEYS: &[&str] = &["ruby:S1192"];

/// Runs every cataloged Ruby detector over one parseable source.
pub(crate) fn check_sonar_rules(
    tree: &Tree,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    debug_assert_eq!(RULE_KEYS.len(), 1);
    let mut issues = Vec::new();
    issues.extend(duplicate_string_literals::check(
        tree.root_node(),
        source,
        options,
    ));
    debug_assert!(
        issues
            .iter()
            .all(|issue| RULE_KEYS.contains(&issue.rule_key.as_str()))
    );
    issues
}
