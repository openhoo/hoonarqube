//! Cataloged Sonar-rule detectors backing the Java sonar-parity route.
//!
//! Every detector here implements a rule frozen in `hoonarqube-catalog`
//! (`java:...` external key). The route runs only on parseable sources:
//! recovered trees fail closed, mirroring the other language frontends.
//! None of the batch-1 rules carry catalog parameters, so `AnalyzerOptions`
//! is threaded through unchanged for later batches.

mod dead_assignment;
mod lambda_parameter_types;
mod legacy_datetime;
mod local_shadows_field;

use crate::AnalyzerOptions;
use crate::context::SemanticIndex;
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use tree_sitter::Tree;

/// Sonar rule keys implemented by this route, in catalog external-key form.
pub(crate) const RULE_KEYS: &[&str] = &["java:S1117", "java:S1854", "java:S2143", "java:S2211"];

/// Runs every cataloged Java detector over one parseable source.
pub(crate) fn check_sonar_rules(
    tree: &Tree,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let root = tree.root_node();
    if root.has_error() {
        return Vec::new();
    }
    let _ = options;
    let lines = LineIndex::new(source);
    let semantics = SemanticIndex::build(root, source, &lines);
    let mut issues = Vec::new();
    issues.extend(local_shadows_field::check(root, source, &lines));
    issues.extend(dead_assignment::check(root, source, &lines, &semantics));
    issues.extend(lambda_parameter_types::check(root, source, &lines));
    issues.extend(legacy_datetime::check(root, source));
    hoonarqube_ir::sort_issues(&mut issues);
    debug_assert!(
        issues
            .iter()
            .all(|issue| RULE_KEYS.contains(&issue.rule_key.as_str()))
    );
    issues
}
