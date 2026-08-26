use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2115 — hard-coded database passwords leak with the source.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let inner = literal_inner_text(literal, source);
        let lowered = inner.to_ascii_lowercase();
        if !lowered.contains("password=") && !lowered.contains("pwd=") {
            continue;
        }
        if lowered.contains("integrated security") {
            continue;
        }
        if embedded_password_value(inner, &lowered).is_some_and(|value| !value.is_empty()) {
            issues.push(issue(
                language,
                "S2115",
                "Do not embed credentials in this connection string.",
                range_of(literal, source),
            ));
        }
    }
    issues
}

/// The credential value inside a connection-string literal, if present.
fn embedded_password_value<'a>(literal_text: &'a str, lowered: &str) -> Option<&'a str> {
    for marker in ["password=", "pwd="] {
        if let Some(position) = lowered.find(marker) {
            let value_start = position + marker.len();
            let value_end = lowered[value_start..]
                .find(';')
                .map_or(lowered.len(), |relative| value_start + relative);
            return Some(literal_text[value_start..value_end].trim_matches('"'));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2115_flags_pwd_marker_and_unterminated_values() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var shortHand = \"User=u;pwd=hunter2;\";\n        var unterminated = \"Server=s;PASSWORD=top\";\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2115").len(), 2);
    }
}
