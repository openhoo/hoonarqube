use super::support::methods_grouped_by_name;
use crate::CsLanguage;
use crate::cst::{issue, range_of, simple_name};
use crate::rules::security::return_type_text;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3995 — string returns beside a sibling `System.Uri`
/// overload lose structure.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let returns_uri = methods
            .iter()
            .any(|method| simple_name(return_type_text(*method, source)) == "Uri");
        if !returns_uri {
            continue;
        }
        for method in &methods {
            if simple_name(return_type_text(*method, source)) == "string" {
                issues.push(issue(
                    language,
                    "S3995",
                    "Return a 'System.Uri' instead of a string here.",
                    range_of(name_anchor(*method), source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3995_parameter_overloads_without_uri_returns_are_clean() {
        let report = analyze_default(
            "class C\n{\n    public string Load(string path) { return path; }\n    public string Load(Uri path) { return \"\"; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3995").is_empty());
    }

    #[test]
    fn s3995_flags_only_the_string_return_of_a_uri_group() {
        let report = analyze_default(
            "class C\n{\n    public Uri Load() { return null!; }\n    public string Load() { return \"\"; }\n    public int Save() { return 0; }\n    public string Save() { return \"\"; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4); // document line 3
    }

    #[test]
    fn s3995_accepts_namespace_qualified_uri_siblings() {
        let report = analyze_default(
            "class C\n{\n    public System.Uri Load() { return null!; }\n    public string Load() { return \"\"; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3995");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4); // document line 3
    }

    #[test]
    fn s3995_empty_class_is_clean() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3995").is_empty());
    }
}
