use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S112 — reserved exception types say nothing about the
/// failure and force callers to over-catch.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            RESERVED_EXCEPTION_TYPES.contains(&simple_name(creation_type_text(*creation, source)))
        })
        .map(|creation| {
            issue(
                language,
                "S112",
                "Throw a more specific exception than this reserved type.",
                range_of(creation, source),
            )
        })
        .collect()
}

/// Reserved exception types that carry no domain meaning.
const RESERVED_EXCEPTION_TYPES: [&str; 3] =
    ["Exception", "ApplicationException", "SystemException"];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s112_flags_system_exception_creations_outside_throws() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        throw new System.ApplicationException(\"q\");\n        Log(new SystemException());\n        var wrapped = new ApplicationExceptionWrapper();\n        var fine = new InvalidOperationException(\"ok\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S112");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }
}
