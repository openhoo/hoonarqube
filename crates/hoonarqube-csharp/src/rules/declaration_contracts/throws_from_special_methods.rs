use super::support::owned_by_callable;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3877 — Dispose/Finalize/Equals/GetHashCode/ToString run
/// during sensitive operations and must not throw.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for callable in collect_kinds(root, &["method_declaration", "destructor_declaration"]) {
        if is_error_tainted(callable) {
            continue;
        }
        let special = callable.child_by_field_name("name").is_some_and(|name| {
            let method_name = node_text(name, source);
            SPECIAL_THROW_METHODS.contains(&method_name)
                && (method_name != "Dispose" || parameters_of(callable).is_empty())
        });
        if !special {
            continue;
        }
        for throw_statement in collect_kinds(callable, &["throw_statement"])
            .into_iter()
            .filter(|throw_statement| owned_by_callable(*throw_statement, callable))
        {
            if is_error_tainted(throw_statement) {
                continue;
            }
            issues.push(issue(
                language,
                "S3877",
                "Remove this 'throw' statement.",
                range_of(throw_statement, source),
            ));
        }
    }
    issues
}

/// Methods that must never throw once running.
const SPECIAL_THROW_METHODS: [&str; 5] =
    ["Dispose", "Finalize", "Equals", "GetHashCode", "ToString"];
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3877_flags_dispose_and_gethashcode_throws() {
        let dispose = analyze_default(
            "class C : System.IDisposable\n{\n    public void Dispose()\n    {\n        throw new System.Exception();\n    }\n}\n",
        );
        assert_eq!(with_key(&dispose, "csharpsquid:S3877").len(), 1);

        let hash = analyze_default(
            "class C\n{\n    public override int GetHashCode()\n    {\n        throw new System.Exception();\n    }\n}\n",
        );
        assert_eq!(with_key(&hash, "csharpsquid:S3877").len(), 1);
    }

    #[test]
    fn s3877_counts_every_throw_statement() {
        let report = analyze_default(
            "class C\n{\n    public void Dispose()\n    {\n        if (failFast)\n        {\n            throw new System.Exception();\n        }\n        throw new System.InvalidOperationException();\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3877").len(), 2);
    }

    #[test]
    fn s3877_spares_similarly_named_regular_methods() {
        let report = analyze_default(
            "class C\n{\n    void DisposeAll()\n    {\n        throw new System.Exception();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3877").is_empty());
    }

    #[test]
    fn s3877_spares_throws_owned_by_nested_callables() {
        let report = analyze_default(
            "class C\n{\n    public override string ToString()\n    {\n        void Fail() { throw new System.Exception(); }\n        System.Func<string> delayed = () => throw new System.Exception();\n        return \"ok\";\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3877").is_empty());
    }
}
