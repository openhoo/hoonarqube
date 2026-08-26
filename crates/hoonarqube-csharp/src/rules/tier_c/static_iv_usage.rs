use super::support::is_static_literal;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, expression_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3329 — symmetric-cipher initialization vectors set from
/// compile-time constants. Subset: `X.IV = <static literal>` assignments
/// (statements and object initializers) and two-argument
/// `CreateEncryptor/CreateDecryptor` calls whose second argument is static.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const KEY_DERIVATION_CALLS: [&str; 2] = ["CreateEncryptor", "CreateDecryptor"];
    let assignments = collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| {
            assignment
                .child_by_field_name("left")
                .is_some_and(|left| expression_name(left, source) == Some("IV"))
        })
        .filter(|assignment| {
            assignment
                .child_by_field_name("right")
                .is_some_and(|right| is_static_literal(right, source))
        });
    let derivations = collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            callee_name(*call, source).is_some_and(|callee| KEY_DERIVATION_CALLS.contains(&callee))
        })
        .filter(|call| invocation_arguments(*call).len() == 2)
        .filter(|call| {
            invocation_arguments(*call)
                .into_iter()
                .nth(1)
                .is_some_and(|argument| is_static_literal(argument_expression(argument), source))
        });
    assignments
        .chain(derivations)
        .map(|site| {
            issue(
                language,
                "S3329",
                "Generate this initialization vector randomly for each encryption instead of using this constant.",
                range_of(site, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3329_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S3329").is_empty());
    }

    #[test]
    fn s3329_flags_create_decryptor_with_static_vector() {
        let report = analyze_default(
            "byte[] Decrypt(byte[] key)\n{\n    var transform = aes.CreateDecryptor(key, new byte[] { 7, 9 });\n    return transform;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3329");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s3329_boundary_single_argument_encryptor_is_not_flagged() {
        let report = analyze_default("var enc = aes.CreateEncryptor(key);\n");
        assert!(with_key(&report, "csharpsquid:S3329").is_empty());
    }

    #[test]
    fn s3329_boundary_static_first_argument_alone_is_not_flagged() {
        let report =
            analyze_default("var enc = aes.CreateEncryptor(new byte[] { 1 }, ivStream);\n");
        assert!(with_key(&report, "csharpsquid:S3329").is_empty());
    }

    #[test]
    fn s3329_runtime_generated_vectors_stay_clean() {
        let report = analyze_default(
            "aes.IV = ivBuffer;\nvar dec = aes.CreateDecryptor(masterKey, ivBuffer);\n",
        );
        assert!(with_key(&report, "csharpsquid:S3329").is_empty());
    }

    #[test]
    fn s3329_flags_two_static_assignments_on_distinct_lines() {
        let report =
            analyze_default("aes.IV = \"0123456789abcdef\";\ncipher.IV = \"abcdefghijklmnop\";\n");
        let flagged = with_key(&report, "csharpsquid:S3329");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 2);
    }
}
