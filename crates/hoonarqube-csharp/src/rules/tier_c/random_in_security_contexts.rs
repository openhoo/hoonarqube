use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, simple_name};
use crate::rules::expressions::creation_type_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2245 — every `new System.Random()` is a security hotspot:
/// the generator is deterministic and predictable, so the reference
/// platform reports each creation regardless of the surrounding naming.
/// Only the exact `Random` simple name counts (`System.Random` resolves to
/// it); look-alike types such as `SecureRandom` stay silent.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues: Vec<Issue> = collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| simple_name(creation_type_text(*creation, source)) == "Random")
        .map(|creation| {
            issue(
                language,
                "S2245",
                "Make sure that using this pseudorandom number generator is safe here.",
                range_of(creation, source),
            )
        })
        .collect();
    issues.extend(
        collect_kinds(root, &["implicit_object_creation_expression"])
            .into_iter()
            .filter(|creation| !is_error_tainted(*creation))
            .filter(|creation| implicit_target_is_random(*creation, source))
            .map(|creation| {
                issue(
                    language,
                    "S2245",
                    "Make sure that using this pseudorandom number generator is safe here.",
                    range_of(creation, source),
                )
            }),
    );
    issues
}

/// Whether a target-typed `new()` provably creates a `Random`: the nearest
/// enclosing declaration spells `Random` as its type (`Random r = new();`).
fn implicit_target_is_random(creation: Node<'_>, source: &str) -> bool {
    let mut ancestor = creation.parent();
    while let Some(current) = ancestor {
        match current.kind() {
            "variable_declaration" | "property_declaration" => {
                return current
                    .child_by_field_name("type")
                    .is_some_and(|ty| simple_name(crate::cst::node_text(ty, source)) == "Random");
            }
            "method_declaration"
            | "local_function_statement"
            | "lambda_expression"
            | "class_declaration"
            | "struct_declaration" => return false,
            _ => ancestor = current.parent(),
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2245_minimal_class_without_random_creations_stays_silent() {
        let report = analyze_default(
            "class Vault\n{\n    void Rotate()\n    {\n        var seed = 1234;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2245").is_empty());
    }

    #[test]
    fn s2245_flags_every_random_creation_regardless_of_context() {
        let report = analyze_default(
            "class Bench\n{\n    protected static readonly Random _rand = new Random();\n    void Roll()\n    {\n        var rng = new Random();\n        rng.Next();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2245_flags_seeded_and_qualified_random_creations() {
        let report = analyze_default(
            "class Bench\n{\n    void Roll()\n    {\n        var a = new Random(42);\n        var b = new System.Random();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2245_ignores_look_alike_random_type_names() {
        let report = analyze_default(
            "class Bench\n{\n    void Roll()\n    {\n        var a = new SecureRandom();\n        var b = new MyRandom();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2245").is_empty());
    }

    #[test]
    fn s2245_ignores_random_shared_and_method_receivers() {
        let report = analyze_default(
            "class Bench\n{\n    void Roll()\n    {\n        var a = Random.Shared;\n        var b = Random.Shared.Next();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2245").is_empty());
    }

    #[test]
    fn s2245_flags_target_typed_new_when_declared_type_is_random() {
        let report = analyze_default(
            "class Bench\n{\n    private static readonly Random _rand = new();\n    void Roll()\n    {\n        Random local = new();\n        local.Next();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2245");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 3);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2245_ignores_target_typed_new_of_other_types() {
        let report = analyze_default(
            "class Bench\n{\n    void Roll()\n    {\n        var local = new System.Text.StringBuilder();\n        System.Text.StringBuilder other = new();\n        local.Append(other);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2245").is_empty());
    }
}
