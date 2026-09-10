use super::support::is_static_literal;
use crate::CsLanguage;
use crate::cst::{
    ancestors_of, canonical_identifier, collect_kinds, is_error_tainted, issue, node_text,
    range_of, simple_name,
};
use crate::rules::dataflow::collect_owned_kinds;
use crate::rules::expressions::{
    callee_name, creation_type_text, enclosing_callable, invocation_arguments,
};
use crate::rules::literals::{argument_expression, declarator_initializer};
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    salted_hash_candidates(root, source)
        .into_iter()
        .filter(|candidate| has_static_salt(*candidate, source))
        .map(|candidate| {
            issue(
                language,
                "S2053",
                "Use a random, unpredictable salt for this password hashing call.",
                range_of(candidate, source),
            )
        })
        .collect()
}

fn has_static_salt(candidate: Node<'_>, source: &str) -> bool {
    let Some(argument) = selected_salt_argument(candidate, source) else {
        return false;
    };
    let value = argument_value_expression(argument);
    let static_value = is_static_literal(value, source)
        || (value.kind() == "identifier" && local_static_array_salt(value, candidate, source));
    static_value
        && !(candidate.kind() == "object_creation_expression"
            && argument.child_by_field_name("name").is_none()
            && is_numeric_literal(value))
}
/// Resolve only a local array declarator that is visible at the use site. The
/// callable and lexical-scope checks keep same-named fields, sibling methods,
/// and nested callable bindings out of the result.
fn local_static_array_salt(identifier: Node<'_>, use_site: Node<'_>, source: &str) -> bool {
    let Some((declarator, initializer)) = local_salt_binding(identifier, use_site, source) else {
        return false;
    };
    is_static_byte_array_literal(declarator, initializer, source)
        && !has_prior_salt_reference(declarator, use_site, identifier, source)
}

fn local_salt_binding<'t>(
    identifier: Node<'t>,
    use_site: Node<'t>,
    source: &str,
) -> Option<(Node<'t>, Node<'t>)> {
    if identifier.kind() != "identifier" {
        return None;
    }
    let owner = enclosing_callable(use_site)?;
    if enclosing_callable(identifier).is_none_or(|actual| actual.id() != owner.id()) {
        return None;
    }
    let wanted = canonical_identifier(node_text(identifier, source));
    collect_owned_kinds(owner, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.end_byte() < use_site.start_byte())
        .filter(|declarator| declaration_scope_contains(*declarator, use_site))
        .filter(|declarator| same_nearest_executable_block(*declarator, use_site))
        .filter(|declarator| !has_uncertain_control_flow(*declarator, use_site))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            (canonical_identifier(node_text(name, source)) == wanted).then_some((declarator, name))
        })
        .max_by_key(|(declarator, _)| declarator.start_byte())
        .and_then(|(declarator, name)| {
            declarator_initializer(declarator, name).map(|initializer| (declarator, initializer))
        })
}

fn is_static_byte_array_literal(declarator: Node<'_>, expression: Node<'_>, source: &str) -> bool {
    if !matches!(
        expression.kind(),
        "array_creation_expression"
            | "implicit_array_creation_expression"
            | "collection_expression"
    ) || !is_static_literal(expression, source)
    {
        return false;
    }
    expression
        .child_by_field_name("type")
        .or_else(|| {
            ancestors_of(declarator)
                .find(|ancestor| ancestor.kind() == "variable_declaration")
                .and_then(|declaration| declaration.child_by_field_name("type"))
        })
        .is_some_and(|type_node| is_byte_array_type(node_text(type_node, source)))
}

fn is_byte_array_type(type_text: &str) -> bool {
    let compact: String = type_text
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    matches!(
        compact.as_str(),
        "byte[]" | "System.Byte[]" | "global::System.Byte[]"
    )
}

/// A declaration is usable only when its nearest lexical scope also contains
/// the use. This intentionally rejects branch-local declarations used after
/// the branch and loop-header declarations used after the loop.
fn declaration_scope_contains(declarator: Node<'_>, use_site: Node<'_>) -> bool {
    const SCOPES: [&str; 14] = [
        "block",
        "switch_section",
        "for_statement",
        "foreach_statement",
        "using_statement",
        "fixed_statement",
        "if_statement",
        "while_statement",
        "do_statement",
        "lock_statement",
        "try_statement",
        "catch_clause",
        "finally_clause",
        "switch_statement",
    ];
    let Some(scope) = ancestors_of(declarator).find(|ancestor| SCOPES.contains(&ancestor.kind()))
    else {
        return false;
    };
    if matches!(
        scope.kind(),
        "if_statement" | "while_statement" | "do_statement" | "lock_statement"
    ) {
        let Some(declaration_region) = direct_child_under(declarator, scope) else {
            return false;
        };
        let Some(use_region) = direct_child_under(use_site, scope) else {
            return false;
        };
        if declaration_region.id() != use_region.id() {
            return false;
        }
    }
    ancestors_of(use_site).any(|ancestor| ancestor.id() == scope.id())
}

fn nearest_executable_block(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| matches!(ancestor.kind(), "block" | "switch_section"))
}

fn same_nearest_executable_block(left: Node<'_>, right: Node<'_>) -> bool {
    nearest_executable_block(left)
        .zip(nearest_executable_block(right))
        .is_some_and(|(left, right)| left.id() == right.id())
}

fn has_uncertain_control_flow(declarator: Node<'_>, use_site: Node<'_>) -> bool {
    let Some(block) = nearest_executable_block(use_site) else {
        return true;
    };
    if nearest_executable_block(declarator)
        .is_none_or(|declaration_block| declaration_block.id() != block.id())
    {
        return true;
    }
    !collect_kinds(block, &["goto_statement", "labeled_statement"]).is_empty()
}

fn direct_child_under<'tree>(node: Node<'tree>, ancestor: Node<'tree>) -> Option<Node<'tree>> {
    let mut current = node;
    while let Some(parent) = current.parent() {
        if parent.id() == ancestor.id() {
            return Some(current);
        }
        current = parent;
    }
    None
}

/// Any earlier read/write of the same binding makes the value unknown. This
/// covers reassignment, element mutation, aliasing, captured references, and
/// calls/returns that could let another operation mutate the array. The
/// selected salt expression is the only reference intentionally exempted.
fn has_prior_salt_reference(
    declarator: Node<'_>,
    use_site: Node<'_>,
    selected_value: Node<'_>,
    source: &str,
) -> bool {
    let Some(owner) = enclosing_callable(use_site) else {
        return true;
    };
    let after_declaration = declarator.end_byte();
    let through_candidate = use_site.end_byte();
    collect_kinds(owner, &["identifier"])
        .into_iter()
        .filter(|identifier| {
            identifier.start_byte() >= after_declaration
                && identifier.end_byte() <= through_candidate
        })
        .any(|identifier| {
            identifier.id() != selected_value.id()
                && !is_named_argument_label(identifier)
                && binding_declarator(identifier, owner, source)
                    .is_some_and(|bound| bound.id() == declarator.id())
        })
}

fn is_named_argument_label(identifier: Node<'_>) -> bool {
    identifier.parent().is_some_and(|parent| {
        parent.kind() == "argument"
            && parent
                .child_by_field_name("name")
                .is_some_and(|name| name.id() == identifier.id())
    })
}

fn binding_declarator<'t>(identifier: Node<'t>, owner: Node<'t>, source: &str) -> Option<Node<'t>> {
    if let Some(parent) = identifier.parent()
        && parent.kind() == "variable_declarator"
        && parent
            .child_by_field_name("name")
            .is_some_and(|name| name.id() == identifier.id())
    {
        return Some(parent);
    }
    if identifier.kind() != "identifier" {
        return None;
    }
    let wanted = canonical_identifier(node_text(identifier, source));
    if let Some(callable) = enclosing_callable(identifier)
        && callable.id() != owner.id()
        && callable_declares_binding(callable, wanted, identifier, source)
    {
        return None;
    }
    collect_owned_kinds(owner, &["variable_declarator"])
        .into_iter()
        .filter(|declarator| declarator.end_byte() <= identifier.start_byte())
        .filter(|declarator| declaration_scope_contains(*declarator, identifier))
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            (canonical_identifier(node_text(name, source)) == wanted).then_some(declarator)
        })
        .max_by_key(Node::start_byte)
}

fn callable_declares_binding(
    callable: Node<'_>,
    wanted: &str,
    use_site: Node<'_>,
    source: &str,
) -> bool {
    collect_kinds(callable, &["parameter", "implicit_parameter"])
        .into_iter()
        .filter(|parameter| {
            enclosing_callable(*parameter).is_some_and(|owner| owner.id() == callable.id())
        })
        .any(|parameter| {
            canonical_identifier(node_text(parameter, source)) == wanted
                || parameter
                    .child_by_field_name("name")
                    .is_some_and(|name| canonical_identifier(node_text(name, source)) == wanted)
        })
        || collect_kinds(callable, &["variable_declarator"])
            .into_iter()
            .filter(|declarator| {
                enclosing_callable(*declarator).is_some_and(|owner| owner.id() == callable.id())
            })
            .filter(|declarator| declaration_scope_contains(*declarator, use_site))
            .filter_map(|declarator| declarator.child_by_field_name("name"))
            .any(|name| canonical_identifier(node_text(name, source)) == wanted)
}

fn selected_salt_argument<'t>(candidate: Node<'t>, source: &str) -> Option<Node<'t>> {
    let arguments = invocation_arguments(candidate);
    arguments
        .iter()
        .find_map(|argument| {
            argument
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "salt")
                .then_some(*argument)
        })
        .or_else(|| {
            let argument = arguments.get(1).copied()?;
            argument
                .child_by_field_name("name")
                .is_none()
                .then_some(argument)
        })
}

fn argument_value_expression(argument: Node<'_>) -> Node<'_> {
    if argument.child_by_field_name("name").is_none() {
        return argument_expression(argument);
    }
    let mut cursor = argument.walk();
    argument
        .named_children(&mut cursor)
        .last()
        .unwrap_or(argument)
}

fn is_numeric_literal(expression: Node<'_>) -> bool {
    matches!(expression.kind(), "integer_literal" | "real_literal")
        || (expression.kind() == "prefix_unary_expression"
            && expression.named_child(0).is_some_and(|operand| {
                matches!(operand.kind(), "integer_literal" | "real_literal")
            }))
}

/// csharpsquid:S2053 — password hashing invoked with a compile-time constant
/// salt. Subset: `Rfc2898DeriveBytes` construction, `Rfc2898DeriveBytes.
/// Pbkdf2`, and `HashPassword/Pbkdf2/PBKDF2` calls. Only a named `salt`
/// argument or an unnamed second positional argument is considered. For
/// `Rfc2898DeriveBytes`, an unnamed numeric second argument denotes generated
/// `saltSize`; named `saltSize` and later iteration, algorithm, and
/// output-length arguments are not salts.
const SALT_TAKING_HASH_APIS: [&str; 3] = ["HashPassword", "Pbkdf2", "PBKDF2"];

fn salted_hash_candidates<'t>(root: Node<'t>, source: &str) -> Vec<Node<'t>> {
    let creations = collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| {
            simple_name(creation_type_text(*creation, source)) == "Rfc2898DeriveBytes"
        });
    let calls = collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| {
            callee_name(*call, source).is_some_and(|callee| SALT_TAKING_HASH_APIS.contains(&callee))
        });
    creations
        .chain(calls)
        .filter(|candidate| !is_error_tainted(*candidate))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2053_minimal_input_emits_nothing() {
        let report = analyze_default("class C\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_boundary_single_argument_creation_is_not_flagged() {
        let report = analyze_default(
            "byte[] Derive(byte[] password)\n{\n    var derive = new Rfc2898DeriveBytes(password);\n    return derive.GetBytes(16);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_boundary_literal_only_as_first_argument_is_not_flagged() {
        let report = analyze_default(
            "byte[] Load()\n{\n    byte[] hash = HashPassword(\"admin\", storedSalt);\n    return hash;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_flags_pbkdf2_uppercase_call_with_static_salt() {
        let report = analyze_default(
            "byte[] Derive(byte[] password)\n{\n    var derived = PBKDF2(password, \"static-pepper\", 1000, 32);\n    return derived;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2053");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 3);
    }

    #[test]
    fn s2053_runtime_generated_salt_control_stays_clean() {
        let report = analyze_default(
            "byte[] Derive(byte[] password)\n{\n    byte[] salt = RandomNumberGenerator.GetBytes(16);\n    var derive = new Rfc2898DeriveBytes(password, salt, 100000);\n    return derive.GetBytes(32);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_flags_local_constant_byte_array_salt() {
        let report = analyze_default(
            r"using System.Security.Cryptography;

public static class PasswordDerivation
{
    public static byte[] Derive(string password)
    {
        var salt = new byte[] { 0x53, 0x41, 0x4C, 0x54 };
        using var kdf = new Rfc2898DeriveBytes(
            password, salt, 1_000, HashAlgorithmName.SHA1);
        return kdf.GetBytes(32);
    }
}
",
        );
        let flagged = with_key(&report, "csharpsquid:S2053");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 8);
        assert_eq!(flagged[0].range.end.line, 9);
    }

    #[test]
    fn s2053_random_and_parameter_salts_stay_clean() {
        let report = analyze_default(
            r"using System.Security.Cryptography;

public static class PasswordDerivationAlias
{
    public static byte[] Derive(string password)
    {
        return DeriveConfigured(password, RandomNumberGenerator.GetBytes(16), 100_000);
    }

    private static byte[] DeriveConfigured(string password, byte[] salt, int iterations)
    {
        using var kdf = new Rfc2898DeriveBytes(
            password, salt, iterations, HashAlgorithmName.SHA256);
        return kdf.GetBytes(32);
    }
}
",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_rejects_mutated_escaped_shadowed_and_salt_size_bindings() {
        let report = analyze_default(
            r#"using System.Security.Cryptography;

public static class PasswordDerivationNegatives
{
    private static readonly byte[] salt = new byte[] { 1, 2 };

    private static void Consume(byte[] value) { }

    private static byte[] RandomSalt(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        using var kdf = new Rfc2898DeriveBytes(password, salt, 1_000);
        return kdf.GetBytes(32);
    }

    private static byte[] MutatedSalt(string password)
    {
        var salt = new byte[] { 1, 2 };
        salt[0] = 3;
        using var kdf = new Rfc2898DeriveBytes(password, salt, 1_000);
        return kdf.GetBytes(32);
    }

    private static byte[] EscapedSalt(string password)
    {
        var salt = new byte[] { 1, 2 };
        Consume(salt);
        using var kdf = new Rfc2898DeriveBytes(password, salt, 1_000);
        return kdf.GetBytes(32);
    }

    private static byte[] CapturedSalt(string password)
    {
        var salt = new byte[] { 1, 2 };
        void Mutate() { salt[0] = 3; }
        Mutate();
        using var kdf = new Rfc2898DeriveBytes(password, salt, 1_000);
        return kdf.GetBytes(32);
    }

    private static byte[] LoopSalt(string password)
    {
        var salt = new byte[] { 1, 2 };
        while (password.Length > 0)
        {
            using var kdf = new Rfc2898DeriveBytes(password, salt, 1_000);
            salt[0] = 3;
            return kdf.GetBytes(32);
        }
        return Array.Empty<byte>();
    }

    private static byte[] CandidateArgumentSalt(string password)
    {
        var salt = new byte[] { 1, 2 };
        using var kdf = new Rfc2898DeriveBytes(Mix(salt), salt, 1_000);
        return kdf.GetBytes(32);
    }

    private static string Mix(byte[] value) => "password";

    private static byte[] FieldSalt(string password)
    {
        using var kdf = new Rfc2898DeriveBytes(password, salt, 1_000);
        return kdf.GetBytes(32);
    }

    private static byte[] SaltSize(string password)
    {
        var saltSize = 16;
        using var kdf = new Rfc2898DeriveBytes(password, saltSize, 1_000);
        return kdf.GetBytes(32);
    }
}
"#,
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_named_salt_is_selected_without_confusing_iterations() {
        let report = analyze_default(
            "byte[] Derive(byte[] password, byte[] runtimeSalt)\n{\n    var safe = Pbkdf2(password, salt: RandomNumberGenerator.GetBytes(16), iterations: 100000, hashAlgorithm: HashAlgorithmName.SHA256, outputLength: 32);\n    var flagged = Pbkdf2(password, salt: new byte[] { 1, 2 }, iterations: 100000, hashAlgorithm: HashAlgorithmName.SHA256, outputLength: 32);\n    return flagged;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2053");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }

    #[test]
    fn s2053_numeric_constructor_salt_size_is_not_flagged() {
        let report = analyze_default(
            "byte[] Derive(string password)\n{\n    var derive = new Rfc2898DeriveBytes(password, 16, 100000);\n    return derive.GetBytes(32);\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2053").is_empty());
    }

    #[test]
    fn s2053_flags_two_static_salts_on_distinct_lines() {
        let report = analyze_default(
            "class Users\n{\n    void Store(string password)\n    {\n        var first = HashPassword(password, \"pepper\");\n        var second = HashPassword(first, \"salt\");\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2053");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }
}
