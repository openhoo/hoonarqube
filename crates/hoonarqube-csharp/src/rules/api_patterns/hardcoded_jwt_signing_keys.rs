use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use crate::rules::literals::is_string_literal;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6781 — signing keys built from literal byte arrays live
/// forever in source control and leak with the repo.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    simple_name(node_text(type_node, source)) == "SymmetricSecurityKey"
                })
        })
        .filter(|creation| {
            invocation_arguments(*creation)
                .into_iter()
                .filter_map(argument_value)
                .any(|value| is_literal_key(value, source))
        })
        .map(|creation| {
            issue(
                language,
                "S6781",
                "Load this signing key from configuration instead of hard-coding it.",
                range_of(creation, source),
            )
        })
        .collect()
}

fn argument_value(argument: Node<'_>) -> Option<Node<'_>> {
    argument.named_child(argument.named_child_count().checked_sub(1)?)
}

fn is_literal_key(value: Node<'_>, source: &str) -> bool {
    match value.kind() {
        "array_creation_expression" => value
            .child_by_field_name("type")
            .is_some_and(|type_node| is_byte_array_type(node_text(type_node, source))),
        "implicit_array_creation_expression" | "collection_expression" => true,
        _ => is_literal_decoder_call(value, source),
    }
}

fn is_byte_array_type(type_text: &str) -> bool {
    let compact = type_text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    matches!(
        compact.as_str(),
        "byte[]" | "Byte[]" | "System.Byte[]" | "global::System.Byte[]"
    )
}

fn is_literal_decoder_call(call: Node<'_>, source: &str) -> bool {
    if call.kind() != "invocation_expression"
        || !invocation_arguments(call)
            .into_iter()
            .filter_map(argument_value)
            .any(is_string_literal)
    {
        return false;
    }

    let Some(receiver) = invocation_receiver(call) else {
        return false;
    };
    let receiver = node_text(receiver, source)
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    matches!(
        (callee_name(call, source), receiver.as_str()),
        (
            Some("GetBytes"),
            "Encoding.UTF8" | "System.Text.Encoding.UTF8" | "global::System.Text.Encoding.UTF8"
        ) | (
            Some("FromBase64String"),
            "Convert" | "System.Convert" | "global::System.Convert"
        )
    )
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6781_flags_literal_byte_and_collection_keys() {
        let report = analyze_default(
            "class C { void M() {\n\
             var a = new SymmetricSecurityKey(new byte[] { 1, 2 });\n\
             var b = new SymmetricSecurityKey(new[] { (byte)1, (byte)2 });\n\
             var c = new SymmetricSecurityKey([1, 2]);\n\
             var d = new SymmetricSecurityKey(new int[] { 1, 2 });\n\
             } }",
        );

        assert_eq!(with_key(&report, "csharpsquid:S6781").len(), 3);
    }

    #[test]
    fn s6781_flags_known_decoders_for_every_string_literal_kind() {
        let report = analyze_default(
            "class C { void M() {\n\
             var a = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(\"plain\"));\n\
             var b = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(@\"verbatim\"));\n\
             var c = new SymmetricSecurityKey(Convert.FromBase64String(\"\"\"raw\"\"\"));\n\
             var d = new SymmetricSecurityKey(global::System.Convert.FromBase64String(\"c2VjcmV0\"));\n\
             } }",
        );

        assert_eq!(with_key(&report, "csharpsquid:S6781").len(), 4);
    }

    #[test]
    fn s6781_ignores_unknown_decoders_and_non_literal_inputs() {
        let report = analyze_default(
            "class C { void M(Provider provider, string configured) {\n\
             var a = new SymmetricSecurityKey(provider.GetBytes(\"hardcoded\"));\n\
             var b = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(\"hardcoded\"));\n\
             var c = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configured));\n\
             var d = new SymmetricSecurityKey(Convert.FromBase64String(configured));\n\
             } }",
        );

        assert!(with_key(&report, "csharpsquid:S6781").is_empty());
    }
}
