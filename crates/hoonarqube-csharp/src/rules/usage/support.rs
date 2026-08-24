use crate::cst::node_text;
use tree_sitter::Node;

/// Number of whole-word occurrences of `word` in `text`. Identifier
/// characters are alphanumeric plus `_`, so `field` never matches `my_field`.
pub(crate) fn count_word_occurrences(text: &str, word: &str) -> usize {
    let bytes = text.as_bytes();
    let mut count = 0;
    let mut from = 0;
    while let Some(found) = text[from..].find(word) {
        let start = from + found;
        let end = start + word.len();
        let left_clean =
            start == 0 || !(bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
        let right_clean =
            end >= bytes.len() || !(bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_');
        if left_clean && right_clean {
            count += 1;
        }
        from = start + word.len();
    }
    count
}

/// One private member candidate for the S1144 audit.
pub(crate) struct PrivateMember<'t> {
    pub(crate) anchor: Node<'t>,
    pub(crate) name: String,
    pub(crate) kind_word: &'static str,
}

/// Whether `root`'s subtree mentions the identifier `name`, ignoring
/// parameter lists (where the parameter itself is declared).
pub(crate) fn mentions_identifier_outside_parameter_list(
    root: Node<'_>,
    name: &str,
    source: &str,
) -> bool {
    if root.kind() == "parameter_list" {
        return false;
    }
    if root.kind() == "identifier" {
        return node_text(root, source) == name;
    }
    let mut cursor = root.walk();
    root.children(&mut cursor)
        .any(|child| mentions_identifier_outside_parameter_list(child, name, source))
}
