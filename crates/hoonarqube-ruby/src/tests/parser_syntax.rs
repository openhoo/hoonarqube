use crate::{engine::parse_source, support::walk};

fn spans<'a>(source: &'a str, kind: &str) -> Vec<&'a str> {
    let tree = parse_source(source).unwrap();
    let root = tree.root_node();
    assert!(!root.has_error(), "{}", root.to_sexp());
    let mut hits = Vec::new();
    walk(root, |node| {
        if node.kind() == kind {
            hits.push(&source[node.byte_range()]);
        }
    });
    hits
}

#[test]
fn anonymous_block_ends_before_whitespace_and_comments() {
    let source = "def f(&)\n sink('é',\n  &\n )\n sink(& # forward\n # note\n )\nend";
    assert_eq!(spans(source, "block_argument"), ["&", "&"]);
    assert_eq!(spans(source, "comment"), ["# forward", "# note"]);
    assert_eq!(spans(source, "block_parameter"), ["&"]);
}

#[test]
fn suffixed_labels_keep_their_symbol_spans() {
    let source = "{text: 'é', defined?: 1, reset!: 2, ready?: 3}";
    assert_eq!(
        spans(source, "hash_key_symbol"),
        ["text", "defined?", "reset!", "ready?"]
    );
}

#[test]
fn block_and_method_punctuation_keep_their_normal_meanings() {
    let source = "def f(&handler)\n sink(&handler)\n a & b\n a && b\n a != b\n a&.b\n defined?(x) ? yes! : no!\nend";
    assert_eq!(spans(source, "block_argument"), ["&handler"]);
    assert_eq!(spans(source, "block_parameter"), ["&handler"]);
    assert_eq!(spans(source, "binary"), ["a & b", "a && b", "a != b"]);
    assert_eq!(spans(source, "unary"), ["defined?(x)"]);
    assert_eq!(spans(source, "conditional"), ["defined?(x) ? yes! : no!"]);
}

#[test]
fn malformed_block_arguments_and_labels_still_fail() {
    for expression in [
        "sink(&, 1)",
        "sink(& , 1)",
        "sink(&,)",
        "{defined?:: 1}",
        "{ready?: => 1}",
    ] {
        let source = format!("def f(&)\n{expression}\nend");
        assert!(
            parse_source(&source).unwrap().root_node().has_error(),
            "{source}"
        );
    }
}
