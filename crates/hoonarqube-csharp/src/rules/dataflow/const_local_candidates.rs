use super::support::callable_blocks;
use super::support::captured_names;
use super::support::collect_owned_kinds;
use super::support::identifier_write;
use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, node_text, range_of, simple_name};
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3353 — locals declared once from a literal and never
/// rewritten carry `const`. Bound: writes counted across the whole
/// member body; lambda-captured names stay exempt because capture
/// freezes their lifetime to the closure instead.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        issues.extend(body_const_candidates(body, source, language));
    }
    issues
}

fn body_const_candidates(body: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let captured = captured_names(body, source);
    let write_counts = identifier_write_counts(body, source);
    collect_owned_kinds(body, &["local_declaration_statement"])
        .into_iter()
        .filter(|declaration| is_const_candidate_declaration(*declaration, source))
        .flat_map(|declaration| collect_owned_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| {
            const_candidate_issue(declarator, source, language, &captured, &write_counts)
        })
        .collect()
}

fn identifier_write_counts<'a>(
    body: Node<'_>,
    source: &'a str,
) -> std::collections::HashMap<&'a str, u32> {
    let mut counts = std::collections::HashMap::new();
    for identifier in collect_owned_kinds(body, &["identifier"]) {
        if identifier_write(identifier).is_some() {
            *counts.entry(node_text(identifier, source)).or_default() += 1;
        }
    }
    counts
}

fn is_const_candidate_declaration(declaration: Node<'_>, source: &str) -> bool {
    if has_modifier(&modifiers_of(declaration, source), "const") {
        return false;
    }
    declaration
        .children(&mut declaration.walk())
        .find(|child| child.kind() == "variable_declaration")
        .and_then(|variable| variable.child_by_field_name("type"))
        .map(|type_node| simple_name(node_text(type_node, source)))
        .is_some_and(|type_text| CONST_CANDIDATE_TYPES.contains(&type_text))
}

fn const_candidate_issue(
    declarator: Node<'_>,
    source: &str,
    language: CsLanguage,
    captured: &std::collections::HashSet<String>,
    write_counts: &std::collections::HashMap<&str, u32>,
) -> Option<Issue> {
    let name_node = declarator.child_by_field_name("name")?;
    let name = node_text(name_node, source);
    let literal_initializer = declarator_initializer(declarator, name_node).is_some_and(|value| {
        matches!(
            value.kind(),
            "integer_literal"
                | "real_literal"
                | "string_literal"
                | "character_literal"
                | "boolean_literal"
        )
    });
    (literal_initializer
        && !captured.contains(name)
        && write_counts.get(name).copied().unwrap_or(0) <= 1)
        .then(|| {
            issue(
                language,
                "S3353",
                format!("Add the 'const' modifier to '{name}'."),
                range_of(name_node, source),
            )
        })
}

/// Primitive types a `const` local may declare.
const CONST_CANDIDATE_TYPES: [&str; 14] = [
    "bool", "byte", "char", "decimal", "double", "float", "int", "long", "sbyte", "short",
    "string", "uint", "ulong", "ushort",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S3353";

    #[test]
    fn empty_callable_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn non_literal_initializer_and_var_type_stay_exempt() {
        let report = analyze_default(
            "class C {\n    int Compute() {\n        return 1;\n    }\n    void M() {\n        int retries;\n        retries = Compute();\n        Use(retries);\n        var width = 42;\n        Use(width);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn lambda_captured_literal_stays_exempt() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int retries = 3;\n        System.Action run = () => Use(retries);\n        run();\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn explicit_const_declaration_is_skipped() {
        let report = analyze_default(
            "class C {\n    void M() {\n        const int retries = 3;\n        Log(retries);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn candidates_across_literal_types_flag_at_distinct_lines() {
        let report = analyze_default(
            "class C {\n    void M() {\n        bool flag = true;\n        char grade = 'a';\n        string title = \"t\";\n        double ratio = 0.5;\n        Use(flag, grade, title, ratio);\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 4);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[3].range.start.line, 6);
        assert_ne!(found[1].range.start.line, found[2].range.start.line);
    }

    #[test]
    fn single_extra_rewrite_crosses_one_write_threshold() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int attempts = 1;\n        attempts++;\n        Log(attempts);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn same_named_local_function_write_does_not_hide_outer_candidate() {
        let report = analyze_default(
            "class C {\n    void M() {\n        int attempts = 1;\n        void Local() {\n            int attempts = 2;\n            attempts++;\n            Use(attempts);\n        }\n        Use(attempts);\n        Local();\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }
}
