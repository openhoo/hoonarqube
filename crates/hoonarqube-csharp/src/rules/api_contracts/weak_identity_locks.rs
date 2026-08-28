use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

const WEAK_LOCK_TYPES: [&str; 5] = [
    "StackOverflowException",
    "OutOfMemoryException",
    "ExecutionEngineException",
    "MarshalByRefObject",
    "MemberInfo",
];

pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let weak_fields: std::collections::HashMap<&str, &str> =
        collect_kinds(root, &["field_declaration"])
            .into_iter()
            .flat_map(|field| collect_kinds(field, &["variable_declaration"]))
            .flat_map(|declaration| {
                let type_name =
                    first_named_child(declaration).map_or("", |ty| node_text(ty, source));
                collect_kinds(declaration, &["variable_declarator"])
                    .into_iter()
                    .filter_map(first_named_child)
                    .map(move |name| (node_text(name, source), type_name))
            })
            .filter(|(_, type_name)| WEAK_LOCK_TYPES.iter().any(|weak| type_name.ends_with(weak)))
            .collect();

    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter(|lock_statement| !is_error_tainted(*lock_statement))
        .filter_map(lock_guard_expression)
        .filter_map(|guard| weak_fields.get(node_text(guard, source)).map(|ty| (guard, *ty)))
        .map(|(guard, lock_type)| {
            issue(
                language,
                "S3998",
                format!(
                    "Replace this lock on '{}' with a lock against an object that cannot be accessed across application domain boundaries.",
                    simple_name(lock_type)
                ),
                range_of(guard, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3998_flags_weak_identity_fields_only() {
        let report = analyze_default(
            "class A\n{\n    readonly StackOverflowException gate = new();\n    readonly object safe = new();\n    void M()\n    {\n        lock (gate) { }\n        lock (safe) { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3998");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }
}
