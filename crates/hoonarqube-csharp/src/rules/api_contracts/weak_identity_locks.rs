use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{enclosing_type, first_named_child};
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
    let weak_fields: std::collections::HashMap<(usize, &str), &str> =
        collect_kinds(root, &["field_declaration"])
            .into_iter()
            .filter_map(|field| enclosing_type(field).map(|owner| (owner.id(), field)))
            .flat_map(|(owner_id, field)| {
                collect_kinds(field, &["variable_declaration"])
                    .into_iter()
                    .map(move |declaration| (owner_id, declaration))
            })
            .flat_map(|(owner_id, declaration)| {
                let type_name =
                    first_named_child(declaration).map_or("", |ty| node_text(ty, source));
                collect_kinds(declaration, &["variable_declarator"])
                    .into_iter()
                    .filter_map(first_named_child)
                    .map(move |name| ((owner_id, node_text(name, source)), type_name))
            })
            .filter(|(_, type_name)| {
                let tail = simple_name(type_name).trim_end_matches('?');
                WEAK_LOCK_TYPES.contains(&tail)
            })
            .collect();

    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter(|lock_statement| !is_error_tainted(*lock_statement))
        .filter_map(|lock_statement| {
            let owner_id = enclosing_type(lock_statement)?.id();
            let guard = lock_guard_expression(lock_statement)?;
            weak_fields
                .get(&(owner_id, node_text(guard, source)))
                .map(|ty| (guard, *ty))
        })
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

    #[test]
    fn s3998_scopes_fields_to_their_declaring_type_and_matches_exact_types() {
        let report = analyze_default(
            "class Weak\n{\n    StackOverflowException gate;\n    void M() { lock (gate) { } }\n}\n\nclass Safe\n{\n    object gate;\n    MyMemberInfo custom;\n    void M()\n    {\n        lock (gate) { }\n        lock (custom) { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3998");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 4);
    }
}
