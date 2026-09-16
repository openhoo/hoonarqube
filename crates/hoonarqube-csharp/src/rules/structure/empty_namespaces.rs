use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3261 — namespaces group declarations. A body holding only
/// comments or preprocessor directives still declares nothing, so it stays
/// empty; a directive that wraps a real declaration keeps the namespace
/// non-empty because some compilation defines the member.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for namespace in collect_kinds(root, &["namespace_declaration"]) {
        if is_error_tainted(namespace) {
            continue;
        }
        let mut cursor = namespace.walk();
        let has_members = namespace
            .children(&mut cursor)
            .find(|child| child.kind() == "declaration_list")
            .is_some_and(|list| {
                let mut list_cursor = list.walk();
                list.children(&mut list_cursor)
                    .any(|member| member.is_named() && declares_member(member))
            });
        if !has_members {
            issues.push(issue(
                language,
                "S3261",
                "Remove this empty namespace.",
                range_of(namespace, source),
            ));
        }
    }
    issues
}

/// Whether a declaration-list child contributes a member under every
/// compilation: comments never do, and `preproc_*` wrappers count only when
/// every conditional branch encloses a declaration (an `#if`/`#else` pair
/// that both declare a type keeps the namespace occupied; a directive with
/// an empty or missing branch leaves some compilation empty).
fn declares_member(member: Node<'_>) -> bool {
    if member.kind() == "comment" {
        return false;
    }
    if !member.kind().starts_with("preproc_") {
        return true;
    }
    let mut cursor = member.walk();
    let children: Vec<Node<'_>> = member.children(&mut cursor).collect();
    let condition = member.child_by_field_name("condition");
    let alternative = member.child_by_field_name("alternative");
    // Branch content: named children that are neither the directive's
    // condition nor its nested `#elif`/`#else` alternative.
    let branch_has_member = children.iter().any(|child| {
        child.is_named()
            && condition.is_none_or(|node| node.id() != child.id())
            && alternative.is_none_or(|node| node.id() != child.id())
            && declares_member(*child)
    });
    match member.kind() {
        "preproc_else" => branch_has_member,
        "preproc_if" | "preproc_elif" => {
            branch_has_member && alternative.is_some_and(|node| declares_member(node))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3261_flags_namespace_holding_only_preproc_and_comments() {
        let report = analyze_default(
            "namespace Dapper.Tests.Performance\n{\n#if !NET5_0_OR_GREATER\n/*\n * explanatory note\n */\n#endif\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3261");
        assert_eq!(flagged.len(), 1);
    }

    #[test]
    fn s3261_flags_namespace_whose_members_sit_behind_a_single_sided_if() {
        // Some compilation (the `#if`-false one) declares nothing, matching
        // the reference finding on dapper's Benchmarks.PetaPoco.cs.
        let report = analyze_default(
            "namespace N\n{\n#if !NET5_0_OR_GREATER\nclass Bench\n{\n}\n#endif\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S3261");
        assert_eq!(flagged.len(), 1);
    }

    #[test]
    fn s3261_ignores_namespace_when_every_branch_declares_a_member() {
        let report = analyze_default(
            "namespace N\n{\n#if X\nclass A {}\n#elif Y\nclass B {}\n#else\nclass C {}\n#endif\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3261").is_empty());
    }

    #[test]
    fn s3261_flags_namespace_when_one_branch_declares_nothing() {
        let report = analyze_default("namespace N\n{\n#if X\nclass A {}\n#else\n#endif\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3261");
        assert_eq!(flagged.len(), 1);
    }
    #[test]
    fn s3261_flags_namespace_holding_only_comments() {
        let report = analyze_default("namespace N\n{\n// nothing here\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3261");
        assert_eq!(flagged.len(), 1);
    }

    #[test]
    fn s3261_ignores_namespace_with_members() {
        let report = analyze_default("namespace N\n{\nclass C\n{\n}\n}\n");
        assert!(with_key(&report, "csharpsquid:S3261").is_empty());
    }

    #[test]
    fn s3261_still_flags_truly_empty_namespaces() {
        let report = analyze_default("namespace N\n{\n}\n");
        let flagged = with_key(&report, "csharpsquid:S3261");
        assert_eq!(flagged.len(), 1);
    }
}
