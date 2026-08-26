use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of};
use crate::rules::expressions::{callee_name, enclosing_type};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use crate::symbol_table::{MemberFlavor, UsageSymbols};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1699 — constructors must not dispatch overridable members.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    symbols: &UsageSymbols<'_>,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for constructor in collect_kinds(root, &["constructor_declaration"]) {
        if is_error_tainted(constructor) {
            continue;
        }
        let owner = enclosing_type(constructor);
        let overridable: std::collections::HashSet<&str> = symbols
            .members
            .iter()
            .filter(|member| {
                member.flavor == MemberFlavor::Method
                    && owner.is_some_and(|owner| member.owner == owner)
                    && !has_modifier(&modifiers_of(member.declaration, source), "static")
                    && modifiers_of(member.declaration, source)
                        .iter()
                        .any(|modifier| matches!(*modifier, "virtual" | "abstract"))
            })
            .map(|member| member.name)
            .collect();
        let Some(body) = body_of(constructor) else {
            continue;
        };
        for invocation in collect_kinds(body, &["invocation_expression"]) {
            if is_error_tainted(invocation) {
                continue;
            }
            let Some(callee) = callee_name(invocation, source) else {
                continue;
            };
            if overridable.contains(callee) {
                issues.push(issue(
                    language,
                    "S1699",
                    format!("Constructor calls overridable method '{callee}'."),
                    range_of(invocation, source),
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1699_ignores_static_same_name_callee() {
        let report = analyze_default(
            "class A\n{\n    public A()\n    {\n        Initialize();\n    }\n\n    private static void Initialize() { }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1699").is_empty());
    }

    #[test]
    fn s1699_flags_abstract_member_call() {
        let report = analyze_default(
            "abstract class A\n{\n    protected abstract void Initialize();\n\n    public A()\n    {\n        Initialize();\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1699");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
    }

    #[test]
    fn s1699_flags_qualified_this_invocation() {
        let report = analyze_default(
            "class A\n{\n    public A()\n    {\n        this.Setup();\n    }\n\n    protected virtual void Setup() { }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S1699");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }

    #[test]
    fn s1699_reports_each_overridable_dispatch_distinctly() {
        let report = analyze_default(
            "class A\n{\n    public A()\n    {\n        Setup();\n        Validate();\n    }\n\n    protected virtual void Setup() { }\n\n    protected virtual void Validate() { }\n}\n",
        );
        let mut lines: Vec<u32> = with_key(&report, "csharpsquid:S1699")
            .iter()
            .map(|issue| issue.range.start.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![5, 6]);
    }

    #[test]
    fn s1699_owner_scoped_lookup_misses_inherited_virtuals() {
        let report = analyze_default(
            "class Base\n{\n    protected virtual void Initialize() { }\n}\n\nclass Derived : Base\n{\n    public Derived()\n    {\n        Initialize();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S1699").is_empty());
    }
}
