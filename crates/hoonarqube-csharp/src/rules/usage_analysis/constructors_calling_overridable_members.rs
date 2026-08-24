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
                    range_of(invocation),
                ));
            }
        }
    }
    issues
}
