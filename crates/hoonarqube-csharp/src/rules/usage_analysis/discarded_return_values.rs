use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::invocation_function;
use crate::rules::structure::is_attributed;
use crate::symbol_table::{
    MemberFlavor, UsageSymbols, has_contract_modifier, is_private_member, owner_is_partial,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3241 — private results nobody captures.
pub(crate) fn check(source: &str, language: CsLanguage, symbols: &UsageSymbols<'_>) -> Vec<Issue> {
    let mut issues = Vec::new();
    for member in &symbols.members {
        let modifiers = modifiers_of(member.declaration, source);
        if member.flavor != MemberFlavor::Method
            || !is_private_member(member.declaration, source, member.nested_type)
            || has_contract_modifier(&modifiers)
            || is_attributed(member.declaration, source)
            || owner_is_partial(member.owner, source)
            || member.name == "Main"
            || member
                .declaration
                .child_by_field_name("returns")
                .is_none_or(|returns| node_text(returns, source).trim() == "void")
        {
            continue;
        }
        let call_sites: Vec<Node> = symbols
            .uses_of(member.name)
            .into_iter()
            .filter_map(invocation_callee_site)
            .collect();
        if call_sites.is_empty() || !call_sites.iter().all(|site| discards_result(*site)) {
            continue;
        }
        issues.push(issue(
            language,
            "S3241",
            "Change return type to 'void'; not a single caller uses the returned value.",
            range_of(
                member
                    .declaration
                    .child_by_field_name("returns")
                    .unwrap_or(member.anchor),
                source,
            ),
        ));
    }
    issues
}

/// The invocation an identifier participates in as callee, if any.
fn invocation_callee_site(reference: Node<'_>) -> Option<Node<'_>> {
    let parent = reference.parent()?;
    if parent.kind() == "invocation_expression" && invocation_function(parent) == Some(reference) {
        return Some(parent);
    }
    if parent.kind() == "member_access_expression" {
        let grandparent = parent.parent()?;
        if grandparent.kind() == "invocation_expression"
            && invocation_function(grandparent) == Some(parent)
        {
            return Some(grandparent);
        }
    }
    None
}

/// Whether an invocation's result evaporates: statement position only.
fn discards_result(invocation: Node<'_>) -> bool {
    let mut current = invocation;
    while let Some(parent) = current.parent() {
        match parent.kind() {
            "parenthesized_expression" => current = parent,
            "expression_statement" => return true,
            _ => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3241_ignores_captured_results() {
        let report = analyze_default(
            "class A\n{\n    private int Compute() => 42;\n    public int Run()\n    {\n        var value = Compute();\n        return value;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3241").is_empty());
    }

    #[test]
    fn s3241_ignores_public_methods() {
        let report = analyze_default(
            "class A\n{\n    public int Compute() => 42;\n    public void Run()\n    {\n        Compute();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3241").is_empty());
    }

    #[test]
    fn s3241_ignores_void_methods() {
        let report = analyze_default(
            "class A\n{\n    private void Compute() { }\n    public void Run()\n    {\n        Compute();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3241").is_empty());
    }

    #[test]
    fn s3241_ignores_attributed_methods() {
        let report = analyze_default(
            "class A\n{\n    [System.Obsolete]\n    private int Compute() => 42;\n    public void Run()\n    {\n        Compute();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3241").is_empty());
    }

    #[test]
    fn s3241_ignores_partial_owners() {
        let report = analyze_default(
            "public partial class A\n{\n    private int Compute() => 42;\n    public void Run()\n    {\n        Compute();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3241").is_empty());
    }

    #[test]
    fn s3241_ignores_entry_point_named_main() {
        let report = analyze_default(
            "class A\n{\n    private int Main() => 0;\n    public void Run()\n    {\n        Main();\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3241").is_empty());
    }

    #[test]
    fn s3241_requires_every_caller_to_discard() {
        let report = analyze_default(
            "class A\n{\n    private int Compute() => 42;\n    public int Run()\n    {\n        var captured = Compute();\n        Compute();\n        return captured;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S3241").is_empty());
    }
}
