use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, parameters_of, range_of};
use crate::rules::modifiers::accessibility_rank;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3253 — constructors that only restate what the compiler
/// generates, and finalizers that merely chain disposal, are noise.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for ctor in collect_kinds(root, &["constructor_declaration"]) {
        let mods = modifiers_of(ctor, source);
        // Private parameterless constructors can deliberately block
        // instantiation; visible ones add nothing.
        if accessibility_rank(&mods) < 2 || !parameters_of(ctor).is_empty() {
            continue;
        }
        let Some(body) = ctor.child_by_field_name("body") else {
            continue;
        };
        if body.named_child_count() == 0 {
            issues.push(issue(
                language,
                "S3253",
                "Remove this redundant constructor.",
                range_of(ctor, source),
            ));
        }
    }
    for dtor in collect_kinds(root, &["destructor_declaration"]) {
        let Some(body) = dtor.child_by_field_name("body") else {
            continue;
        };
        // `base.Dispose();` alone is exactly what the compiler already does.
        let inner = node_text(body, source).trim_matches(|c| c == '{' || c == '}');
        if inner.trim() == "base.Dispose();" {
            issues.push(issue(
                language,
                "S3253",
                "Remove this redundant finalizer.",
                range_of(dtor, source),
            ));
        }
    }
    issues
}
