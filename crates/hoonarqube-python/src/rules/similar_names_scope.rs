use crate::support::binding_stmt_targets;
use crate::support::child_bodies;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

// --- python:S1845 — names differing only in capitalization ----------------------
//
// Within one scope (module or class body) two members whose names differ only
// by letter case are a maintenance trap. The later occurrence is flagged;
// exact duplicates are redefinitions and stay out of scope here.

pub(crate) fn check_similar_names_scope(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_collisions(parsed.syntax().body.as_slice(), &mut issues, index, source);
    visit_nested_classes(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

/// Recurses into class bodies, treating each as its own scope.
fn visit_nested_classes(suite: &[Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    for stmt in suite {
        if let Stmt::ClassDef(class) = stmt {
            flag_collisions(&class.body, issues, index, source);
            visit_nested_classes(&class.body, issues, index, source);
        } else {
            for body in child_bodies(stmt) {
                visit_nested_classes(body, issues, index, source);
            }
        }
    }
}

fn flag_collisions(suite: &[Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    // `(lowercased spelling, first-seen spelling, range)` in declaration order.
    let mut seen: Vec<(String, String, TextRange)> = Vec::new();
    for (name, range) in scope_bindings(suite) {
        let lowered = name.to_lowercase();
        match seen.iter().find(|(key, _, _)| *key == lowered) {
            Some((_, first, _)) if *first != name => {
                issues.push(issue_at(
                    "python:S1845",
                    &format!(
                        "Rename '{name}' because it differs only in capitalization from '{first}'."
                    ),
                    range,
                    index,
                    source,
                ));
            }
            Some(_) => {}
            None => seen.push((lowered.clone(), name.to_string(), range)),
        }
    }
}

/// Names introduced directly by a scope's statements with their ranges:
/// definitions and binding targets. Nested scopes are not descended into.
fn scope_bindings(suite: &[Stmt]) -> Vec<(&str, TextRange)> {
    let mut bindings = Vec::new();
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(function) => {
                bindings.push((function.name.id.as_str(), function.name.range()));
            }
            Stmt::ClassDef(class) => {
                bindings.push((class.name.id.as_str(), class.name.range()));
            }
            other => {
                for target in binding_stmt_targets(other) {
                    if let ruff_python_ast::Expr::Name(name) = target {
                        bindings.push((name.id.as_str(), name.range()));
                    }
                }
            }
        }
    }
    bindings
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1845_flags_case_only_collisions_in_scope() {
        let module = scan("value = 1\nValue = 2\n");
        assert_eq!(findings(&module, "python:S1845").len(), 1);
        let class_scope = scan(concat!(
            "class C:\n",
            "    def render(self):\n",
            "        return 1\n",
            "    RENDER = 2\n",
        ));
        assert_eq!(findings(&class_scope, "python:S1845").len(), 1);
    }

    #[test]
    fn s1845_spares_identical_names_and_separate_scopes() {
        for clean in [
            // Exact duplicates are redefinitions, not case collisions.
            "value = 1\nvalue = 2\n",
            // Members of separate class scopes never collide.
            "class A:\n    def go(self):\n        return 1\nclass B:\n    def go(self):\n        return 2\n",
            "def outer():\n    value = 1\nvalue = 2\n",
        ] {
            assert!(findings(&scan(clean), "python:S1845").is_empty());
        }
    }
}
