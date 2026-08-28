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
// CE targets class members (methods and fields): two names in one class body
// differing only by letter case are a maintenance trap. The later occurrence
// is flagged; module-level bindings are out of scope, and exact duplicates are
// redefinitions handled elsewhere.

pub(crate) fn check_similar_names_scope(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
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
    // `(lowercased spelling, first-seen spelling, range, member kind)` in declaration order.
    let mut seen: Vec<(String, String, TextRange, &'static str)> = Vec::new();
    for (name, range, kind) in scope_bindings(suite) {
        let lowered = name.to_lowercase();
        match seen.iter().find(|(key, _, _, _)| *key == lowered) {
            Some((_, first, first_range, first_kind)) if *first != name => {
                let first_line = crate::support::to_range(*first_range, index, source)
                    .start
                    .line;
                issues.push(issue_at(
                    "python:S1845",
                    &format!(
                        "Rename {kind} \"{name}\" to prevent any misunderstanding/clash with {first_kind} \"{first}\" defined on line {first_line}"
                    ),
                    range,
                    index,
                    source,
                ));
            }
            Some(_) => {}
            None => seen.push((lowered.clone(), name.to_string(), range, kind)),
        }
    }
}

/// Names introduced directly by a scope's statements with their ranges:
/// definitions and binding targets. Nested scopes are not descended into.
fn scope_bindings(suite: &[Stmt]) -> Vec<(&str, TextRange, &'static str)> {
    let mut bindings = Vec::new();
    for stmt in suite {
        match stmt {
            Stmt::FunctionDef(function) => {
                bindings.push((function.name.id.as_str(), function.name.range(), "method"));
            }
            Stmt::ClassDef(class) => {
                bindings.push((class.name.id.as_str(), class.name.range(), "class"));
            }
            other => {
                for target in binding_stmt_targets(other) {
                    if let ruff_python_ast::Expr::Name(name) = target {
                        bindings.push((name.id.as_str(), name.range(), "field"));
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
    fn s1845_flags_case_only_collisions_in_class_bodies() {
        // CE scopes the rule to class members; module-level bindings stay silent.
        assert!(findings(&scan("value = 1\nValue = 2\n"), "python:S1845").is_empty());
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
