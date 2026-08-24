use crate::support::binding_stmt_targets;
use crate::support::child_bodies;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtClassDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1700 — members sharing their class's name -------------------------
//
// Methods and class-body fields whose name equals the enclosing class name,
// compared case-insensitively, invite confusion between instance members and
// the type itself. Only the immediate class scope counts.

pub(crate) fn check_member_name_matches_class(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suite(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}

fn visit_suite(suite: &[Stmt], issues: &mut Vec<Issue>, index: &LineIndex, source: &str) {
    for stmt in suite {
        if let Stmt::ClassDef(class) = stmt {
            flag_matching_members(class, issues, index, source);
            visit_suite(&class.body, issues, index, source);
        } else {
            for body in child_bodies(stmt) {
                visit_suite(body, issues, index, source);
            }
        }
    }
}

fn flag_matching_members(
    class: &StmtClassDef,
    issues: &mut Vec<Issue>,
    index: &LineIndex,
    source: &str,
) {
    let lowered_class = class.name.id.to_lowercase();
    let mut push = |name_range: ruff_text_size::TextRange| {
        issues.push(issue_at(
            "python:S1700",
            "Rename this member to not match an existing class name.",
            name_range,
            index,
            source,
        ));
    };
    for stmt in &class.body {
        match stmt {
            Stmt::FunctionDef(function) => {
                if function.name.id.to_lowercase() == lowered_class {
                    push(function.name.range());
                }
            }
            _ => {
                for target in binding_stmt_targets(stmt) {
                    if let ruff_python_ast::Expr::Name(name) = target
                        && name.id.to_lowercase() == lowered_class
                    {
                        push(name.range());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1700_flags_case_insensitive_member_matches() {
        let flagged = scan("class Parser:\n    def parser(self):\n        pass\n");
        let found = findings(&flagged, "python:S1700");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);

        let field = scan("class Config:\n    CONFIG = 1\n");
        assert_eq!(findings(&field, "python:S1700").len(), 1);
    }

    #[test]
    fn s1700_only_immediate_class_scope_counts() {
        let nested =
            scan("class Outer:\n    class Inner:\n        def outer(self):\n            pass\n");
        assert!(findings(&nested, "python:S1700").is_empty());
    }

    #[test]
    fn s1700_unrelated_members_stay_clean() {
        let clean = "class Router:\n    def route(self):\n        pass\n    TIMEOUT = 5\n";
        assert!(findings(&scan(clean), "python:S1700").is_empty());
    }
}
