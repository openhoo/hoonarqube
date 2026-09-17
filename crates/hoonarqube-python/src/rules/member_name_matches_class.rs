use crate::support::binding_stmt_targets;
use crate::support::child_bodies;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_ast::StmtClassDef;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// Methods and class-body fields whose name equals the enclosing class name,
// compared case-insensitively, invite confusion between instance members and
// the type itself. Only the immediate class scope counts, including instance
// attributes assigned to `self` inside `__init__`.
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
    // Sonar's FieldDuplicatesClassNameCheck returns early when the class
    // has any base — a same-named field may intentionally shadow a base.
    if !class.bases().is_empty() {
        return;
    }
    let lowered_class = class.name.id.to_lowercase();
    let mut push = |name: &str, name_range: ruff_text_size::TextRange| {
        issues.push(issue_at(
            "python:S1700",
            &format!("Rename field \"{name}\""),
            name_range,
            index,
            source,
        ));
    };
    for stmt in &class.body {
        match stmt {
            Stmt::FunctionDef(_) => {}
            _ => {
                for target in binding_stmt_targets(stmt) {
                    if let Expr::Name(name) = target
                        && name.id.to_lowercase() == lowered_class
                    {
                        push(name.id.as_str(), name.range());
                    }
                }
            }
        }
    }
    for stmt in &class.body {
        if let Stmt::FunctionDef(function) = stmt
            && function.name.id.as_str() == "__init__"
            && function.decorator_list.is_empty()
        {
            let instance = function
                .parameters
                .posonlyargs
                .first()
                .or_else(|| function.parameters.args.first())
                .map_or("self", |parameter| parameter.parameter.name.id.as_str());
            flag_matching_instance_attributes(&function.body, instance, &lowered_class, &mut push);
        }
    }
}

/// Flags `instance.<name>` assignment targets inside `__init__` whose
/// attribute name matches the class name case-insensitively. Nested
/// definitions inside `__init__` are separate functions and are skipped.
fn flag_matching_instance_attributes(
    suite: &[Stmt],
    instance: &str,
    lowered_class: &str,
    push: &mut impl FnMut(&str, ruff_text_size::TextRange),
) {
    for stmt in suite {
        if matches!(stmt, Stmt::FunctionDef(_) | Stmt::ClassDef(_)) {
            continue;
        }
        for target in attribute_assignment_targets(stmt) {
            if let Expr::Attribute(attribute) = target
                && let Expr::Name(base) = attribute.value.as_ref()
                && base.id.as_str() == instance
                && attribute.attr.id.to_lowercase() == lowered_class
            {
                push(attribute.attr.id.as_str(), attribute.attr.range());
            }
        }
        for body in child_bodies(stmt) {
            flag_matching_instance_attributes(body, instance, lowered_class, push);
        }
    }
}

/// Assignment target expressions of plain assignment statements, including
/// attribute targets such as `self.editor` that name-leaf helpers drop.
fn attribute_assignment_targets(stmt: &Stmt) -> Vec<&Expr> {
    match stmt {
        Stmt::Assign(assign) => assign.targets.iter().collect(),
        Stmt::AnnAssign(assignment) => vec![&assignment.target],
        Stmt::AugAssign(assignment) => vec![&assignment.target],
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1700_flags_case_insensitive_field_matches() {
        let field = scan("class Config:\n    CONFIG = 1\n");
        assert_eq!(findings(&field, "python:S1700").len(), 1);
        let method = scan("class Parser:\n    def parser(self):\n        pass\n");
        assert!(findings(&method, "python:S1700").is_empty());
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

    #[test]
    fn s1700_flags_init_instance_attribute_matching_class_name() {
        let flagged = scan(concat!(
            "class Editor:\n",
            "    def __init__(self, editor=None):\n",
            "        self.editor = editor\n",
            "\n",
            "class Config:\n",
            "    CONFIG = 1\n",
            "\n",
            "class Method:\n",
            "    def Editor(self):\n",
            "        return None\n"
        ));
        let found = findings(&flagged, "python:S1700");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 6);
        let unrelated_attribute =
            scan("class Editor:\n    def __init__(self):\n        self.env = {}\n");
        assert!(findings(&unrelated_attribute, "python:S1700").is_empty());
    }
}
