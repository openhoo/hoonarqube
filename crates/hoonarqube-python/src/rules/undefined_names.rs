use crate::engine::scope::FileFacts;
use crate::engine::scope::SymbolTable;
use crate::support::is_builtin_name;
use crate::support::is_dunder_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;

// --- python:S5953 — undefined names ------------------------------------------

pub(crate) fn check_undefined_names(
    table: &SymbolTable,
    facts: &FileFacts,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    if facts.dynamic_names || facts.has_wildcard_import {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for load in &table.resolved_loads {
        if load.in_annotation || load.target.is_some() || is_builtin_name(&load.name) {
            continue;
        }
        if is_dunder_name(&load.name) {
            continue;
        }
        issues.push(issue_at(
            "python:S5953",
            &format!(
                "{} is not defined. Change its name or define it before using it",
                load.name
            ),
            load.range,
            index,
            source,
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5953_accepts_star_args_kwargs_and_builtin_exceptions() {
        let source = concat!(
            "import socket\n",
            "def forward(*args, **kwargs):\n",
            "    return args, kwargs\n",
            "def relay(**kwargs):\n",
            "    return forward(**kwargs)\n",
            "def collect(*args):\n",
            "    return forward(*args)\n",
            "def risky():\n",
            "    try:\n",
            "        socket.create_connection(('host', 1))\n",
            "    except OSError:\n",
            "        return None\n",
        );
        assert!(findings(&scan(source), "python:S5953").is_empty());

        // A genuinely undefined name still fires.
        let undefined = scan("value = missing_name + 1\n");
        assert_eq!(findings(&undefined, "python:S5953").len(), 1);
    }

    #[test]
    fn vars_assignment_binds_like_globals() {
        let source = "vars()[\"dynamically_defined\"] = 1\nprint(dynamically_defined)\n";
        assert!(findings(&scan(source), "python:S5953").is_empty());

        let control = "globals()[\"dynamically_defined\"] = 1\nprint(dynamically_defined)\n";
        assert!(findings(&scan(control), "python:S5953").is_empty());

        let undefined = scan("print(missing_name)\n");
        assert_eq!(findings(&undefined, "python:S5953").len(), 1);
    }
}
