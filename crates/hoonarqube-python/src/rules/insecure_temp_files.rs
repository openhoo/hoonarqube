use crate::engine::file_context::FileContext;
use crate::support::dotted_name_in;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashMap;
use std::collections::HashSet;

// --- python:S5445 — insecure temporary files ----------------------------------

pub(crate) fn check_insecure_temp_files(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let insecure = ["tempfile.mktemp", "os.tempnam", "os.tmpnam"];
    // Bare local names bound by `from tempfile/os import <target> [as X]`
    // and module aliases bound by `import tempfile/os [as m]`; sibling rules
    // accept these import spellings alongside fully qualified paths.
    let mut bare_names: HashSet<&str> = HashSet::new();
    let mut module_aliases: HashMap<&str, &str> = HashMap::new();
    for stmt in &file_ctx.stmts {
        match stmt {
            Stmt::ImportFrom(import_from) => collect_bare_names(import_from, &mut bare_names),
            Stmt::Import(import) => collect_module_aliases(import, &mut module_aliases),
            _ => {}
        }
    }

    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if flags_call(call, &insecure, &bare_names, &module_aliases) {
            issues.push(issue_at(
                "python:S5445",
                "Remove this usage of the deprecated insecure temporary file API.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

fn collect_bare_names<'a>(
    import_from: &'a ruff_python_ast::StmtImportFrom,
    bare_names: &mut HashSet<&'a str>,
) {
    let Some(module) = import_from.module.as_ref() else {
        return;
    };
    let targets: &[&str] = match module.as_str() {
        "tempfile" => &["mktemp"],
        "os" => &["tempnam", "tmpnam"],
        _ => return,
    };
    for alias in &import_from.names {
        if targets.contains(&alias.name.as_str()) {
            bare_names.insert(
                alias
                    .asname
                    .as_deref()
                    .map_or(alias.name.as_str(), |asname| asname),
            );
        }
    }
}

fn collect_module_aliases<'a>(
    import: &'a ruff_python_ast::StmtImport,
    module_aliases: &mut HashMap<&'a str, &'a str>,
) {
    for alias in &import.names {
        let name = alias.name.as_str();
        if name == "tempfile" || name == "os" {
            let local = alias.asname.as_deref().map_or(name, |asname| asname);
            module_aliases.insert(local, name);
        }
    }
}

fn flags_call(
    call: &ruff_python_ast::ExprCall,
    insecure: &[&str],
    bare_names: &HashSet<&str>,
    module_aliases: &HashMap<&str, &str>,
) -> bool {
    if dotted_name_in(&call.func, insecure) {
        return true;
    }
    match call.func.as_ref() {
        Expr::Name(name) => bare_names.contains(name.id.as_str()),
        Expr::Attribute(attr) => aliased_attribute_is_insecure(attr, module_aliases),
        _ => false,
    }
}

fn aliased_attribute_is_insecure(
    attr: &ruff_python_ast::ExprAttribute,
    module_aliases: &HashMap<&str, &str>,
) -> bool {
    let Expr::Name(base) = attr.value.as_ref() else {
        return false;
    };
    let Some(module) = module_aliases.get(base.id.as_str()) else {
        return false;
    };
    matches!(
        (*module, attr.attr.as_str()),
        ("tempfile", "mktemp") | ("os", "tempnam" | "tmpnam")
    )
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5445_flags_import_bound_temp_file_spellings() {
        let qualified = scan("import os\npath = os.tempnam(directory)\n");
        assert_eq!(findings(&qualified, "python:S5445").len(), 1);
        let from_imported = scan("from tempfile import mktemp\npath = mktemp()\n");
        assert_eq!(findings(&from_imported, "python:S5445").len(), 1);
        let aliased_from_import = scan("from os import tempnam as tn\npath = tn(p)\n");
        assert_eq!(findings(&aliased_from_import, "python:S5445").len(), 1);
        let aliased_module = scan("import tempfile as tf\npath = tf.mktemp()\n");
        assert_eq!(findings(&aliased_module, "python:S5445").len(), 1);
        let clean = scan("import tempfile\npath = tempfile.NamedTemporaryFile()\nprint(mktemp)\n");
        assert!(findings(&clean, "python:S5445").is_empty());
    }
}
