use crate::engine::file_context::FileContext;
use crate::support::{binding_stmt_targets, child_bodies, is_true_literal, issue_at, keyword_value};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt, StmtClassDef};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
enum DjangoName {
    Django,
    Db,
    Models,
    Model,
    StringField,
}

type Bindings<'a> = HashMap<&'a str, DjangoName>;

pub(crate) fn check_django_string_field_null(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    inspect_suite(
        file_ctx.module_body,
        &mut Bindings::new(),
        None,
        false,
        &mut |call: &ruff_python_ast::ExprCall| {
            issues.push(issue_at(
                "python:S6553",
                "String-based fields should use blank=True rather than null=True.",
                call.range(),
                index,
                source,
            ));
        },
    );
    issues
}

fn imported_name(path: &str) -> Option<DjangoName> {
    match path {
        "django" => Some(DjangoName::Django),
        "django.db" => Some(DjangoName::Db),
        "django.db.models" => Some(DjangoName::Models),
        "django.db.models.Model" | "django.db.models.base.Model" => Some(DjangoName::Model),
        "django.db.models.CharField" | "django.db.models.TextField" => Some(DjangoName::StringField),
        _ => None,
    }
}

fn resolve(expr: &Expr, bindings: &Bindings<'_>) -> Option<DjangoName> {
    match expr {
        Expr::Name(name) => bindings.get(name.id.as_str()).copied(),
        Expr::Attribute(attribute) => {
            match (resolve(&attribute.value, bindings)?, attribute.attr.as_str()) {
                (DjangoName::Django, "db") => Some(DjangoName::Db),
                (DjangoName::Db, "models") => Some(DjangoName::Models),
                (DjangoName::Models, "Model") => Some(DjangoName::Model),
                (DjangoName::Models, "CharField" | "TextField") => Some(DjangoName::StringField),
                _ => None,
            }
        }
        _ => None,
    }
}

fn bind<'a>(bindings: &mut Bindings<'a>, name: &'a str, value: Option<DjangoName>) {
    if let Some(value) = value {
        bindings.insert(name, value);
    } else {
        bindings.remove(name);
    }
}

fn is_model(class: &StmtClassDef, bindings: &Bindings<'_>) -> bool {
    class.arguments.as_ref().is_some_and(|arguments| {
        arguments
            .args
            .iter()
            .any(|base| resolve(base, bindings) == Some(DjangoName::Model))
    })
}

fn unmanaged(class: &StmtClassDef) -> bool {
    class.body.iter().any(|member| {
        let Stmt::ClassDef(meta) = member else {
            return false;
        };
        meta.name.as_str() == "Meta"
            && meta.body.iter().any(|member| {
                matches!(member, Stmt::Assign(assign)
                    if assign.targets.iter().any(|target|
                        matches!(target, Expr::Name(name) if name.id.as_str() == "managed"))
                    && matches!(assign.value.as_ref(), Expr::BooleanLiteral(value) if !value.value))
            })
    })
}

fn inspect_field(value: &Expr, bindings: &Bindings<'_>, report: &mut impl FnMut(&ruff_python_ast::ExprCall)) {
    let Expr::Call(call) = value else {
        return;
    };
    let true_keyword = |name| keyword_value(&call.arguments, name).is_some_and(is_true_literal);
    if resolve(&call.func, bindings) == Some(DjangoName::StringField)
        && true_keyword("null")
        && !(true_keyword("blank") && true_keyword("unique"))
    {
        report(call);
    }
}

// Keep identities in execution order. Unknown rebindings erase provenance;
// unlike callee-tail matching, a user-defined Model or TextField is not Django.
fn inspect_suite<'a>(
    suite: &'a [Stmt],
    bindings: &mut Bindings<'a>,
    globals: Option<&Bindings<'a>>,
    model_body: bool,
    report: &mut impl FnMut(&ruff_python_ast::ExprCall),
) {
    for stmt in suite {
        // Assignment expressions can overwrite an imported root in a header
        // or argument. Losing that identity is safer than guessing its value.
        for expr in crate::support::stmt_exprs(stmt) {
            crate::support::for_each_expr(expr, &mut |expr| {
                if let Expr::Named(named) = expr {
                    invalidate_target(&named.target, bindings);
                }
            });
        }
        match stmt {
            Stmt::Import(_) | Stmt::ImportFrom(_) => record_import(stmt, bindings),
            Stmt::Assign(assign) => {
                if model_body {
                    inspect_field(&assign.value, bindings, report);
                }
                let value = resolve(&assign.value, bindings);
                for target in &assign.targets {
                    invalidate_target(target, bindings);
                    if let Expr::Name(name) = target {
                        bind(bindings, name.id.as_str(), value);
                    }
                }
            }
            Stmt::ClassDef(class) => {
                let model = is_model(class, bindings);
                // Nested class bodies cannot close over the enclosing class's
                // namespace, although their base expressions can use it.
                let enclosing = globals.unwrap_or(bindings);
                let mut members = enclosing.clone();
                inspect_suite(&class.body, &mut members, Some(enclosing), model && !unmanaged(class), report);
                bind(bindings, class.name.as_str(), model.then_some(DjangoName::Model));
            }
            Stmt::FunctionDef(function) => {
                bind(bindings, function.name.as_str(), None);
            }
            _ => invalidate_statement(stmt, bindings),
        }
    }
}

fn record_import<'a>(stmt: &'a Stmt, bindings: &mut Bindings<'a>) {
    match stmt {
        Stmt::Import(import) => {
            for alias in &import.names {
                let path = alias.name.as_str();
                let name = alias.asname.as_ref().map_or_else(
                    || path.split('.').next().unwrap_or(path),
                    |name| name.as_str(),
                );
                let imported = if alias.asname.is_some() { path } else { name };
                bind(bindings, name, imported_name(imported));
            }
        }
        Stmt::ImportFrom(import) => {
            for alias in &import.names {
                let name = alias.asname.as_ref().unwrap_or(&alias.name).as_str();
                let value = import.module.as_ref().filter(|_| import.level == 0).and_then(|module| {
                    imported_name(&format!("{}.{}", module.as_str(), alias.name.as_str()))
                });
                if name == "*" {
                    bindings.clear();
                } else {
                    bind(bindings, name, value);
                }
            }
        }
        _ => {}
    }
}

fn invalidate_target(target: &Expr, bindings: &mut Bindings<'_>) {
    match target {
        Expr::Name(name) => { bindings.remove(name.id.as_str()); }
        Expr::Attribute(attribute) => invalidate_target(&attribute.value, bindings),
        Expr::Subscript(subscript) => invalidate_target(&subscript.value, bindings),
        Expr::Tuple(tuple) => {
            for target in &tuple.elts {
                invalidate_target(target, bindings);
            }
        }
        Expr::List(list) => {
            for target in &list.elts {
                invalidate_target(target, bindings);
            }
        }
        Expr::Starred(starred) => invalidate_target(&starred.value, bindings),
        _ => {}
    }
}

// Conditional/loop writes cannot establish a definite import identity. Do not
// carry an earlier alias through those writes or treat nested calls as fields.
fn invalidate_statement<'a>(stmt: &'a Stmt, bindings: &mut Bindings<'a>) {
    for target in binding_stmt_targets(stmt) {
        if let Expr::Name(name) = target {
            bindings.remove(name.id.as_str());
        }
    }
    match stmt {
        Stmt::Assign(assign) => {
            for target in &assign.targets {
                invalidate_target(target, bindings);
            }
        }
        Stmt::AnnAssign(assign) => invalidate_target(&assign.target, bindings),
        Stmt::AugAssign(assign) => invalidate_target(&assign.target, bindings),
        Stmt::Try(_) => bindings.clear(),
        Stmt::Import(_) | Stmt::ImportFrom(_) | Stmt::Delete(_) | Stmt::Match(_) => bindings.clear(),
        Stmt::FunctionDef(function) => { bindings.remove(function.name.as_str()); }
        Stmt::ClassDef(class) => { bindings.remove(class.name.as_str()); }
        _ => {
            for body in child_bodies(stmt) {
                for member in body {
                    invalidate_statement(member, bindings);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6553_model_fields_require_null_without_blank_unique_exemption() {
        let source = concat!(
            "from django.db import models\n",
            "class Book(models.Model):\n",
            "    title = models.CharField(null=True)\n",
            "    text = models.TextField(null=True, blank=True)\n",
            "    unique = models.CharField(null=True, unique=True)\n",
            "    optional = models.CharField(null=True, blank=True, unique=True)\n",
            "    required = models.CharField(null=False)\n",
            "    number = models.IntegerField(null=True)\n",
        );
        let report = scan(source);
        let actual: Vec<_> = findings(&report, "python:S6553").iter().map(|issue| {
            (issue.range.start.line, issue.range.start.column, issue.range.end.line, issue.range.end.column)
        }).collect();
        assert_eq!(actual, [(3, 12, 3, 39), (4, 11, 4, 50), (5, 13, 5, 53)]);
    }

    #[test]
    fn s6553_ignores_non_model_calls_nested_calls_and_unmanaged_models() {
        let report = scan(concat!(
            "from django.db import models, migrations\n",
            "standalone = models.CharField(null=True)\n",
            "class Plain:\n",
            "    text = models.TextField(null=True)\n",
            "class Migration(migrations.Migration):\n",
            "    operations = [migrations.AlterField(field=models.CharField(null=True))]\n",
            "class Unmanaged(models.Model):\n",
            "    text = models.TextField(null=True)\n",
            "    class Meta:\n",
            "        managed = False\n",
            "class Book(models.Model):\n",
            "    wrapped = wrapper(models.TextField(null=True))\n",
            "    def method(self):\n",
            "        return models.CharField(null=True)\n",
            "    class Plain:\n",
            "        text = models.TextField(null=True)\n",
        ));
        assert!(findings(&report, "python:S6553").is_empty());
    }

    #[test]
    fn s6553_preserves_import_aliases_inheritance_and_rebindings() {
        let report = scan(concat!(
            "from django.db.models import Model as Base, TextField as Text\n",
            "import django.db.models as db\n",
            "Field = Text\n",
            "class Parent(Base):\n",
            "    text = Field(null=True)\n",
            "class Child(Parent):\n",
            "    text = db.CharField(null=True)\n",
            "    Field = custom\n",
            "    other = Field(null=True)\n",
            "Text = custom\n",
            "class Rebound(Base):\n",
            "    text = Text(null=True)\n",
            "Base = custom\n",
            "class NotModel(Base):\n",
            "    text = db.TextField(null=True)\n",
            "if condition:\n",
            "    db = custom\n",
            "class Unknown(db.Model):\n",
            "    text = db.CharField(null=True)\n",
        ));
        let locations: Vec<_> = findings(&report, "python:S6553").iter().map(|issue| issue.range.start.line).collect();
        assert_eq!(locations, [5, 7]);
    }

    #[test]
    fn s6553_does_not_reuse_mutated_or_unpacked_model_identities() {
        let report = scan(concat!(
            "from django.db import models\n",
            "class Model: pass\n",
            "class Lookalike(Model):\n",
            "    text = models.TextField(null=True)\n",
            "Left, Right = models.Model\n",
            "class Unpacked(Left):\n",
            "    text = models.TextField(null=True)\n",
            "models.Model = custom\n",
            "class Mutated(models.Model):\n",
            "    text = models.TextField(null=True)\n",
        ));
        assert!(findings(&report, "python:S6553").is_empty());
    }
}
