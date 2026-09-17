use crate::engine::file_context::FileContext;
use crate::engine::project_context::{GraphqlResolver, PythonProjectContext, build_module_facts};
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_django_model_str(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
    module_name: &str,
    project: &PythonProjectContext,
) -> Vec<Issue> {
    let module = build_module_facts(module_name, parsed);
    let resolver = GraphqlResolver::new(&module, project);
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::ClassDef(class) = stmt {
            let (django_model, has_str) = resolver.django_model_str_facts(class.start());
            // Sonar's DjangoModelStrMethodCheck skips abstract models via
            // getMetaClass — `class Meta: abstract = True` is exempt.
            let is_abstract = class.body.iter().any(|member| {
                let Stmt::ClassDef(meta) = member else {
                    return false;
                };
                if meta.name.as_str() != "Meta" {
                    return false;
                }
                meta.body.iter().any(|m| {
                    let Stmt::Assign(assign) = m else {
                        return false;
                    };
                    assign.targets.iter().any(|t| {
                        matches!(t, ruff_python_ast::Expr::Name(n) if n.id.as_str() == "abstract")
                    }) && matches!(assign.value.as_ref(), ruff_python_ast::Expr::BooleanLiteral(b) if b.value)
                })
            });
            if django_model && !is_abstract && !has_str {
                issues.push(issue_at(
                    "python:S6554",
                    "Define __str__ on this Django model.",
                    class.name.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::PythonProjectContext;
    use crate::test_support::{findings, scan, scan_in_project};
    use std::path::PathBuf;

    #[test]
    fn s6554_requires_str_on_django_models() {
        let flagged = scan(concat!(
            "from django.db import models\n",
            "class Book(models.Model):\n",
            "    title = models.CharField(max_length=5)\n",
            "class Shelf(models.Model):\n",
            "    def __str__(self):\n",
            "        return \"s\"\n"
        ));
        assert_eq!(findings(&flagged, "python:S6554").len(), 1);
    }

    #[test]
    fn s6554_inherits_str_from_project_mixins_and_reexports() {
        let mut project = PythonProjectContext::new();
        project.add_module("app.base", concat!(
            "class Representation:\n",
            "    def __str__(self): return str(self.value)\n",
            "class Intermediate(Representation): pass\n",
            "class Missing: pass\n",
        ));
        project.add_module("app.exports", "from .base import Intermediate as Label\n");
        let source = concat!(
            "from django.db import models\n",
            "from app.exports import Label as Display\n",
            "from app.base import Missing\n",
            "from unavailable import External\n",
            "class Inherited(models.Model, Display): pass\n",
            "class MissingMethod(models.Model, Missing): pass\n",
            "class Unresolved(models.Model, External): pass\n",
        );
        let report = scan_in_project(&project, PathBuf::from("app/models.py"), source);
        assert_eq!(findings(&report, "python:S6554").iter()
            .map(|issue| issue.range.start.line).collect::<Vec<_>>(), vec![6, 7]);
        // Without dependency source an imported mixin is not evidence of __str__.
        assert_eq!(findings(&scan(source), "python:S6554").len(), 3);
    }

    #[test]
    fn s6554_preserves_abstract_exemption_and_concrete_missing_methods() {
        let source = concat!(
            "from django.db.models import Model\n",
            "class Abstract(Model):\n",
            "    class Meta: abstract = True\n",
            "class Missing(Abstract): pass\n",
            "class Printable(Abstract):\n",
            "    def __str__(self): return 'value'\n",
            "class Child(Printable): pass\n",
            "class Masked(Printable): __str__ = None\n",
            "class Concrete(Model):\n",
            "    class Meta: abstract = False\n",
        );
        let report = scan(source);
        assert_eq!(findings(&report, "python:S6554").iter()
            .map(|issue| issue.range.start.line).collect::<Vec<_>>(), vec![4, 8, 9]);
    }

    #[test]
    fn s6554_resolves_bindings_not_class_names() {
        let source = concat!(
            "from django.db.models import Model\n",
            "class Display:\n",
            "    def __str__(self): return 'value'\n",
            "SavedDisplay = Display\n",
            "class Display: pass\n",
            "class Rebound(Model, Display): pass\n",
            "class Saved(Model, SavedDisplay): pass\n",
            "class Model(Model): pass\n",
            "class Derived(Model): pass\n",
            "from unrelated import Model\n",
            "class NotDjango(Model): pass\n",
            "class Scope:\n",
            "    class Display:\n",
            "        def __str__(self): return 'nested'\n",
            "from django.db.models import Model\n",
            "class StillMissing(Model, Display): pass\n",
        );
        let report = scan(source);
        assert_eq!(findings(&report, "python:S6554").iter()
            .map(|issue| issue.range.start.line).collect::<Vec<_>>(), vec![6, 8, 9, 16]);
    }

    #[test]
    fn s6554_does_not_count_nested_or_overwritten_str_definitions() {
        let report = scan(concat!(
            "from django.db import models\n",
            "class Nested:\n",
            "    class Inner:\n",
            "        def __str__(self): return 'inner'\n",
            "class Overwritten:\n",
            "    def __str__(self): return 'old'\n",
            "    __str__ = None\n",
            "class MissingNested(models.Model, Nested): pass\n",
            "class MissingOverwritten(models.Model, Overwritten): pass\n",
        ));
        assert_eq!(findings(&report, "python:S6554").iter()
            .map(|issue| issue.range.start.line).collect::<Vec<_>>(), vec![8, 9]);
    }

    #[test]
    fn s6554_gis_model_identity_requires_a_real_inherited_method() {
        let mut project = PythonProjectContext::new();
        project.add_module("app.base", "class Display:\n    def __str__(self): return 'GIS'\n");
        project.add_module("app.cycle_a", "from app.cycle_b import Display\n");
        project.add_module("app.cycle_b", "from app.cycle_a import Display\n");
        let source = concat!(
            "from django.contrib.gis.db import models\n",
            "from app.base import Display\n",
            "from app.cycle_a import Display as Cyclic\n",
            "class Inherited(models.Model, Display): pass\n",
            "class Missing(models.Model): pass\n",
            "class Unresolved(models.Model, Cyclic): pass\n",
        );
        let report = scan_in_project(&project, PathBuf::from("app/models.py"), source);
        assert_eq!(findings(&report, "python:S6554").iter()
            .map(|issue| issue.range.start.line).collect::<Vec<_>>(), vec![5, 6]);
    }
}
