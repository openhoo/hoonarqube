use crate::engine::file_context::FileContext;
use crate::support::{
    WebBinding, expr_in, flow_location, issue_at, scope_maps, visit_scoped_stmts,
};
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8374";
const MESSAGE: &str = "Move this decorator to the \"decorators\" class attribute.";
const SECONDARY_MESSAGE: &str = "This class inherits from a Flask View.";

/// python:S8374 — decorators on a Flask class-based view are silently
/// ignored: `View.as_view()` builds the real view function, and decorators
/// applied to the class never reach it. The reference check
/// (`FlaskViewDecoratorCheck`) flags every decorator on a class that
/// inherits from `flask.views.View` (which also covers `MethodView` and
/// local subclasses), anchoring on the decorator with a secondary location
/// on the class name. The compliant form lists the decorators in the
/// `decorators` class attribute, innermost first.
pub(crate) fn check_s8374_flask_view_decorators(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_scoped_stmts(
        file_ctx.module_body,
        file_ctx.web_bindings.module_scope(),
        &mut |stmt, scopes| {
            let Stmt::ClassDef(class) = stmt else {
                return;
            };
            if class.decorator_list.is_empty() {
                return;
            }
            let maps = scope_maps(scopes);
            let is_view = class.arguments.as_ref().is_some_and(|arguments| {
                arguments
                    .args
                    .iter()
                    .any(|base| expr_in(base, &maps) == WebBinding::FlaskViewClass)
            });
            if !is_view {
                return;
            }
            for decorator in &class.decorator_list {
                let issue =
                    issue_at(RULE_KEY, MESSAGE, decorator.range(), index, source).with_flow(vec![
                        flow_location(SECONDARY_MESSAGE, class.name.range(), index, source),
                    ]);
                issues.push(issue);
            }
        },
    );
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan};

    fn found(source: &str) -> Vec<hoonarqube_ir::Issue> {
        findings(&scan(source), "python:S8374")
            .into_iter()
            .cloned()
            .collect()
    }

    #[test]
    fn s8374_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: both decorators on the View subclass
        // anchor on the decorator, with the class name as secondary.
        let issues = found(concat!(
            "from flask.views import View\n",
            "from flask_login import login_required\n",
            "\n",
            "@login_required\n",
            "@cache(minutes=2)\n",
            "class UserList(View):\n",
            "    def dispatch_request(self):\n",
            "        users = User.query.all()\n",
            "        return render_template('users.html', users=users)\n",
        ));
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].range.start, pos(4, 0));
        assert_eq!(issues[0].range.end, pos(4, 15));
        assert_eq!(issues[1].range.start, pos(5, 0));
        assert_eq!(issues[1].range.end, pos(5, 17));
        assert_eq!(issues[0].flows.len(), 1);
        assert_eq!(issues[0].flows[0].locations[0].range.start, pos(6, 6));
        assert_eq!(
            issues[0].flows[0].locations[0].message,
            "This class inherits from a Flask View."
        );
    }

    #[test]
    fn s8374_accepts_the_sonar_compliant_example() {
        // Sonar's Compliant example: decorators listed in the `decorators`
        // class attribute are applied by as_view() and stay silent.
        assert!(
            found(concat!(
                "from flask.views import View\n",
                "from flask_login import login_required\n",
                "\n",
                "class UserList(View):\n",
                "    decorators = [cache(minutes=2), login_required]\n",
                "\n",
                "    def dispatch_request(self):\n",
                "        users = User.query.all()\n",
                "        return render_template('users.html', users=users)\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8374_flags_method_view_and_local_subclasses() {
        // MethodView inherits from View, and a local subclass of a Flask
        // view keeps the identity; decorators on both flag.
        let issues = found(concat!(
            "import flask.views\n",
            "from flask.views import MethodView\n",
            "\n",
            "@login_required\n",
            "class Api(MethodView):\n",
            "    def get(self):\n",
            "        return 'ok'\n",
            "\n",
            "class Base(flask.views.View):\n",
            "    pass\n",
            "\n",
            "@cache(minutes=5)\n",
            "class Users(Base):\n",
            "    def dispatch_request(self):\n",
            "        return 'ok'\n",
        ));
        assert_eq!(issues.len(), 2);
        assert_eq!(issues[0].range.start, pos(4, 0));
        assert_eq!(issues[1].range.start, pos(12, 0));
    }

    #[test]
    fn s8374_ignores_plain_classes_and_undecorated_views() {
        // Decorators on classes that do not inherit from a Flask view, and
        // view classes without decorators, stay silent.
        assert!(
            found(concat!(
                "from flask.views import View\n",
                "\n",
                "@login_required\n",
                "class Plain:\n",
                "    pass\n",
                "\n",
                "class Quiet(View):\n",
                "    def dispatch_request(self):\n",
                "        return 'ok'\n",
            ))
            .is_empty()
        );
    }
}
