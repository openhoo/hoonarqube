use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::string_literal_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_disclosed_secret_keys(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for statement in &file_ctx.stmts {
        let (targets, value): (Vec<&Expr>, Option<&Expr>) = match statement {
            Stmt::Assign(assign) => (assign.targets.iter().collect(), Some(assign.value.as_ref())),
            Stmt::AnnAssign(assign) => (vec![assign.target.as_ref()], assign.value.as_deref()),
            _ => continue,
        };
        let Some(value) = value else {
            continue;
        };
        if !file_ctx.known_bindings.is_static_text(value) {
            continue;
        }
        for target in targets {
            if is_flask_secret_target(target, file_ctx) {
                issues.push(issue_at(
                    "python:S6779",
                    "Do not disclose secret keys in source code.",
                    value.range(),
                    index,
                    source,
                ));
                break;
            }
        }
    }
    issues
}

fn is_flask_secret_target(target: &Expr, file_ctx: &FileContext) -> bool {
    let Expr::Subscript(subscript) = target else {
        return false;
    };
    file_ctx
        .known_bindings
        .resolve_expr_identity(&subscript.value)
        == KnownBinding::FlaskConfig
        && string_literal_text(&subscript.slice).is_some_and(|key| key == "SECRET_KEY")
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s6779_requires_a_real_flask_secret_assignment() {
        let flagged = scan(
            "from flask import Flask\n\n\
             app = Flask(__name__)\n\
             app.config['SECRET_KEY'] = \"secret\"\n",
        );
        assert_eq!(findings(&flagged, "python:S6779").len(), 1);

        let safe = scan(
            "from flask import Flask\nimport os\n\n\
             app = Flask(__name__)\n\
             app.config['SECRET_KEY'] = os.environ['SECRET_KEY']\n",
        );
        assert!(findings(&safe, "python:S6779").is_empty());
    }

    #[test]
    fn s6779_ignores_lookalike_configurations() {
        let lookalike = scan("config['SECRET_KEY'] = \"secret\"\n");
        assert!(findings(&lookalike, "python:S6779").is_empty());
    }
}
