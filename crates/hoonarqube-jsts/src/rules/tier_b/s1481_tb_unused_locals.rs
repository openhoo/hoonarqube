// Rule module s1481_tb_unused_locals (generated).
use crate::engine::scope_model::{TbKind, TbModel};
use crate::support::{IssueSink, RuleScope};

/// S1481 (JS only) — local variables/functions/classes without any reference.
pub(crate) fn check_tb_unused_locals(model: &TbModel<'_>, sink: &mut IssueSink<'_>) {
    for binding in &model.bindings {
        let unreferenced = binding.reads.is_empty() && binding.writes.is_empty();
        if binding.kind.is_local_value()
            && !binding.global
            && !binding.function_expression_name
            && unreferenced
        {
            let noun = match binding.kind {
                TbKind::Function => "function",
                TbKind::Class => "class",
                _ => "local variable",
            };
            let name = binding.name;
            sink.emit_span(
                RuleScope::JsOnly,
                "S1481",
                &if noun == "local variable" {
                    format!("Remove the declaration of the unused '{name}' variable.")
                } else {
                    format!("Remove this unused {noun} '{name}'.")
                },
                binding.decl,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn unused_locals_flagged_inside_functions_but_not_at_top_level() {
        let source = "const kept = 1;\nfunction f() {\n  const orphan = 2;\n}\nf();\n";
        let issues = filtered(&js(source), "S1481");
        assert_eq!(issues.len(), 1);
        assert!(issues[0].contains("orphan"));
    }

    #[test]
    fn function_expression_names_are_exempt_from_unused_locals() {
        for source in [
            "const app = {}; app.init = function init() { return app; }; app.init();",
            "[1].map(function callback(value) { return value; });",
            "(function initialized() { return 1; })();",
            "const api = async function asyncName() { return 1; }; api();",
            "const api = function* generatorName() { yield 1; }; api();",
        ] {
            assert!(filtered(&js(source), "S1481").is_empty(), "{source}");
        }
    }

    #[test]
    fn function_expression_names_keep_nested_unused_values_and_declarations() {
        let source = concat!(
            "function outer() {\n",
            "  const kept = function innerName() {\n",
            "    const orphan = 1;\n",
            "    function hidden() {}\n",
            "    return 2;\n",
            "  };\n",
            "  return kept;\n",
            "}\nouter();\n",
        );
        let actual: Vec<_> = js(source)
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "javascript:S1481")
            .collect();
        assert_eq!(
            actual,
            [
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'orphan' variable.",
                    (3, 10),
                    (3, 16),
                ),
                issue(
                    "javascript:S1481",
                    "Remove this unused function 'hidden'.",
                    (4, 13),
                    (4, 19),
                ),
            ]
        );
    }

    #[test]
    fn function_expression_names_keep_unused_outer_variable_and_class_behavior() {
        let source = "function outer() {\n  const orphan = function selfName() { return 1; };\n  return 2;\n}\nouter();\n";
        let actual: Vec<_> = js(source)
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "javascript:S1481")
            .collect();
        assert_eq!(
            actual,
            [issue(
                "javascript:S1481",
                "Remove the declaration of the unused 'orphan' variable.",
                (2, 8),
                (2, 14),
            )]
        );
        // Class expression behavior is a separately retained parity lead.
        let source = "const exportedClass = class NamedClass {};\nnew exportedClass();\n";
        assert_eq!(
            filtered(&js(source), "S1481"),
            ["javascript:S1481:1:Remove this unused class 'NamedClass'."]
        );
    }

    #[test]
    fn function_expression_names_preserve_recursion_and_typescript_scope() {
        let recursive = "const factorial = function recurse(value) { return value === 0 ? 1 : value * recurse(value - 1); }; factorial(3);";
        assert!(filtered(&js(recursive), "S1481").is_empty());
        let typed = "const api = function typed(value: number): number { return value; }; api(1);";
        assert!(filtered(&ts(typed), "S1481").is_empty());
    }
}
