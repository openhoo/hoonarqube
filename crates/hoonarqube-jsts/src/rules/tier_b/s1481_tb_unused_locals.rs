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

    fn unused_issues(source: &str) -> Vec<hoonarqube_ir::Issue> {
        js(source)
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "javascript:S1481")
            .collect()
    }

    #[test]
    fn express_range_binding_alias_is_clean() {
        assert_eq!(
            unused_issues(
                "const req = {};\nreq.range = function range(size, options) {\n  var range = this.get('Range');\n  if (!range) return;\n  return parseRange(size, range, options);\n};\n"
            ),
            []
        );
    }

    #[test]
    fn express_subdomains_binding_alias_is_clean() {
        assert_eq!(
            unused_issues(
                "const req = {};\ndefineGetter(req, 'subdomains', function subdomains() {\n  var hostname = this.hostname;\n  var offset = this.app.get('subdomain offset');\n  var subdomains = !isIP(hostname)\n    ? hostname.split('.').reverse()\n    : [hostname];\n  return subdomains.slice(offset);\n});\n"
            ),
            []
        );
    }

    #[test]
    fn express_colon_index_binding_alias_is_clean() {
        assert_eq!(
            unused_issues(
                "function acceptParams(str) {\n  var length = str.length;\n  var colonIndex = str.indexOf(';');\n  var index = colonIndex === -1 ? length : colonIndex;\n  while (index < length) {\n    var colonIndex = str.indexOf(';', index);\n    var endIndex = colonIndex === -1 ? length : colonIndex;\n    index = endIndex + 1;\n  }\n  return index;\n}\nacceptParams('text');\n"
            ),
            []
        );
    }

    #[test]
    fn var_aliases_share_reads_before_declaration_closures_and_writes() {
        for source in [
            "function f() { var value = 1; var value = 2; return value; } f();",
            "function f() { { var value = 1; } { var value = 2; } return value; } f();",
            "function f() { console.log(value); var value; var value; } f();",
            "function f() { var value; var value; return () => value; } f()();",
            "function f() { var value; var value; value = 1; } f();",
            "function f(value) { var value; return value; } f(1);",
            "function f() { function value() {} var value; return value; } f();",
            "const api = function recurse(value) { var recurse; return value ? recurse(value - 1) : 0; }; api(1);",
        ] {
            assert_eq!(unused_issues(source), [], "{source}");
        }
    }

    #[test]
    fn unused_var_aliases_keep_each_declaration_primary() {
        let source = "function f() {\n  var orphan = 1;\n  var orphan = 2;\n  return 0;\n}\nf();\n";
        assert_eq!(
            unused_issues(source),
            [
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'orphan' variable.",
                    (2, 6),
                    (2, 12)
                ),
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'orphan' variable.",
                    (3, 6),
                    (3, 12)
                ),
            ]
        );
    }

    #[test]
    fn unused_self_name_and_parameter_var_aliases_remain_findings() {
        for (source, name, end) in [
            (
                "const api = function self() {\n  var self = 1;\n  return 2;\n};\napi();\n",
                "self",
                10,
            ),
            (
                "function api(value) {\n  var value;\n  return 2;\n}\napi(1);\n",
                "value",
                11,
            ),
        ] {
            assert_eq!(
                unused_issues(source),
                [issue(
                    "javascript:S1481",
                    &format!("Remove the declaration of the unused '{name}' variable."),
                    (2, 6),
                    (2, end)
                )]
            );
        }
    }

    #[test]
    fn invalid_lexical_redeclarations_do_not_borrow_var_references() {
        for source in [
            "function f() {\n  let value = 1;\n  var value;\n  return value;\n}\nf();\n",
            "function f() {\n  const value = 1;\n  var value;\n  return value;\n}\nf();\n",
            "function f() {\n  class value {}\n  var value;\n  return value;\n}\nf();\n",
        ] {
            assert_eq!(
                unused_issues(source),
                [issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'value' variable.",
                    (3, 6),
                    (3, 11)
                )]
            );
        }
    }

    #[test]
    fn var_aliases_do_not_share_references_across_function_or_block_scopes() {
        let source = concat!(
            "function outer() {\n",
            "  var value = 1;\n",
            "  function inner() {\n",
            "    var value = 2;\n",
            "    var value = 3;\n",
            "    return 0;\n",
            "  }\n",
            "  { let value = 4; console.log(value); }\n",
            "  { let value = 5; }\n",
            "  inner();\n",
            "  return value;\n",
            "}\nouter();\n",
        );
        assert_eq!(
            unused_issues(source),
            [
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'value' variable.",
                    (4, 8),
                    (4, 13)
                ),
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'value' variable.",
                    (5, 8),
                    (5, 13)
                ),
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'value' variable.",
                    (9, 8),
                    (9, 13)
                ),
            ]
        );
    }

    #[test]
    fn var_aliases_keep_unicode_crlf_and_non_reference_decoys() {
        let source = concat!(
            "function f() {\r\n",
            "  var café = 1;\r\n",
            "  var café = 2;\r\n",
            "  const text = '🦉 café'; // café\r\n",
            "  const obj = { café: 3 };\r\n",
            "  return obj.café + text.length;\r\n",
            "}\r\nf();\r\n",
        );
        assert_eq!(
            unused_issues(source),
            [
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'café' variable.",
                    (2, 6),
                    (2, 10)
                ),
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'café' variable.",
                    (3, 6),
                    (3, 10)
                ),
            ]
        );
    }

    #[test]
    fn var_aliases_preserve_ordinary_locals_functions_classes_and_typescript_silence() {
        let source = "function f() {\n  const orphan = 1;\n  function hidden() {}\n  class Hidden {}\n  return 0;\n}\nf();\n";
        assert_eq!(
            unused_issues(source),
            [
                issue(
                    "javascript:S1481",
                    "Remove the declaration of the unused 'orphan' variable.",
                    (2, 8),
                    (2, 14)
                ),
                issue(
                    "javascript:S1481",
                    "Remove this unused function 'hidden'.",
                    (3, 11),
                    (3, 17)
                ),
                issue(
                    "javascript:S1481",
                    "Remove this unused class 'Hidden'.",
                    (4, 8),
                    (4, 14)
                ),
            ]
        );
        let typed =
            "function f(value: number): number { var value; var orphan = 1; return value; } f(1);";
        assert!(filtered(&ts(typed), "S1481").is_empty());
    }
}
