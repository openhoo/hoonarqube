use crate::engine::file_context::FileContext;
use crate::support::{UnconditionalAssertFacts, issue_at, unconditional_assert_verdict_with_facts};
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unconditional_assertions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let facts = UnconditionalAssertFacts::build(parsed);
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if unconditional_assert_verdict_with_facts(call, source, &facts).is_some() {
            issues.push(issue_at(
                "python:S5914",
                "Replace this expression; its boolean value is constant.",
                call.arguments.args[0].range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5914_flags_only_constant_boolean_assertions() {
        let flagged =
            scan("case.assertTrue(True)\ncase.assertFalse(False)\ncase.assertEqual(a, a)\n");
        let issues = findings(&flagged, "python:S5914");
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().all(
            |issue| issue.message == "Replace this expression; its boolean value is constant."
        ));
        assert_eq!(
            (issues[0].range.start.line, issues[0].range.start.column),
            (1, 16)
        );
        // CE does not implement the assertEqual(x, x) comparison form.
        assert!(findings(&scan("case.assertEqual(a, a)\n"), "python:S5914").is_empty());
    }

    #[test]
    fn s5914_flags_reaching_constant_assignments_but_not_dynamic_or_shadowed_values() {
        let flagged = scan("actual = 1\ncase.assertTrue(actual)\n");
        let issues = findings(&flagged, "python:S5914");
        assert_eq!(issues.len(), 1);
        assert_eq!(
            issues[0].message,
            "Replace this expression; its boolean value is constant."
        );

        let nested_literal = scan("def check():\n    case.assertTrue(True)\n");
        assert_eq!(findings(&nested_literal, "python:S5914").len(), 1);

        let branch_clean = concat!(
            "actual = 1\n",
            "if flag:\n",
            "    actual = 2\n",
            "case.assertTrue(actual)\n"
        );
        assert!(findings(&scan(branch_clean), "python:S5914").is_empty());

        let try_alias_clean = concat!(
            "actual = 1\n",
            "try:\n",
            "    pass\n",
            "except Exception as actual:\n",
            "    pass\n",
            "case.assertTrue(actual)\n"
        );
        assert!(findings(&scan(try_alias_clean), "python:S5914").is_empty());

        let match_capture_clean = concat!(
            "actual = 1\n",
            "match value:\n",
            "    case actual:\n",
            "        pass\n",
            "case.assertTrue(actual)\n"
        );
        assert!(findings(&scan(match_capture_clean), "python:S5914").is_empty());

        let capture_free_match = concat!(
            "actual = 1\n",
            "match value:\n",
            "    case 1:\n",
            "        pass\n",
            "case.assertTrue(actual)\n"
        );
        assert_eq!(findings(&scan(capture_free_match), "python:S5914").len(), 1);

        let nested_capture_scope = concat!(
            "actual = 1\n",
            "def check(value):\n",
            "    match value:\n",
            "        case actual:\n",
            "            pass\n",
            "class Holder:\n",
            "    match value:\n",
            "        case actual:\n",
            "            pass\n",
            "case.assertTrue(actual)\n"
        );
        assert_eq!(
            findings(&scan(nested_capture_scope), "python:S5914").len(),
            1
        );

        let scoped_calls_clean = concat!(
            "actual = 1\n",
            "(lambda actual: case.assertTrue(actual))(value)\n",
            "[case.assertTrue(actual) for actual in values]\n"
        );
        assert!(findings(&scan(scoped_calls_clean), "python:S5914").is_empty());

        let clean = concat!(
            "actual = int(input())\n",
            "case.assertTrue(actual)\n",
            "actual = 1\n",
            "actual = input()\n",
            "case.assertTrue(actual)\n",
            "def check(actual):\n",
            "    case.assertTrue(actual)\n"
        );
        assert!(findings(&scan(clean), "python:S5914").is_empty());
    }
}
