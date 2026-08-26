use super::support::composite_template;
use super::support::is_composite_format_call;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of, to_u32};
use crate::rules::logging::template_placeholders;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2275 — every referenced format slot needs an argument.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(call) || !is_composite_format_call(call, source) {
            continue;
        }
        let Some((literal, template, budget)) = composite_template(call, source) else {
            continue;
        };
        let highest = template_placeholders(template)
            .iter()
            .filter_map(|name| format_slot_index(name))
            .max();
        if highest.is_some_and(|index| index >= to_u32(budget)) {
            issues.push(issue(
                language,
                "S2275",
                "Match the format-string slots to the arguments of this call.",
                range_of(literal, source),
            ));
        }
    }
    issues
}

/// Numeric index of a `{12}`-style format slot. An all-digit index beyond
/// `u32` always exceeds any argument budget, so it maps to `u32::MAX`
/// rather than being dropped like a `{name}` interpolation slot.
fn format_slot_index(name: &str) -> Option<u32> {
    if !name.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    Some(name.parse().unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2275_flags_only_when_highest_slot_exceeds_budget() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{1}\", one, two);\n        text = string.Format(\"{2}\", one, two);\n        builder.AppendFormat(\"{0}-{1}\", one);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2275");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 6); // document line 5
        assert_eq!(flagged[1].range.start.line, 7); // document line 6
    }

    #[test]
    fn s2275_ignores_escaped_and_nonnumeric_slots() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{{0}}\", one);\n        text = string.Format(\"{name}\");\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2275").is_empty());
    }

    #[test]
    fn s2275_flags_slot_indexes_beyond_u32() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        text = string.Format(\"{9999999999999}\", one);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2275");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 5);
    }
}
