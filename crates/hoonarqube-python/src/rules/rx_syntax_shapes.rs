use crate::engine::rx::RxParsed;
use crate::engine::rx::RxUnit;
use crate::engine::rx::for_each_rx_item;
use crate::engine::rx::rx_atom_nullable;
use crate::rules::rx_alternation_shapes::check_rx_alternation_shapes;
use crate::rules::rx_empty_groups::check_rx_empty_groups;
use crate::rules::rx_pointless_groups::check_rx_pointless_groups;
use crate::rules::rx_redundant_alternatives::check_rx_redundant_alternatives;
use crate::support::to_u32;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

pub(crate) fn check_rx_syntax_shapes(
    parsed: &RxParsed,
    units: &[RxUnit],
    verbose: bool,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    // python:S5842 — repeated patterns matching the empty string.
    for_each_rx_item(&parsed.root, &mut |item| {
        if item.quant.is_some() && rx_atom_nullable(&item.atom) {
            let span = match &item.atom {
                crate::engine::rx::RxAtom::Group(group) => group.span,
                _ => item.span,
            };
            push(
                "python:S5842",
                "Rework this part of the regex to not match the empty string.",
                span,
            );
        }
    });
    // python:S6001 — back references to groups not matched before them.
    for record in &parsed.backrefs {
        let valid = match (&record.number, &record.name) {
            (Some(number), _) => number != &0 && record.visible_numbers.contains(number),
            (None, Some(name)) => record.visible_names.contains(name),
            (None, None) => true,
        };
        if !valid {
            push(
                "python:S6001",
                "This back reference refers to a group that is not matched before it.",
                record.span,
            );
        }
    }
    // python:S6537 — octal escapes at both the string and pattern level.
    for span in units
        .iter()
        .filter(|unit| unit.octal)
        .map(|unit| TextRange::at(unit.at, TextSize::from(to_u32(unit.ch.len_utf8()))))
        .chain(parsed.octals.iter().map(|record| record.span))
    {
        push(
            "python:S6537",
            "Replace this octal escape with a hexadecimal or Unicode escape.",
            span,
        );
    }
    // python:S6002 / python:S6035 / python:S6323 — alternation and lookahead shapes.
    check_rx_alternation_shapes(parsed, verbose, push);
    // python:S5855 — alternatives covered by an earlier alternative.
    check_rx_redundant_alternatives(&parsed.root, push);
    check_rx_empty_groups(parsed, push);
    check_rx_pointless_groups(parsed, push);
}

#[cfg(test)]
mod tests {

    use crate::test_support::regex_finds;

    #[test]
    fn s6001_flags_back_references_to_unmatched_groups() {
        for pattern in [r"\1(.)", r"(.)\2", r"(.)|\1", r"(?P<x>.)|(?P=x)"] {
            assert!(
                regex_finds(
                    &format!("import re\nre.compile(r'{pattern}')\n"),
                    "python:S6001"
                ),
                "{pattern}"
            );
        }
        assert!(!regex_finds(
            "import re\nre.compile(r'(.)\\1')\n",
            "python:S6001"
        ));
    }
}
