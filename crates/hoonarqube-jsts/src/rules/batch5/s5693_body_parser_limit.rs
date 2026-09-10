use crate::rules::batch5::collectors::{SecurityHotspotCollector, SecurityModule, SecurityValue};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

const STANDARD_SIZE_LIMIT: f64 = 2_000_000.0;
const PARSER_METHODS: [&str; 4] = ["json", "raw", "text", "urlencoded"];

impl SecurityHotspotCollector<'_, '_> {
    /// `S5693`: body parsers configured above the reviewed request limit.
    ///
    /// Express and body-parser both default to a 100kb limit.  Therefore an
    /// omitted option is safe here; only a statically known numeric or
    /// byte-size string above the catalog's 2,000,000-byte standard limit is
    /// reported.  Opaque, runtime, and mutation-invalidated values stay
    /// unknown rather than being guessed.  The pinned `SonarJS` 4.2 control
    /// incorrectly looks for plural `limits` on body-parser; this native
    /// implementation intentionally uses the real singular `limit` option.
    pub(crate) fn check_body_parser_limit(&mut self, call: &CallExpression<'_>) {
        let at = call.span().start;
        let is_parser = [SecurityModule::Express, SecurityModule::BodyParser]
            .into_iter()
            .any(|module| {
                PARSER_METHODS.iter().copied().any(|method| {
                    self.security_bindings
                        .is_module_member(&call.callee, module, method, at)
                })
            });
        if !is_parser {
            return;
        }
        let Some(options) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Some(limit) = self.security_bindings.object_property(options, "limit", at) else {
            return;
        };
        if !limit_exceeds_standard(&limit) {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S5693",
            "Configure a request-body size limit ('limit').",
            call.span(),
        );
    }
}

fn limit_exceeds_standard(value: &SecurityValue) -> bool {
    match value {
        SecurityValue::Number(value) => *value > STANDARD_SIZE_LIMIT,
        SecurityValue::String(value) => {
            parse_byte_size(value).is_some_and(|value| value > STANDARD_SIZE_LIMIT)
        }
        _ => false,
    }
}

fn parse_byte_size(value: &str) -> Option<f64> {
    let value = value.trim();
    let number_end = value
        .char_indices()
        .find_map(|(index, character)| {
            (!character.is_ascii_digit() && !matches!(character, '.' | '+' | '-')).then_some(index)
        })
        .unwrap_or(value.len());
    let number_text = value.get(..number_end)?;
    let unit = value.get(number_end..)?.trim().to_ascii_lowercase();
    if unit.is_empty() {
        let integer_end = number_text.find('.').unwrap_or(number_text.len());
        return number_text
            .get(..integer_end)?
            .parse::<f64>()
            .ok()
            .map(f64::trunc);
    }
    let number = number_text.parse::<f64>().ok()?;
    let multiplier = match unit.as_str() {
        "b" => 1.0,
        "kb" => 1_024.0,
        "mb" => 1_048_576.0,
        "gb" => 1_073_741_824.0,
        "tb" => 1_099_511_627_776.0,
        "pb" => 1_125_899_906_842_624.0,
        _ => return None,
    };
    Some((number * multiplier).floor())
}

#[cfg(test)]
mod tests {
    use crate::test_support::{count_key, js_keys, ts_keys};

    #[test]
    fn only_known_parser_limits_above_two_million_bytes_are_flagged() {
        let javascript = "\
const bodyParser = require('body-parser');\n\
bodyParser.json({ limit: '4mb' });\n\
bodyParser.raw({ limit: 2_000_001 });\n\
const json = bodyParser.json;\n\
json({ limit: '4mb' });\n";
        assert_eq!(count_key(&js_keys(javascript), "javascript:S5693"), 3);

        let typescript = "\
import bodyParser from 'body-parser';\n\
bodyParser.json({ limit: '4mb' });\n\
bodyParser.urlencoded({ extended: false, limit: '2mb' });\n";
        assert_eq!(count_key(&ts_keys(typescript), "typescript:S5693"), 2);
    }

    #[test]
    fn string_limits_follow_bytes_parsing_without_scientific_guessing() {
        assert!(
            super::parse_byte_size("2000000.9")
                .is_some_and(|value| value <= super::STANDARD_SIZE_LIMIT)
        );
        assert!(super::parse_byte_size("4e6").is_none());
        assert!(
            super::parse_byte_size("3pb").is_some_and(|value| value > super::STANDARD_SIZE_LIMIT)
        );
    }

    #[test]
    fn express_parsers_use_the_same_bound_and_default() {
        let source = "\
const express = require('express');\n\
express.json({ limit: '4mb' });\n\
express.urlencoded({});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S5693"), 1);
    }

    #[test]
    fn defaults_small_limits_and_unknown_or_mutated_values_are_clean() {
        let source = "\
const bodyParser = require('body-parser');\n\
bodyParser.json({});\n\
bodyParser.text({ limit: '100kb' });\n\
bodyParser.urlencoded({ limit: 2_000_000 });\n\
const runtimeLimit = process.env.BODY_LIMIT;\n\
bodyParser.raw({ limit: runtimeLimit });\n\
const options = { limit: '4mb' };\n\
options.limit = '1mb';\n\
bodyParser.json(options);\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S5693"), 0);
    }

    #[test]
    fn computed_and_dynamic_writes_invalidate_only_after_observation() {
        let source = "\
const bodyParser = require('body-parser');\n\
const before = { limit: '4mb' };\n\
bodyParser.json(before);\n\
before['limit'] = 1000;\n\
bodyParser.json(before);\n\
const dynamic = { limit: '4mb' };\n\
const key = process.env.BODY_OPTION;\n\
dynamic[key] = 1000;\n\
bodyParser.json(dynamic);\n\
const unrelated = { limit: '4mb' };\n\
unrelated.other = true;\n\
bodyParser.json(unrelated);\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S5693"), 2);
    }

    #[test]
    fn bound_option_spreads_are_not_treated_as_snapshots() {
        let source = "\
const bodyParser = require('body-parser');\n\
const options = { limit: '4mb', ...{ limit: '1mb' } };\n\
bodyParser.json(options);\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S5693"), 0);
    }

    #[test]
    fn local_lookalikes_shadowed_roots_and_rebound_roots_are_clean() {
        let source = "\
const bodyParser = { json() {} };\n\
bodyParser.json({ limit: '4mb' });\n\
function parse(express) {\n\
  express.json({ limit: '4mb' });\n\
}\n\
let express = require('express');\n\
express = { json() {} };\n\
express.json({ limit: '4mb' });\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S5693"), 0);
    }
}
