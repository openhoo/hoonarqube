use super::regex_syntax::is_regex_pattern;
use super::support::literal_assignments;
use super::support::literal_inner_text;
use crate::cst::{issue, range_of};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6418 — names matching a secret word plus high-entropy
/// literal values point at hard-coded secrets.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    literal_assignments(root, source)
        .into_iter()
        .filter(|(_, name, literal)| {
            let value = literal_inner_text(*literal, source);
            secret_word_in(name, &options.secret_words).is_some()
                && looks_like_secret(value, options.secret_randomness_sensibility)
                && !is_regex_pattern(value)
        })
        .map(|(anchor, _, _)| {
            issue(
                language,
                "S6418",
                "Review this potentially hard-coded secret.",
                range_of(anchor, source),
            )
        })
        .collect()
}

/// Matches the catalog default `secretWords` shapes natively
/// (`api[_\-]?key`) and degrades every other entry to a case-insensitive
/// substring search.
fn secret_word_in<'w>(name: &str, words: &'w [String]) -> Option<&'w str> {
    let lowered = name.to_lowercase();
    words.iter().map(String::as_str).find(|word| {
        if word.eq_ignore_ascii_case(r"api[_\-]?key") {
            lowered.contains("apikey") || lowered.contains("api_key") || lowered.contains("api-key")
        } else {
            lowered.contains(&word.to_lowercase())
        }
    })
}

/// Entropy heuristic: enough distinct character classes and a non-trivial
/// length separate real secrets from placeholder values like `"token"`.
fn looks_like_secret(value: &str, sensibility: u32) -> bool {
    let classes = [
        value.chars().any(|c| c.is_ascii_lowercase()),
        value.chars().any(|c| c.is_ascii_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| !c.is_ascii_alphanumeric()),
    ];
    value.chars().count() >= 8
        && classes.iter().filter(|seen| **seen).count()
            >= usize::try_from(sensibility).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6418_minimum_length_counts_characters_not_utf8_bytes() {
        let report = analyze_default("var apiKey = \"aA1!éé\";\n");
        assert!(with_key(&report, "csharpsquid:S6418").is_empty());
    }

    #[test]
    fn s6418_skips_regex_pattern_constants() {
        // The issue-824 fixture: an anchored pattern with a character class
        // and bounded quantifier describes a token shape, not a token value.
        let report = analyze_default(
            "using System.Text.RegularExpressions;\n\
             internal static class TokenRules\n{\n\
                 private const string TokenPattern = \"^[A-Za-z0-9_-]{43}$\";\n\n\
                 public static bool IsValid(string token)\n    {\n\
                     return Regex.IsMatch(token, TokenPattern);\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6418").is_empty());

        // Other credential-named regex shapes stay clean as well.
        let patterns = analyze_default(
            "var tokenPattern = @\"^\\d{4}-[A-Z]{2}$\";\n\
             var secretRegex = \"(alpha|beta)[0-9]+\";\n",
        );
        assert!(with_key(&patterns, "csharpsquid:S6418").is_empty());
    }

    #[test]
    fn s6418_keeps_secret_shaped_values_reportable() {
        // A 43-character alphanumeric token value carries no regex syntax.
        let report = analyze_default(
            "private const string AccessToken = \"aB3xY9kQ2mNp7RsT4vW8zA1bC3dE5fG6hJ7kL9mN0p\";\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6418").len(), 1);

        // A lone anchor is not enough to exempt a secret-looking value.
        let anchored = analyze_default("var token = \"^aB3xY9kQ2mNp\";\n");
        assert_eq!(with_key(&anchored, "csharpsquid:S6418").len(), 1);

        // Regex characters that do not form a valid pattern stay reportable.
        let invalid = analyze_default("var token = \"aB3$xY9#kQ[2\";\n");
        assert_eq!(with_key(&invalid, "csharpsquid:S6418").len(), 1);
    }
}
