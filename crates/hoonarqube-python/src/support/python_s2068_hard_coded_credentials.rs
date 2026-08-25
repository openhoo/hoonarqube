// --- python:S2068 — hard-coded credentials.

pub(crate) const CREDENTIAL_WORDS: [&str; 4] = ["password", "passwd", "pwd", "passphrase"];

pub(crate) fn name_words(name: &str) -> impl Iterator<Item = &str> {
    name.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
}

/// Matches `(?i)(password|passwd|pwd|passphrase)\s*[=:]\s*\S` inside a
/// string literal.
pub(crate) fn embeds_credential(text: &str) -> bool {
    let lower = text.to_lowercase();
    CREDENTIAL_WORDS.iter().any(|word| {
        lower.match_indices(word).any(|(position, _)| {
            let rest = lower[position + word.len()..].trim_start_matches([' ', '\t']);
            let Some(separator) = rest.chars().next() else {
                return false;
            };
            (separator == '=' || separator == ':')
                && rest[1..]
                    .trim_start_matches([' ', '\t'])
                    .chars()
                    .next()
                    .is_some_and(|ch| !ch.is_whitespace())
        })
    })
}
