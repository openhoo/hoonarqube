// --- python:S2068 — hard-coded credentials.

pub(crate) const CREDENTIAL_WORDS: [&str; 4] = ["password", "passwd", "pwd", "passphrase"];

pub(crate) fn name_words(name: &str) -> impl Iterator<Item = &str> {
    name.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|word| !word.is_empty())
}

#[derive(Clone, Copy)]
pub(crate) enum CredentialInterpolation {
    Percent,
    Brace,
}

/// Matches credential-shaped text whose value is concrete rather than a
/// runtime interpolation.  The caller supplies the surrounding expression
/// context because a plain string literal alone cannot prove that `%s` or
/// `{name}` is evaluated as a template.
pub(crate) fn embeds_credential(
    text: &str,
    interpolation: Option<CredentialInterpolation>,
) -> bool {
    let lower = text.to_lowercase();
    CREDENTIAL_WORDS.iter().any(|word| {
        lower.match_indices(word).any(|(position, _)| {
            let rest = lower[position + word.len()..].trim_start_matches([' ', '\t']);
            let Some((separator_offset, separator)) = rest.char_indices().next() else {
                return false;
            };
            if separator != '=' && separator != ':' {
                return false;
            }
            let value =
                rest[separator_offset + separator.len_utf8()..].trim_start_matches([' ', '\t']);
            value
                .chars()
                .next()
                .is_some_and(|first| !first.is_whitespace())
                && !interpolation.is_some_and(|kind| starts_with_runtime_placeholder(value, kind))
        })
    })
}

fn starts_with_runtime_placeholder(value: &str, kind: CredentialInterpolation) -> bool {
    if matches!(kind, CredentialInterpolation::Brace) {
        return value.starts_with('{') && !value.starts_with("{{") && value[1..].contains('}');
    }
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'%') || bytes.get(1) == Some(&b'%') {
        return false;
    }
    let mut position = 1;
    if bytes.get(position) == Some(&b'(') {
        let Some(relative_end) = bytes[position + 1..].iter().position(|byte| *byte == b')') else {
            return false;
        };
        position += relative_end + 2;
    }
    while bytes
        .get(position)
        .is_some_and(|byte| matches!(byte, b'-' | b'+' | b' ' | b'#' | b'0'))
    {
        position += 1;
    }
    while bytes.get(position).is_some_and(u8::is_ascii_digit) {
        position += 1;
    }
    if bytes.get(position) == Some(&b'.') {
        position += 1;
        while bytes.get(position).is_some_and(u8::is_ascii_digit) {
            position += 1;
        }
    }
    while bytes
        .get(position)
        .is_some_and(|byte| matches!(byte, b'h' | b'l' | b'L'))
    {
        position += 1;
    }
    bytes
        .get(position)
        .is_some_and(|byte| b"diouxXeEfFgGcrsa".contains(byte))
}
