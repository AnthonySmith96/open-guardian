//! Evasion-resistant normalization for DLP detection.
//!
//! [`normalize_for_matching`] produces a canonical view of untrusted
//! text — NFKC, zero-width stripping, homoglyph folding, casefolding,
//! and recursive URL/HTML decoding — used exclusively for *detection*.
//! The original text is never rewritten: secrets located in the raw
//! text are redacted in place, while secrets that only surface in the
//! normalized view (obfuscated) cannot be safely rewritten and are
//! blocked upstream by the caller.

const ZERO_WIDTH_CHARS: &[char] = &[
    '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{FEFF}', '\u{202A}', '\u{202B}',
    '\u{202C}', '\u{202D}', '\u{202E}', '\u{2060}', '\u{2061}', '\u{2062}', '\u{2063}',
];

const HOMOGLYPH_MAPPINGS: &[(char, &str)] = &[
    ('\u{0430}', "a"),
    ('\u{0435}', "e"),
    ('\u{043E}', "o"),
    ('\u{0440}', "p"),
    ('\u{0441}', "c"),
    ('\u{0445}', "x"),
    ('\u{0433}', "g"),
    ('\u{0434}', "d"),
    ('\u{0443}', "y"),
    ('\u{0437}', "z"),
    ('\u{0438}', "i"),
    ('\u{043A}', "k"),
    ('\u{043B}', "l"),
    ('\u{043C}', "m"),
    ('\u{043D}', "n"),
    ('\u{0442}', "t"),
    ('\u{0444}', "f"),
    ('\u{03B1}', "a"),
    ('\u{03B5}', "e"),
    ('\u{03BF}', "o"),
    ('\u{03C1}', "p"),
    ('\u{03C3}', "c"),
    ('\u{FF21}', "A"),
    ('\u{FF41}', "a"),
    ('\u{212A}', "K"),
];

const MAX_DECODE_DEPTH: usize = 5;
/// Skip recursive decoding above this size: the pass is a detection
/// aid, not a promise to decode arbitrarily large payloads.
const MAX_DECODE_BYTES: usize = 1024 * 1024;

/// Returns the canonical matching form of `content`:
/// NFKC → zero-width strip → homoglyph fold → casefold →
/// recursive URL/HTML entity decoding.
pub fn normalize_for_matching(content: &str) -> String {
    use unicode_normalization::UnicodeNormalization;

    let normalized: String = content.nfkc().collect();

    let mut result = String::with_capacity(normalized.len());
    for c in normalized.chars() {
        if ZERO_WIDTH_CHARS.contains(&c) {
            continue;
        }
        match HOMOGLYPH_MAPPINGS.iter().find(|(orig, _)| *orig == c) {
            Some((_, replacement)) => result.push_str(replacement),
            None => result.push(c),
        }
    }
    let result = result.to_lowercase();

    if result.len() <= MAX_DECODE_BYTES {
        decode_recursive(&result, 0)
    } else {
        result
    }
}

fn looks_percent_encoded(content: &str) -> bool {
    content.as_bytes().windows(3).any(|window| {
        window[0] == b'%' && window[1].is_ascii_hexdigit() && window[2].is_ascii_hexdigit()
    })
}

fn contains_html_entity(content: &str) -> bool {
    let bytes = content.as_bytes();
    bytes
        .windows(2)
        .any(|window| window[0] == b'&' && (window[1] == b'#' || window[1].is_ascii_alphanumeric()))
        && content.contains(';')
}

fn decode_recursive(content: &str, depth: usize) -> String {
    if depth >= MAX_DECODE_DEPTH {
        return content.to_string();
    }

    let mut current = content.to_string();
    let mut decoded = false;

    if looks_percent_encoded(&current) {
        if let Ok(decoded_text) = urlencoding::decode(&current) {
            current = decoded_text.into_owned();
            decoded = true;
        }
    }

    if contains_html_entity(&current) {
        let decoded_text = html_escape::decode_html_entities(&current).to_string();
        if decoded_text != current {
            current = decoded_text;
            decoded = true;
        }
    }

    if decoded {
        decode_recursive(&current, depth + 1)
    } else {
        current
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_for_matching;

    #[test]
    fn percent_encoding_is_decoded_for_matching() {
        assert_eq!(normalize_for_matching("%73%6B%2Dsecret"), "sk-secret");
    }

    #[test]
    fn html_entities_are_decoded_for_matching() {
        assert_eq!(
            normalize_for_matching("password&#61;hunter2"),
            "password=hunter2"
        );
    }

    #[test]
    fn zero_width_and_homoglyphs_are_folded() {
        // 'а' here is Cyrillic U+0430, plus a zero-width space.
        let homoglyph = "аpproved\u{200B}key";
        assert_eq!(normalize_for_matching(homoglyph), "approvedkey");
    }

    #[test]
    fn case_is_folded() {
        assert_eq!(normalize_for_matching("IGNORE Previous"), "ignore previous");
    }

    #[test]
    fn recursive_double_encoding_is_unwrapped() {
        assert_eq!(normalize_for_matching("%2573%256B%252D"), "sk-");
    }

    #[test]
    fn plain_text_survives_unchanged() {
        assert_eq!(normalize_for_matching("hello world 123"), "hello world 123");
    }
}
