//! SG-41 German message text conventions.
//!
//! The historical plaintext space key is `J`. Literal `J` is written `II`,
//! and German umlauts are expanded before the electrical transformation.
//! These presentation transformations are separate from `Sg41Core`.

use old_crypto_rs::helpers::{group_five, ungroup_ciphertext};

/// Prepare German plaintext for the alphabetic SG-41.
///
/// ASCII letters become uppercase, spaces become `J`, `Ä/Ö/Ü` become
/// `AE/OE/UE`, and literal `J` becomes `II`. Other characters are rejected
/// with their Unicode-character index.
///
/// The result is not losslessly reversible: the historical encoding loses
/// the distinction between an original `II` and a substituted `J`.
pub fn prepare_plaintext(input: &str) -> Result<String, (usize, char)> {
    let mut output = String::with_capacity(input.len());

    for (index, ch) in input.chars().enumerate() {
        match ch {
            ' ' => output.push('J'),
            'j' | 'J' => output.push_str("II"),
            'ä' | 'Ä' => output.push_str("AE"),
            'ö' | 'Ö' => output.push_str("OE"),
            'ü' | 'Ü' => output.push_str("UE"),
            'A'..='I' | 'K'..='Z' => output.push(ch),
            'a'..='i' | 'k'..='z' => output.push(ch.to_ascii_uppercase()),
            _ => return Err((index, ch)),
        }
    }

    Ok(output)
}

/// Display raw deciphered SG-41 letters as readable text.
///
/// An electrical `J` denotes a word space. This does not reconstruct
/// umlauts or the original literal `J` spelling, and is not a lossless
/// inverse of `prepare_plaintext`.
#[must_use]
pub fn display_plaintext(raw: &str) -> String {
    raw.replace('J', " ")
}

/// Normalize grouped SG-41 ciphertext to uppercase letters.
///
/// ASCII grouping whitespace is ignored without advancing machine state.
pub fn parse_ciphertext(input: &str) -> Result<String, (usize, char)> {
    ungroup_ciphertext(input)
}

/// Format *ungrouped*, normalized ciphertext in five-letter groups.
///
/// The caller must first prepare/normalize the text. Existing grouping
/// whitespace is not removed by this function.
#[must_use]
pub fn format_ciphertext(raw: &str) -> String {
    group_five(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn german_conventions() {
        assert_eq!(
            prepare_plaintext("Jäger über Öl").unwrap(),
            "IIAEGERJUEBERJOEL"
        );
        assert_eq!(prepare_plaintext("Hallo Welt").unwrap(), "HALLOJWELT");
    }

    #[test]
    fn invalid_plaintext_is_rejected_at_character_index() {
        assert_eq!(prepare_plaintext("Aß").unwrap_err(), (1, 'ß'));
        assert_eq!(prepare_plaintext("A!").unwrap_err(), (1, '!'));
    }

    #[test]
    fn display_is_intentionally_lossy() {
        assert_eq!(display_plaintext("HALLOJWELT"), "HALLO WELT");
        assert_eq!(display_plaintext("IIAEGER"), "IIAEGER");
    }

    #[test]
    fn ciphertext_grouping_uses_shared_helpers() {
        assert_eq!(
            parse_ciphertext("ihepl retqs\nDSDSN").unwrap(),
            "IHEPLRETQSDSDSN"
        );
        assert_eq!(
            format_ciphertext("IHEPLRETQSDSDSN"),
            "IHEPL RETQS DSDSN"
        );
        assert_eq!(parse_ciphertext("ABC-").unwrap_err(), (3, '-'));
    }

    #[test]
    fn historic_reference_remains_unmodified() {
        let reference = "SCHLUESSELGERAETVIEREINSWANDERER";
        assert_eq!(prepare_plaintext(reference).unwrap(), reference);
    }
}
