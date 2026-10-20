//! US military and historical tactical text normalization helpers.
//!
//! Provides utilities for standard WWII and Cold War tactical encipherment
//! text preparation conventions (e.g. CSP-889 / SIGABA, TSEC/KL-7, Hagelin M-209),
//! including space and letter substitution rules, ciphertext grouping, and whitespace filtering.
//!
//! # Lossy plaintext conventions
//!
//! Historical plaintext preparation may map distinct input characters
//! to the same electrical or transmitted character.
//!
//! In SIGABA/KL-7-style handling, both an original `X` and an
//! original `Z` can become electrical `X`. In M-209-style handling,
//! both a word space and a literal `Z` become `Z`.
//!
//! These ambiguities cannot be resolved by decryption alone.
//! Human-readable display helpers should therefore not be treated
//! as exact inverses of plaintext preparation functions.

use crate::helpers::output_as_block;

/// Encode one human plaintext character into a 26-element contact index (`0..25`)
/// according to historical US military cipher machine conventions (SIGABA, KL-7).
///
/// # Conventions
/// - `' '` (space) maps to electrical contact `'Z'` (index 25).
/// - `'Z'` / `'z'` maps to electrical contact `'X'` (index 23).
/// - `'A'..='Y'` / `'a'..='y'` map directly to indices `0..=24`.
/// - Any other character returns `None`.
#[must_use]
pub const fn plaintext_to_military_us(ch: char) -> Option<u8> {
    match ch {
        ' ' => Some(b'Z' - b'A'),
        'z' | 'Z' => Some(b'X' - b'A'),
        'a'..='y' => Some(ch as u8 - b'a'),
        'A'..='Y' => Some(ch as u8 - b'A'),
        _ => None,
    }
}


/// Convert one deciphered electrical contact (`0..25`) to human-readable
/// plaintext according to SIGABA/KL-7 conventions.
///
/// # Conventions
///
/// - Contact `25` (`'Z'`) is displayed as a space.
/// - Contacts `0..=24` are displayed as `'A'..='Y'`.
/// - Invalid contact indices return `None`.
///
/// # Lossy conversion
///
/// This is not the inverse of [`plaintext_to_military_us`].
///
/// During plaintext preparation, an original `'Z'` is substituted with
/// electrical `'X'` (contact 23), while an original `'X'` also maps to
/// contact 23. Consequently, a deciphered `'X'` cannot be identified
/// unambiguously as an original `'X'` or `'Z'`.
///
/// The function therefore returns `'X'` for both cases. Recovering the
/// original spelling requires external context.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{
///     military_us_to_plaintext, plaintext_to_military_us,
/// };
///
/// assert_eq!(military_us_to_plaintext(25), Some(' '));
/// assert_eq!(military_us_to_plaintext(23), Some('X'));
/// assert_eq!(
///     military_us_to_plaintext(plaintext_to_military_us('Z').unwrap()),
///     Some('X')
/// );
/// ```
#[must_use]
pub const fn military_us_to_plaintext(contact: u8) -> Option<char> {
    match contact {
        25 => Some(' '),
        0..=24 => Some((b'A' + contact) as char),
        _ => None,
    }
}

/// Parse one ciphertext character according to US military conventions.
///
/// Returns:
/// - `Ok(Some(contact))` for ASCII letters (`0..25`).
/// - `Ok(None)` for grouping whitespace (`' '`, `'\t'`, `'\r'`, `'\n'`), which must
///   not advance machine state.
/// - `Err(ch)` if an unsupported ciphertext character is encountered.
pub fn ciphertext_to_military_us(ch: char) -> Result<Option<u8>, char> {
    match ch {
        'a'..='z' => Ok(Some(ch.to_ascii_uppercase() as u8 - b'A')),
        'A'..='Z' => Ok(Some(ch as u8 - b'A')),
        ' ' | '\t' | '\r' | '\n' => Ok(None),
        _ => Err(ch),
    }
}

/// Format a continuous stream of ciphertext letters into standard 5-letter groups.
///
/// # Examples
/// ```
/// use old_crypto_rs::helpers::format_five_letter_groups;
///
/// assert_eq!(format_five_letter_groups("ABCDE"), "ABCDE");
/// assert_eq!(format_five_letter_groups("ABCDEF"), "ABCDE F");
/// assert_eq!(format_five_letter_groups("ABCDEFGHIJKLMNO"), "ABCDE FGHIJ KLMNO");
/// ```
#[must_use]
pub fn format_five_letter_groups(ciphertext: &str) -> String {
    output_as_block(ciphertext)
}

/// Alias for [`format_five_letter_groups`].
#[must_use]
pub fn group_five(letters: &str) -> String {
    format_five_letter_groups(letters)
}

/// Interpret spaces as `'Z'`, and normalize ASCII letters to uppercase for tactical ciphers (e.g. M-209).
///
/// Returns `Err((index, character))` if an unsupported character is encountered.
pub fn prepare_tactical_plaintext(plaintext: &str) -> Result<String, (usize, char)> {
    let mut prepared = String::with_capacity(plaintext.len());

    for (index, character) in plaintext.chars().enumerate() {
        match character {
            ' ' => prepared.push('Z'),
            'A'..='Z' => prepared.push(character),
            'a'..='z' => prepared.push(character.to_ascii_uppercase()),
            _ => return Err((index, character)),
        }
    }

    Ok(prepared)
}

/// Remove ASCII whitespace used solely to group ciphertext and normalize letters to uppercase.
///
/// Returns `Err((index, character))` if an unsupported character is encountered.
pub fn ungroup_ciphertext(ciphertext: &str) -> Result<String, (usize, char)> {
    let mut ungrouped = String::with_capacity(ciphertext.len());

    for (index, character) in ciphertext.chars().enumerate() {
        match character {
            'A'..='Z' => ungrouped.push(character),
            'a'..='z' => ungrouped.push(character.to_ascii_uppercase()),
            c if c.is_ascii_whitespace() => {}
            _ => return Err((index, character)),
        }
    }

    Ok(ungrouped)
}

/// Replace every raw `'Z'` with a word space `' '` for historical display presentation.
///
/// Render raw deciphered tactical plaintext with word spaces.
///
/// Replaces every uppercase `'Z'` with a space, following the
/// presentation convention used by machines such as the M-209.
///
/// # Lossy conversion
///
/// During [`prepare_tactical_plaintext`], spaces are encoded as `'Z'`,
/// but literal `'Z'` characters are also preserved. The resulting
/// representation cannot distinguish an original space from an original
/// `'Z'`.
///
/// This function interprets **every** uppercase `'Z'` as a space.
/// Consequently, it is intended for human-readable presentation only,
/// not for lossless recovery of the original message.
///
/// Callers that need to preserve the deciphered character stream should
/// retain the raw plaintext instead.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{
///     display_tactical_plaintext, prepare_tactical_plaintext,
/// };
///
/// assert_eq!(
///     display_tactical_plaintext("ATTACKZATZDAWN"),
///     "ATTACK AT DAWN"
/// );
///
/// assert_eq!(
///     prepare_tactical_plaintext("PIZZA").unwrap(),
///     "PIZZA"
/// );
///
/// assert_eq!(
///     display_tactical_plaintext("PIZZA"),
///     "PI  A"
/// );
/// ```
#[must_use]
pub fn display_tactical_plaintext(raw: &str) -> String {
    raw.replace('Z', " ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_military_us_space_and_z_mapping() {
        assert_eq!(plaintext_to_military_us(' '), Some(25));
        assert_eq!(plaintext_to_military_us('z'), Some(23));
        assert_eq!(plaintext_to_military_us('Z'), Some(23));
        assert_eq!(plaintext_to_military_us('a'), Some(0));
        assert_eq!(plaintext_to_military_us('A'), Some(0));
        assert_eq!(plaintext_to_military_us('y'), Some(24));
        assert_eq!(plaintext_to_military_us('Y'), Some(24));
        assert_eq!(plaintext_to_military_us('!'), None);

        assert_eq!(military_us_to_plaintext(25), Some(' '));
        assert_eq!(military_us_to_plaintext(23), Some('X'));
        assert_eq!(military_us_to_plaintext(0), Some('A'));
        assert_eq!(military_us_to_plaintext(24), Some('Y'));
        assert_eq!(military_us_to_plaintext(26), None);
    }

    #[test]
    fn test_ciphertext_to_military_us() {
        assert_eq!(ciphertext_to_military_us('A'), Ok(Some(0)));
        assert_eq!(ciphertext_to_military_us('z'), Ok(Some(25)));
        assert_eq!(ciphertext_to_military_us(' '), Ok(None));
        assert_eq!(ciphertext_to_military_us('\t'), Ok(None));
        assert_eq!(ciphertext_to_military_us('\n'), Ok(None));
        assert_eq!(ciphertext_to_military_us('1'), Err('1'));
    }

    #[test]
    fn test_format_five_letter_groups() {
        assert_eq!(format_five_letter_groups("ABCDE"), "ABCDE");
        assert_eq!(format_five_letter_groups("ABCDEF"), "ABCDE F");
        assert_eq!(format_five_letter_groups("ABCDEFGHIJKLMNO"), "ABCDE FGHIJ KLMNO");
        assert_eq!(format_five_letter_groups(""), "");
        assert_eq!(group_five("ABCDEFG"), "ABCDE FG");
    }

    #[test]
    fn test_prepare_tactical_plaintext() {
        assert_eq!(prepare_tactical_plaintext("ATTACK AT DAWN").unwrap(), "ATTACKZATZDAWN");
        assert_eq!(prepare_tactical_plaintext("Hi Z").unwrap(), "HIZZ");
        assert_eq!(prepare_tactical_plaintext("AB!").unwrap_err(), (2, '!'));
    }

    #[test]
    fn test_ungroup_ciphertext() {
        assert_eq!(ungroup_ciphertext("ABC DE\nFG").unwrap(), "ABCDEFG");
        assert_eq!(ungroup_ciphertext("abc def").unwrap(), "ABCDEF");
        assert_eq!(ungroup_ciphertext("AB-").unwrap_err(), (2, '-'));
    }

    #[test]
    fn test_display_tactical_plaintext() {
        assert_eq!(display_tactical_plaintext("THEZPIZZAZHASZARRIVED"), "THE PI  A HAS ARRIVED");
    }
}
