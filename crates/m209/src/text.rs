//! Historical M-209 text conventions, separate from raw contact conversion.
//!
//! The M-209 accepts letters only. Operators represent word spaces as `Z`;
//! a genuine `Z` is therefore indistinguishable from a space upon display.
//! Five-letter grouping is presentation-only and does not step the machine.
//! This module does not construct message indicators or remove padding.

use old_crypto_rs::helpers::output_as_block;
use thiserror::Error;

use crate::{Contact, M209Config};

/// Errors in text prepared for the M-209 alphabet.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    #[error("invalid plaintext character {character:?} at character index {index}")]
    InvalidPlaintext { index: usize, character: char },

    #[error("invalid ciphertext character {character:?} at character index {index}")]
    InvalidCiphertext { index: usize, character: char },
}

/// Interpret spaces as `Z`, and normalize ASCII letters to uppercase.
///
/// This transformation is lossy when displayed as words after decipherment:
/// genuine `Z` letters cannot be distinguished from encoded spaces.
pub fn prepare_plaintext(plaintext: &str) -> Result<String, TextError> {
    let mut prepared = String::with_capacity(plaintext.len());

    for (index, character) in plaintext.chars().enumerate() {
        match character {
            ' ' => prepared.push('Z'),
            'A'..='Z' => prepared.push(character),
            'a'..='z' => prepared.push(character.to_ascii_uppercase()),
            _ => return Err(TextError::InvalidPlaintext { index, character }),
        }
    }

    Ok(prepared)
}

/// Remove ASCII whitespace used solely to group ciphertext.
///
/// Invalid characters are rejected rather than silently passed through.
pub fn ungroup_ciphertext(ciphertext: &str) -> Result<String, TextError> {
    let mut ungrouped = String::with_capacity(ciphertext.len());

    for (index, character) in ciphertext.chars().enumerate() {
        match character {
            'A'..='Z' => ungrouped.push(character),
            'a'..='z' => ungrouped.push(character.to_ascii_uppercase()),
            c if c.is_ascii_whitespace() => {}
            _ => return Err(TextError::InvalidCiphertext { index, character }),
        }
    }

    Ok(ungrouped)
}

/// Group the supplied *already normalized* letters, without padding them.
pub fn group_five(letters: &str) -> String {
    output_as_block(letters)
}

/// Replace every raw `Z` with a word space for historical presentation.
///
/// This does **not** recover literal `Z` letters; use `decrypt_text_raw`
/// when lossless raw-machine text is required.
pub fn display_plaintext(raw: &str) -> String {
    raw.replace('Z', " ")
}

/// Encipher a text message from the configuration's initial wheel positions.
///
/// This performs space substitution and optional grouping, but **not** Army
/// indicator construction, padding, or message framing.
pub fn encrypt_text(
    config: &M209Config,
    plaintext: &str,
    grouped: bool,
) -> Result<String, TextError> {
    let prepared = prepare_plaintext(plaintext)?;
    let mut machine = config.build_machine();
    let mut ciphertext = String::with_capacity(prepared.len());

    for character in prepared.bytes() {
        let contact = Contact::new(character - b'A').expect("normalized ASCII letter");
        ciphertext.push(machine.convert_contact(contact).letter());
    }

    Ok(if grouped { group_five(&ciphertext) } else { ciphertext })
}

/// Decipher ciphertext to **raw** A–Z contacts, retaining literal `Z` values.
///
/// Grouping whitespace is ignored and never advances the wheels.
pub fn decrypt_text_raw(config: &M209Config, ciphertext: &str) -> Result<String, TextError> {
    let ungrouped = ungroup_ciphertext(ciphertext)?;
    let mut machine = config.build_machine();
    let mut plaintext = String::with_capacity(ungrouped.len());

    for character in ungrouped.bytes() {
        let contact = Contact::new(character - b'A').expect("normalized ASCII letter");
        plaintext.push(machine.convert_contact(contact).letter());
    }

    Ok(plaintext)
}

/// Decipher using the historical convention of displaying `Z` as a space.
pub fn decrypt_text(config: &M209Config, ciphertext: &str) -> Result<String, TextError> {
    decrypt_text_raw(config, ciphertext).map(|raw| display_plaintext(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{
        PYTHON_REFERENCE_CIPHERTEXT, PYTHON_REFERENCE_PINS, PYTHON_REFERENCE_PLAINTEXT,
        PYTHON_REFERENCE_START, python_reference_drum,
    };

    fn reference_config() -> M209Config {
        M209Config::from_letters(
            PYTHON_REFERENCE_PINS,
            PYTHON_REFERENCE_START,
            python_reference_drum(),
        )
        .unwrap()
    }

    #[test]
    fn python_example_matches_grouped_ciphertext() {
        let config = reference_config();
        assert_eq!(
            encrypt_text(&config, PYTHON_REFERENCE_PLAINTEXT, true).unwrap(),
            PYTHON_REFERENCE_CIPHERTEXT
        );
        assert_eq!(
            encrypt_text(&config, PYTHON_REFERENCE_PLAINTEXT, false).unwrap(),
            "QBCHUWCCDIYFNCHLOZJYG"
        );
    }

    #[test]
    fn raw_and_historical_decoding_have_explicitly_different_semantics() {
        let config = reference_config();
        assert_eq!(
            decrypt_text_raw(&config, PYTHON_REFERENCE_CIPHERTEXT).unwrap(),
            "THEZPIZZAZHASZARRIVED"
        );
        assert_eq!(
            decrypt_text(&config, PYTHON_REFERENCE_CIPHERTEXT).unwrap(),
            "THE PI  A HAS ARRIVED"
        );
    }

    #[test]
    fn grouping_does_not_pad_or_add_machine_operations() {
        assert_eq!(group_five("ABCDEFG"), "ABCDE FG");
        assert_eq!(group_five("ABCDEFGHIJ"), output_as_block("ABCDEFGHIJ"));
        assert_eq!(group_five(""), "");
        assert_eq!(ungroup_ciphertext("ABC DE\nFG").unwrap(), "ABCDEFG");
        assert_eq!(prepare_plaintext("Hi Z").unwrap(), "HIZZ");
    }

    #[test]
    fn invalid_inputs_are_rejected_without_silent_passthrough() {
        assert_eq!(
            prepare_plaintext("AB!").unwrap_err(),
            TextError::InvalidPlaintext { index: 2, character: '!' }
        );
        assert_eq!(
            ungroup_ciphertext("AB-").unwrap_err(),
            TextError::InvalidCiphertext { index: 2, character: '-' }
        );
    }
}
