//! Text formatting, normalization, and letter/figure shift handling for TSEC/KL-7.
//!
//! # Historical Text Conventions
//! - Encipher:
//!   - Plaintext space (`' '`) is mapped to electrical letter `'Z'`.
//!   - Plaintext `'Z'` is mapped to electrical letter `'X'`.
//!   - Lowercase ASCII letters are converted to uppercase.
//!   - Other punctuation marks must be spelled out or ignored.
//! - Decipher:
//!   - Electrical letter `'Z'` is printed as a space (`' '`).
//!   - All other letters `'A'..='Y'` are printed as themselves.
//!   - Grouping whitespace (spaces, tabs, newlines) in ciphertext is presentation only
//!     and does not advance the machine state.
//! - Output Formatting:
//!   - Standard military format groups ciphertext in 5-letter blocks.

use super::{
    contact::Contact26,
    machine::Kl7Core,
    maze::MazeError,
};
use core::fmt;

/// Error returned by the KL-7 text processing layer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TextError {
    /// Plaintext contained an unsupported character.
    UnsupportedPlaintext(char),
    /// Ciphertext contained an invalid character.
    UnsupportedCiphertext(char),
    /// An electrical conduction error occurred in the re-entry maze.
    Maze(MazeError),
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlaintext(c) => {
                write!(f, "character '{c}' is not supported in KL-7 plaintext")
            }
            Self::UnsupportedCiphertext(c) => {
                write!(f, "character '{c}' is not valid KL-7 ciphertext")
            }
            Self::Maze(e) => write!(f, "re-entry maze error: {e}"),
        }
    }
}

impl std::error::Error for TextError {}

impl From<MazeError> for TextError {
    fn from(e: MazeError) -> Self {
        Self::Maze(e)
    }
}

/// Convert a plaintext character into an electrical contact (`A=0..Z=25`).
pub fn plaintext_to_contact(ch: char) -> Result<Contact26, TextError> {
    match ch {
        ' ' => Ok(Contact26::new(b'Z' - b'A').unwrap()),
        'z' | 'Z' => Ok(Contact26::new(b'X' - b'A').unwrap()),
        'a'..='y' => Ok(Contact26::from_ascii_letter(ch).unwrap()),
        'A'..='Y' => Ok(Contact26::from_ascii_letter(ch).unwrap()),
        _ => Err(TextError::UnsupportedPlaintext(ch)),
    }
}

/// Convert a deciphered contact (`A=0..Z=25`) into a human-readable character.
#[must_use]
pub fn contact_to_plaintext(contact: Contact26) -> char {
    if contact.get() == b'Z' - b'A' {
        ' '
    } else {
        contact.to_ascii_char()
    }
}

/// Format a continuous stream of ciphertext letters into standard 5-letter groups.
#[must_use]
pub fn format_five_letter_groups(ciphertext: &str) -> String {
    let mut result = String::with_capacity(ciphertext.len() + ciphertext.len() / 5);
    let mut count = 0;

    for ch in ciphertext.chars() {
        if ch.is_ascii_alphabetic() {
            if count > 0 && count % 5 == 0 {
                result.push(' ');
            }
            result.push(ch.to_ascii_uppercase());
            count += 1;
        }
    }

    result
}

/// Encipher human-readable plaintext with the given core into formatted 5-letter groups.
pub fn encipher_text_with(core: &mut Kl7Core, src: &str) -> Result<String, TextError> {
    let mut raw_cipher = String::with_capacity(src.len());

    for ch in src.chars() {
        let contact = plaintext_to_contact(ch)?;
        let enc = core.encipher_contact(contact).map_err(TextError::Maze)?;
        raw_cipher.push(enc.to_ascii_char());
    }

    Ok(format_five_letter_groups(&raw_cipher))
}

/// Decipher formatted ciphertext with the given core back into human plaintext.
pub fn decipher_text_with(core: &mut Kl7Core, src: &str) -> Result<String, TextError> {
    let mut output = String::with_capacity(src.len());

    for ch in src.chars() {
        if ch.is_whitespace() {
            // Grouping whitespace is presentation only; ignore without advancing machine
            continue;
        }

        if let Some(contact) = Contact26::from_ascii_letter(ch) {
            let dec = core.decipher_contact(contact).map_err(TextError::Maze)?;
            output.push(contact_to_plaintext(dec));
        } else {
            return Err(TextError::UnsupportedCiphertext(ch));
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Kl7Config;

    #[test]
    fn five_letter_grouping_formatting() {
        assert_eq!(format_five_letter_groups("ABCDE"), "ABCDE");
        assert_eq!(format_five_letter_groups("ABCDEF"), "ABCDE F");
        assert_eq!(format_five_letter_groups("ABCDEFGHIJKLMNO"), "ABCDE FGHIJ KLMNO");
    }

    #[test]
    fn space_and_z_mapping_round_trip() {
        let config = Kl7Config::uss_beagle();
        let mut enc_core = config.build_core();
        let mut dec_core = config.build_core();

        let plaintext = "ATTACK AT DAWN";
        let ciphertext = encipher_text_with(&mut enc_core, plaintext).unwrap();
        let decrypted = decipher_text_with(&mut dec_core, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
