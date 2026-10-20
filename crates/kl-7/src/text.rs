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

pub use old_crypto_rs::helpers::format_five_letter_groups;
use old_crypto_rs::helpers::{military_us_to_plaintext, plaintext_to_military_us};

pub use crate::error::TextError;

use super::{
    contact::Contact26,
    machine::Kl7Core,
};

/// Convert a plaintext character into an electrical contact (`A=0..Z=25`).
pub fn plaintext_to_contact(ch: char) -> Result<Contact26, TextError> {
    plaintext_to_military_us(ch)
        .map(|idx| Contact26::new(idx).expect("valid 26-contact index"))
        .ok_or(TextError::UnsupportedPlaintext(ch))
}

/// Convert a deciphered contact (`A=0..Z=25`) into a human-readable character.
#[must_use]
pub fn contact_to_plaintext(contact: Contact26) -> char {
    military_us_to_plaintext(contact.get()).expect("valid 26-contact index")
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
