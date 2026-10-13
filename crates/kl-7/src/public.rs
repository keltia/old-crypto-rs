//! Public TSEC/KL-7 facade.
//!
//! `Kl7` stores a validated immutable configuration and a fully constructed initial `Kl7Core`.
//! Each operation copies that initial state, preserving reset-per-call behavior.

use super::{
    config::Kl7Config,
    contact::Contact26,
    machine::Kl7Core,
    maze::MazeError,
    text::{decipher_text_with, encipher_text_with, TextError},
};
use core::fmt;

/// Block trait adapter for block-oriented cipher consumers.
pub trait Block {
    fn block_size(&self) -> usize;
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize;
}

/// Error type returned by KL-7 public encryption/decryption operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kl7Error {
    /// An electrical conduction error occurred in the re-entry maze.
    Maze(MazeError),
    /// An unsupported or invalid character was encountered.
    InvalidCharacter(char),
    /// A text layer formatting or validation error occurred.
    Text(TextError),
}

impl fmt::Display for Kl7Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Maze(e) => write!(f, "maze error: {e}"),
            Self::InvalidCharacter(c) => write!(f, "invalid character: '{c}'"),
            Self::Text(e) => write!(f, "text error: {e}"),
        }
    }
}

impl std::error::Error for Kl7Error {}

impl From<MazeError> for Kl7Error {
    fn from(e: MazeError) -> Self {
        Self::Maze(e)
    }
}

impl From<TextError> for Kl7Error {
    fn from(e: TextError) -> Self {
        Self::Text(e)
    }
}

/// Validated TSEC/KL-7 (ADONIS / POLLUX) cipher machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kl7 {
    config: Kl7Config,
    initial: Kl7Core,
}

impl Kl7 {
    /// Construct a new machine from a validated configuration.
    #[must_use]
    pub fn new(config: Kl7Config) -> Self {
        let initial = config.build_core();
        Self { config, initial }
    }

    /// Return the immutable configuration.
    #[must_use]
    pub const fn config(&self) -> &Kl7Config {
        &self.config
    }

    /// Return a clone of the initial runtime core.
    #[must_use]
    pub fn initial_core(&self) -> Kl7Core {
        self.initial.clone()
    }

    /// Standard historical text encipherment.
    ///
    /// Resets the machine to initial state, converts plaintext (with spaces mapped to Z),
    /// and formats the ciphertext in standard 5-letter groups.
    pub fn encrypt_text(&self, src: &str) -> Result<String, Kl7Error> {
        let mut core = self.initial.clone();
        encipher_text_with(&mut core, src).map_err(Kl7Error::from)
    }

    /// Standard historical text decipherment.
    ///
    /// Resets the machine to initial state, ignores ciphertext grouping whitespace,
    /// and converts electrical Z back into spaces.
    pub fn decrypt_text(&self, src: &str) -> Result<String, Kl7Error> {
        let mut core = self.initial.clone();
        decipher_text_with(&mut core, src).map_err(Kl7Error::from)
    }

    /// Encrypt text directly (converting ASCII letters A-Z and ignoring non-letters / spaces).
    ///
    /// The machine is reset to the initial configured state for each call.
    pub fn encrypt_letters_only(&self, src: &str) -> Result<String, Kl7Error> {
        let mut core = self.initial.clone();
        let mut output = String::with_capacity(src.len());

        for ch in src.chars() {
            if let Some(contact) = Contact26::from_ascii_letter(ch) {
                let enc = core.encipher_contact(contact)?;
                output.push(enc.to_ascii_char());
            }
        }

        Ok(output)
    }

    /// Decrypt text directly (converting ASCII ciphertext letters A-Z).
    ///
    /// The machine is reset to the initial configured state for each call.
    pub fn decrypt_letters_only(&self, src: &str) -> Result<String, Kl7Error> {
        let mut core = self.initial.clone();
        let mut output = String::with_capacity(src.len());

        for ch in src.chars() {
            if let Some(contact) = Contact26::from_ascii_letter(ch) {
                let dec = core.decipher_contact(contact)?;
                output.push(dec.to_ascii_char());
            }
        }

        Ok(output)
    }
}

impl From<Kl7Config> for Kl7 {
    fn from(config: Kl7Config) -> Self {
        Self::new(config)
    }
}

impl Block for Kl7 {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let n = src.len().min(dst.len());
        let mut core = self.initial.clone();

        for (&input, output) in src[..n].iter().zip(&mut dst[..n]) {
            let ch = char::from(input);
            if let Some(contact) = Contact26::from_ascii_letter(ch) {
                if let Ok(encrypted) = core.encipher_contact(contact) {
                    *output = encrypted.to_ascii_char() as u8;
                } else {
                    *output = input;
                }
            } else {
                *output = input;
            }
        }

        n
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let n = src.len().min(dst.len());
        let mut core = self.initial.clone();

        for (&input, output) in src[..n].iter().zip(&mut dst[..n]) {
            let ch = char::from(input);
            if let Some(contact) = Contact26::from_ascii_letter(ch) {
                if let Ok(decrypted) = core.decipher_contact(contact) {
                    *output = decrypted.to_ascii_char() as u8;
                } else {
                    *output = input;
                }
            } else {
                *output = input;
            }
        }

        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uss_beagle_public_facade_round_trip() {
        let kl7 = Kl7::new(Kl7Config::uss_beagle());
        let plaintext = "TOPSECRETOPERATIONCOMMENCINGATMIDNIGHT";
        let ciphertext = kl7.encrypt_letters_only(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = kl7.decrypt_letters_only(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn block_trait_adapter_matches_direct_letter_methods() {
        let kl7 = Kl7::new(Kl7Config::uss_beagle());
        let plain = b"TOPSECRET";
        let mut cipher = [0u8; 9];
        let mut dec = [0u8; 9];

        let count = kl7.encrypt(&mut cipher, plain);
        assert_eq!(count, 9);

        let direct_cipher = kl7.encrypt_letters_only("TOPSECRET").unwrap();
        assert_eq!(cipher, direct_cipher.as_bytes());

        let count_dec = kl7.decrypt(&mut dec, &cipher);
        assert_eq!(count_dec, 9);
        assert_eq!(&dec, plain);
    }
}
