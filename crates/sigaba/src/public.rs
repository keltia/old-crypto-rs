//! Public SIGABA facade.
//!
//! `Sigaba` stores only a validated immutable configuration.  Each high-level
//! operation constructs a fresh `SigabaCore`, matching the crate's historical
//! reset-per-call `Block` behavior while avoiding interior mutable legacy rotor
//! state.
//!
//! Prefer `encrypt_text` / `decrypt_text` for historically accurate CSP-889
//! text handling.  The `Block` implementation is a fixed-length compatibility
//! adapter.

use crate::Block;

use super::{
    config::SigabaConfig,
    contact::Contact26,
    text::{
        contact_to_plaintext, decipher_text, encipher_text, plaintext_to_contact,
        TextError,
    },
};

/// Validated CSP-889 SIGABA / ECM Mark II machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sigaba {
    config: SigabaConfig,
}

impl Sigaba {
    /// Construct a machine from a validated CSP-889 configuration.
    #[must_use]
    pub const fn new(config: SigabaConfig) -> Self {
        Self { config }
    }

    /// Return the immutable validated configuration.
    #[must_use]
    pub const fn config(&self) -> &SigabaConfig {
        &self.config
    }

    /// Historically accurate text encipherment.
    ///
    /// The machine is reset to the configured initial state for every call.
    ///
    /// Text rules include:
    ///
    /// - plaintext space -> electrical Z;
    /// - plaintext Z -> electrical X;
    /// - lowercase ASCII is normalized;
    /// - unsupported plaintext characters return `TextError`.
    pub fn encrypt_text(&self, src: &str) -> Result<String, TextError> {
        let mut core = self.config.build_core().map_err(TextError::from)?;
        encipher_text(&mut core, src)
    }

    /// Historically accurate text decipherment.
    ///
    /// The machine is reset to the configured initial state for every call.
    /// Ciphertext grouping whitespace is ignored without advancing the rotors.
    pub fn decrypt_text(&self, src: &str) -> Result<String, TextError> {
        let mut core = self.config.build_core().map_err(TextError::from)?;
        decipher_text(&mut core, src)
    }
}

impl From<SigabaConfig> for Sigaba {
    fn from(config: SigabaConfig) -> Self {
        Self::new(config)
    }
}

impl Block for Sigaba {
    /// SIGABA is a stream machine; the compatibility block size is one byte.
    fn block_size(&self) -> usize {
        1
    }

    /// Fixed-length compatibility encryption.
    ///
    /// Processing is bounded by `min(src.len(), dst.len())`.  ASCII letters
    /// and spaces use the historical text mapping. Unsupported bytes are
    /// copied unchanged and do not advance the machine.
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let n = src.len().min(dst.len());
        let Ok(mut core) = self.config.build_core() else {
            // A successfully constructed public SigabaConfig cannot currently
            // reach this branch because reference wirings are static and
            // validated. Preserve the Block contract without panicking.
            return 0;
        };

        for (&input, output) in src[..n].iter().zip(&mut dst[..n]) {
            let ch = char::from(input);

            match plaintext_to_contact(ch) {
                Ok(contact) => {
                    let encrypted = core.encipher_contact(contact);
                    *output = b'A' + encrypted.get();
                }
                Err(_) => {
                    *output = input;
                }
            }
        }

        n
    }

    /// Fixed-length compatibility decryption.
    ///
    /// Processing is bounded by `min(src.len(), dst.len())`. ASCII ciphertext
    /// letters are deciphered. Other bytes are copied unchanged and do not
    /// advance the machine, allowing grouping whitespace to remain present
    /// without affecting rotor state.
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let n = src.len().min(dst.len());
        let Ok(mut core) = self.config.build_core() else {
            return 0;
        };

        for (&input, output) in src[..n].iter().zip(&mut dst[..n]) {
            if input.is_ascii_alphabetic() {
                let normalized = input.to_ascii_uppercase();
                let contact = Contact26::new(normalized - b'A')
                    .expect("ASCII alphabetic input is a valid Contact26");
                let decrypted = core.decipher_contact(contact);
                *output = contact_to_plaintext(decrypted) as u8;
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
    use crate::{
        alphabet_rotor::Orientation,
        config::{IndexRotorSetting, LargeRotorSetting},
        contact::{Position10, Position26},
        data::{IndexRotorId, LargeRotorId, LargeRotorSet},
    };

    fn config() -> SigabaConfig {
        let large = |id: u8, position: u8| {
            LargeRotorSetting::new(
                LargeRotorId::new(id).unwrap(),
                Position26::new(position).unwrap(),
                Orientation::Normal,
            )
        };

        let index = |id: u8| {
            IndexRotorSetting::new(
                IndexRotorId::new(id).unwrap(),
                Position10::ZERO,
            )
        };

        SigabaConfig::new(
            LargeRotorSet::PekelneyReference,
            [
                large(0, 14),
                large(1, 14),
                large(2, 14),
                large(3, 14),
                large(4, 14),
            ],
            [
                large(5, 14),
                large(6, 14),
                large(7, 14),
                large(8, 14),
                large(9, 14),
            ],
            [index(0), index(1), index(2), index(3), index(4)],
        )
        .unwrap()
    }

    #[test]
    fn public_text_api_matches_independent_known_answer() {
        let machine = Sigaba::new(config());

        assert_eq!(
            machine.encrypt_text("HELLO WORLD").unwrap(),
            "FLQGFQUEQCH",
        );
        assert_eq!(
            machine.decrypt_text("FLQGF QUEQC H").unwrap(),
            "HELLO WORLD",
        );
    }

    #[test]
    fn block_adapter_matches_known_answer_without_grouping() {
        let machine = Sigaba::new(config());
        let mut ciphertext = [0_u8; 11];

        let written = machine.encrypt(&mut ciphertext, b"HELLO WORLD");

        assert_eq!(written, 11);
        assert_eq!(&ciphertext, b"FLQGFQUEQCH");

        let mut plaintext = [0_u8; 11];
        let written = machine.decrypt(&mut plaintext, &ciphertext);

        assert_eq!(written, 11);
        assert_eq!(&plaintext, b"HELLO WORLD");
    }

    #[test]
    fn block_encrypt_is_bounded_by_short_destination() {
        let machine = Sigaba::new(config());
        let mut dst = [0_u8; 5];

        let written = machine.encrypt(&mut dst, b"HELLO WORLD");

        assert_eq!(written, 5);

        let mut reference = [0_u8; 5];
        let reference_written = machine.encrypt(&mut reference, b"HELLO");
        assert_eq!(reference_written, 5);
        assert_eq!(dst, reference);
    }

    #[test]
    fn block_decrypt_is_bounded_by_short_destination() {
        let machine = Sigaba::new(config());
        let mut dst = [0_u8; 5];

        let written = machine.decrypt(&mut dst, b"FLQGFQUEQCH");

        assert_eq!(written, 5);
        assert_eq!(&dst, b"HELLO");
    }

    #[test]
    fn block_adapter_is_bounded_by_short_source() {
        let machine = Sigaba::new(config());
        let mut dst = [b'?'; 16];

        let written = machine.encrypt(&mut dst, b"HELLO");

        assert_eq!(written, 5);
        assert_eq!(&dst[5..], &[b'?'; 11]);
    }

    #[test]
    fn unsupported_block_bytes_pass_through_without_stepping() {
        let machine = Sigaba::new(config());

        let mut with_separator = [0_u8; 11];
        machine.encrypt(&mut with_separator, b"HELLO-WORLD");

        let mut left = [0_u8; 5];
        machine.encrypt(&mut left, b"HELLO");

        assert_eq!(&with_separator[..5], &left);
        assert_eq!(with_separator[5], b'-');

        // The unsupported '-' does not advance state, so WORLD begins at the
        // same state as it would immediately after HELLO.
        let mut compact = [0_u8; 10];
        machine.encrypt(&mut compact, b"HELLOWORLD");
        assert_eq!(&with_separator[6..], &compact[5..]);
    }

    #[test]
    fn every_block_call_resets_to_configured_initial_state() {
        let machine = Sigaba::new(config());
        let mut first = [0_u8; 5];
        let mut second = [0_u8; 5];

        machine.encrypt(&mut first, b"HELLO");
        machine.encrypt(&mut second, b"HELLO");

        assert_eq!(first, second);
    }
}
