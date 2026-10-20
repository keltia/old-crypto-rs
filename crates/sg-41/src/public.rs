//! Byte-oriented SG-41 facade implementing the shared `Block` trait.
//!
//! Each call starts from the configuration's initial wheel settings. For
//! continuous character-by-character operation, use [`super::core::Sg41Core`].

use old_crypto_rs::Block;

use super::config::Sg41Config;

/// Reusable block adapter for the alphabetic SG-41.
///
/// ASCII letters are normalized to uppercase before conversion. Nonletters
/// are copied unchanged and do not advance the wheels. Text preparation and
/// historical message formatting belong to separate, higher-level layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SG41 {
    config: Sg41Config,
}

impl SG41 {
    pub const fn new(config: Sg41Config) -> Self {
        Self { config }
    }

    pub const fn config(&self) -> &Sg41Config {
        &self.config
    }

    /// Transform only the bytes that fit in both slices, starting at the
    /// configured initial state on every call.
    fn process(&self, dst: &mut [u8], src: &[u8], encrypt: bool) -> usize {
        let length = src.len().min(dst.len());
        let mut core = self.config.build_core();

        for (output, &input) in dst[..length].iter_mut().zip(&src[..length]) {
            if input.is_ascii_alphabetic() {
                let letter = input.to_ascii_uppercase() as char;
                let cycle = if encrypt {
                    core.encipher_char(letter)
                } else {
                    core.decipher_char(letter)
                }
                .expect("ASCII letter is valid SG-41 input");

                *output = cycle.output as u8;
            } else {
                *output = input;
            }
        }

        length
    }
}

impl Block for SG41 {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.process(dst, src, true)
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.process(dst, src, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WHEEL_COUNT, WindowLabel};

    const PINS: [&str; WHEEL_COUNT] = [
        "0001101011000100010001101",
        "0110100100001011100101100",
        "11001001000100100100010",
        "01001000111010001110010",
        "001001001010000101011010",
        "011001100110001011010100",
    ];

    fn reference_machine() -> SG41 {
        let windows = [
            WindowLabel::Letter('A'),
            WindowLabel::Letter('B'),
            WindowLabel::Letter('C'),
            WindowLabel::Letter('D'),
            WindowLabel::Number(1),
            WindowLabel::Number(0),
        ];

        SG41::new(Sg41Config::from_key_settings(windows, PINS).unwrap())
    }

    #[test]
    fn historical_known_answer_through_shared_block() {
        let machine = reference_machine();
        let plaintext = b"SCHLUESSELGERAETVIEREINSWANDERER";
        let ciphertext = b"IHEPLRETQSDSNDCWHPIVVGLYMHOWSJQS";
        let mut output = [0; 32];

        assert_eq!(machine.block_size(), 1);
        assert_eq!(machine.encrypt(&mut output, plaintext), plaintext.len());
        assert_eq!(&output, ciphertext);

        assert_eq!(machine.decrypt(&mut output, ciphertext), ciphertext.len());
        assert_eq!(&output, plaintext);
    }

    #[test]
    fn every_call_resets_to_initial_configuration() {
        let machine = reference_machine();
        let mut first = [0; 32];
        let mut second = [0; 32];

        machine.encrypt(&mut first, b"SCHLUESSELGERAETVIEREINSWANDERER");
        machine.encrypt(&mut second, b"SCHLUESSELGERAETVIEREINSWANDERER");

        assert_eq!(first, second);
    }

    #[test]
    fn short_destinations_do_not_process_extra_letters() {
        let machine = reference_machine();
        let mut output = [0; 4];

        assert_eq!(machine.encrypt(&mut output, b"SCHLUESSEL"), 4);
        assert_eq!(&output, b"IHEP");

        let mut destination = [b'!'; 6];
        assert_eq!(machine.decrypt(&mut destination, b"IH"), 2);
        assert_eq!(&destination, b"SC!!!!");
    }

    #[test]
    fn nonletters_are_passed_through_without_stepping() {
        let machine = reference_machine();
        let mut output = [0; 8];

        assert_eq!(machine.encrypt(&mut output, b"s!c h?l."), 8);
        assert_eq!(&output, b"I!H E?P.");

        let mut decoded = [0; 8];
        assert_eq!(machine.decrypt(&mut decoded, &output), 8);
        assert_eq!(&decoded, b"S!C H?L.");
    }

    #[test]
    fn empty_buffers_leave_destinations_unchanged() {
        let machine = reference_machine();
        let mut untouched = [b'!'; 3];

        assert_eq!(machine.encrypt(&mut untouched, b""), 0);
        assert_eq!(untouched, [b'!'; 3]);
        assert_eq!(machine.decrypt(&mut [], b"ANY"), 0);
    }
}
