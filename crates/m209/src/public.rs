//! Byte-oriented M-209 facade implementing the shared workspace `Block` trait.
//!
//! Each block invocation starts from the configured initial key. For continuous
//! streams, use `M209Machine` directly instead.

use old_crypto_rs::Block;

use crate::{Contact, M209Config};

/// M-209 cipher adapter for the canonical workspace `Block` interface.
///
/// ASCII letters are converted through the machine's 26-contact alphabet.
/// Lowercase ASCII is normalized to uppercase. Unsupported bytes are copied
/// unchanged and do not cause the machine's wheels to advance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct M209 {
    config: M209Config,
}

impl M209 {
    /// Retain the validated key and initial wheel indicators.
    pub const fn new(config: M209Config) -> Self {
        Self { config }
    }

    /// Inspect the immutable starting key used by every block call.
    pub const fn config(&self) -> &M209Config {
        &self.config
    }

    /// Convert at most `min(src.len(), dst.len())` bytes from the initial key.
    ///
    /// The historic M-209 transformation is reciprocal, so encryption and
    /// decryption share this implementation. No implicit space-to-Z mapping,
    /// padding, or five-letter grouping is applied here.
    fn process(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let length = src.len().min(dst.len());
        let mut machine = self.config.build_machine();

        for (output, &input) in dst[..length].iter_mut().zip(&src[..length]) {
            if input.is_ascii_alphabetic() {
                // ASCII letters are guaranteed to be in the Contact range.
                let index = input.to_ascii_uppercase() - b'A';
                let contact = Contact::new(index).expect("validated ASCII contact");
                *output = machine.convert_contact(contact).letter() as u8;
            } else {
                *output = input;
            }
        }

        length
    }
}

impl Block for M209 {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.process(dst, src)
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.process(dst, src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{MANUAL_1944_CHECK, MANUAL_1944_PINS, manual_1944_drum};

    fn sample_cipher() -> M209 {
        let config = M209Config::from_letters(
            MANUAL_1944_PINS,
            "AAAAAA",
            manual_1944_drum(),
        )
        .expect("valid historical configuration");

        M209::new(config)
    }

    #[test]
    fn historical_known_answer_through_shared_block() {
        let cipher = sample_cipher();
        let plaintext = [b'A'; 26];
        let mut ciphertext = [0; 26];

        assert_eq!(cipher.block_size(), 1);
        assert_eq!(cipher.encrypt(&mut ciphertext, &plaintext), 26);
        assert_eq!(&ciphertext, MANUAL_1944_CHECK.as_bytes());

        let mut decoded = [0; 26];
        assert_eq!(cipher.decrypt(&mut decoded, &ciphertext), 26);
        assert_eq!(decoded, plaintext);
    }

    #[test]
    fn each_call_resets_to_the_initial_key() {
        let cipher = sample_cipher();
        let mut first = [0; 26];
        let mut second = [0; 26];

        cipher.encrypt(&mut first, &[b'A'; 26]);
        cipher.encrypt(&mut second, &[b'A'; 26]);

        assert_eq!(first, second);
        assert_eq!(&first, MANUAL_1944_CHECK.as_bytes());
    }

    #[test]
    fn output_is_bounded_by_the_shorter_slice() {
        let cipher = sample_cipher();
        let mut short = [0; 3];
        assert_eq!(cipher.encrypt(&mut short, b"AAAAA"), 3);
        assert_eq!(&short, &MANUAL_1944_CHECK.as_bytes()[..3]);

        let mut long = [b'!'; 6];
        assert_eq!(cipher.decrypt(&mut long, b"T"), 1);
        assert_eq!(long, [b'A', b'!', b'!', b'!', b'!', b'!']);

        assert_eq!(cipher.encrypt(&mut [], b"ABC"), 0);
    }

    #[test]
    fn passthrough_bytes_do_not_advance_the_wheels() {
        let cipher = sample_cipher();
        let mut output = [0; 8];
        let length = cipher.encrypt(&mut output, b"a !\nA\xffA");

        assert_eq!(length, 7);
        assert_eq!(output[0], b'T');
        assert_eq!(&output[1..4], b" !\n");
        assert_eq!(output[5], 0xff);
        assert_eq!(output[7], 0);

        // Compare the valid letters against a contiguous machine run: the
        // intervening unsupported bytes must not advance the pin wheels.
        let mut compact = [0; 3];
        cipher.encrypt(&mut compact, b"AAA");
        assert_eq!([output[0], output[4], output[6]], compact);
    }
}
