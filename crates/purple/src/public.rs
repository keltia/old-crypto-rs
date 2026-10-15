//! Reset-per-call public PURPLE facade and byte-buffer compatibility trait.

use old_crypto_rs::Block;
use crate::{AlphabetError, PurpleConfig, PurpleMachine};

/// Reusable PURPLE configuration. Each operation starts at the configured positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Purple {
    config: PurpleConfig,
}

impl Purple {
    pub const fn new(config: PurpleConfig) -> Self { Self { config } }
    pub const fn config(&self) -> &PurpleConfig { &self.config }
    pub fn initial_machine(&self) -> PurpleMachine { self.config.build_machine() }

    /// Encipher strict uppercase ASCII without punctuation normalization.
    pub fn encrypt_bytes(&self, input: &[u8]) -> Result<Vec<u8>, AlphabetError> {
        self.initial_machine().encipher_bytes(input)
    }

    /// Decipher strict uppercase ASCII without punctuation normalization.
    pub fn decrypt_bytes(&self, input: &[u8]) -> Result<Vec<u8>, AlphabetError> {
        self.initial_machine().decipher_bytes(input)
    }

    /// Encipher strict A-Z text. Unsupported characters are rejected, not dropped.
    pub fn encrypt_text(&self, input: &str) -> Result<String, AlphabetError> {
        Ok(String::from_utf8(self.encrypt_bytes(input.as_bytes())?)
            .expect("PURPLE produces only ASCII letters"))
    }

    /// Decipher strict A-Z text. Unsupported characters are rejected, not dropped.
    pub fn decrypt_text(&self, input: &str) -> Result<String, AlphabetError> {
        Ok(String::from_utf8(self.decrypt_bytes(input.as_bytes())?)
            .expect("PURPLE produces only ASCII letters"))
    }
}

impl From<PurpleConfig> for Purple {
    fn from(config: PurpleConfig) -> Self { Self::new(config) }
}

impl Block for Purple {
    fn block_size(&self) -> usize { 1 }

    /// Process at most min(src.len(), dst.len()) uppercase letters. Stops before
    /// an invalid byte, leaving the remainder of the destination untouched.
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        process_block(self.initial_machine(), dst, src, PurpleMachine::encipher)
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        process_block(self.initial_machine(), dst, src, PurpleMachine::decipher)
    }
}

fn process_block(mut machine: PurpleMachine, dst: &mut [u8], src: &[u8],
    transform: fn(&mut PurpleMachine, u8) -> Result<u8, AlphabetError>) -> usize {
    let mut written = 0;
    for (&byte, slot) in src.iter().zip(dst.iter_mut()) {
        match transform(&mut machine, byte) {
            Ok(result) => { *slot = result; written += 1; }
            Err(_) => break,
        }
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PurpleAlphabet, PurpleMotion, SwitchPosition};
    use crate::TwentiesSwitchId::{One, Two, Three};

    fn test_purple() -> Purple {
        let p = |n| SwitchPosition::new(n).unwrap();
        let config = PurpleConfig::new(
            PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap(),
            p(9), [p(1), p(24), p(6)], PurpleMotion::new(Two, Three, One).unwrap(),
        );
        Purple::new(config)
    }

    #[test]
    fn facade_matches_independent_python_vector_and_resets() {
        let purple = test_purple();
        let plaintext = "THEPURPLEMACHINEISNOWONLINE";
        let expected = "OGIVTSIAAHMWMHTVIBYYJUOJFUE";
        assert_eq!(purple.encrypt_text(plaintext).unwrap(), expected);
        assert_eq!(purple.encrypt_text(plaintext).unwrap(), expected);
        assert_eq!(purple.decrypt_text(expected).unwrap(), plaintext);
        assert_eq!(purple.initial_machine().state().sixes(), purple.config().sixes());
    }

    #[test]
    fn block_bounds_and_roundtrip() {
        let purple = test_purple();
        let src = b"THEPURPLE";
        let mut short = [0u8; 4];
        assert_eq!(purple.encrypt(&mut short, src), 4);
        assert_eq!(&short, &purple.encrypt_bytes(&src[..4]).unwrap());
        let mut recovered = [0u8; 4];
        assert_eq!(purple.decrypt(&mut recovered, &short), 4);
        assert_eq!(&recovered, &src[..4]);
        let mut empty = [];
        assert_eq!(purple.encrypt(&mut empty, src), 0);
    }

    #[test]
    fn invalid_characters_are_rejected_without_processing_suffix() {
        let purple = test_purple();
        assert_eq!(purple.encrypt_text("HELLO WORLD"),
            Err(AlphabetError::InvalidInputLetter { byte: b' ' }));
        assert_eq!(purple.decrypt_text("abc"),
            Err(AlphabetError::InvalidInputLetter { byte: b'a' }));
        let mut destination = [b'?'; 8];
        assert_eq!(purple.encrypt(&mut destination, b"AB!CDEFG"), 2);
        assert_eq!(&destination[..2], &purple.encrypt_bytes(b"AB").unwrap());
        assert_eq!(&destination[2..], b"??????");
    }
}
