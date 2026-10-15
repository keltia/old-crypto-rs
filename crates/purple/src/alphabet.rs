//! The configurable external alphabet (plugboard) of the PURPLE machine.
//!
//! A key alphabet contains 26 distinct uppercase ASCII letters. Its first six
//! slots lead to the sixes switch; its remaining twenty slots lead to the
//! twenties switch bank. All indices within either bank are zero-based.

use core::fmt;

use crate::{SixesContact, TwentiesContact};

/// A contact in one of PURPLE's two disjoint electrical branches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlphabetContact {
    Sixes(SixesContact),
    Twenties(TwentiesContact),
}

/// Error encountered when validating a PURPLE alphabet or external letter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlphabetError {
    InvalidLength { actual: usize },
    InvalidLetter { index: usize, byte: u8 },
    DuplicateLetter { byte: u8 },
    InvalidInputLetter { byte: u8 },
}

impl fmt::Display for AlphabetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidLength { actual } => write!(f, "alphabet must have 26 bytes, got {actual}"),
            Self::InvalidLetter { index, byte } => write!(f, "invalid alphabet byte {byte} at index {index}"),
            Self::DuplicateLetter { byte } => write!(f, "duplicate alphabet letter {}", char::from(byte)),
            Self::InvalidInputLetter { byte } => write!(f, "input byte {byte} is not an uppercase ASCII letter"),
        }
    }
}

impl std::error::Error for AlphabetError {}

/// A validated daily alphabet, expressed in contact order (6 + 20).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PurpleAlphabet {
    letters: [u8; 26],
    /// For each ASCII letter A..Z, its index in `letters`.
    slots: [u8; 26],
}

impl PurpleAlphabet {
    /// Common reference/default setting; not an historical daily key.
    pub const DEFAULT: &'static str = "AEIOUYBCDFGHJKLMNPQRSTVWXZ";

    /// Construct from precisely 26 unique ASCII uppercase letters.
    pub fn new(value: &str) -> Result<Self, AlphabetError> {
        let bytes = value.as_bytes();
        if bytes.len() != 26 {
            return Err(AlphabetError::InvalidLength { actual: bytes.len() });
        }
        let mut letters = [0u8; 26];
        let mut slots = [0u8; 26];
        let mut seen = [false; 26];
        for (i, &byte) in bytes.iter().enumerate() {
            if !byte.is_ascii_uppercase() {
                return Err(AlphabetError::InvalidLetter { index: i, byte });
            }
            let letter = usize::from(byte - b'A');
            if seen[letter] {
                return Err(AlphabetError::DuplicateLetter { byte });
            }
            seen[letter] = true;
            letters[i] = byte;
            slots[letter] = i as u8;
        }
        Ok(Self { letters, slots })
    }

    /// Return the daily alphabet in contact order.
    pub const fn letters(&self) -> &[u8; 26] {
        &self.letters
    }

    /// Map an external letter to its bank and zero-based contact.
    pub fn contact(&self, letter: u8) -> Result<AlphabetContact, AlphabetError> {
        if !letter.is_ascii_uppercase() {
            return Err(AlphabetError::InvalidInputLetter { byte: letter });
        }
        let slot = self.slots[usize::from(letter - b'A')];
        if slot < 6 {
            Ok(AlphabetContact::Sixes(SixesContact::new(slot).expect("validated sixes slot")))
        } else {
            Ok(AlphabetContact::Twenties(TwentiesContact::new(slot - 6).expect("validated twenties slot")))
        }
    }

    /// Map a valid electrical contact back to an external uppercase letter.
    pub fn letter(&self, contact: AlphabetContact) -> u8 {
        match contact {
            AlphabetContact::Sixes(c) => self.letters[usize::from(c.index())],
            AlphabetContact::Twenties(c) => self.letters[6 + usize::from(c.index())],
        }
    }
}

impl Default for PurpleAlphabet {
    fn default() -> Self {
        Self::new(Self::DEFAULT).expect("static default alphabet is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_split() {
        let a = PurpleAlphabet::default();
        assert_eq!(a.letters(), b"AEIOUYBCDFGHJKLMNPQRSTVWXZ");
        assert_eq!(a.contact(b'A').unwrap(), AlphabetContact::Sixes(SixesContact::new(0).unwrap()));
        assert_eq!(a.contact(b'Y').unwrap(), AlphabetContact::Sixes(SixesContact::new(5).unwrap()));
        assert_eq!(a.contact(b'B').unwrap(), AlphabetContact::Twenties(TwentiesContact::new(0).unwrap()));
        assert_eq!(a.contact(b'Z').unwrap(), AlphabetContact::Twenties(TwentiesContact::new(19).unwrap()));
    }

    #[test]
    fn historical_alphabet_round_trip_every_letter() {
        let a = PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap();
        for letter in b'A'..=b'Z' {
            assert_eq!(a.letter(a.contact(letter).unwrap()), letter);
        }
        assert_eq!(a.contact(b'N').unwrap(), AlphabetContact::Sixes(SixesContact::new(0).unwrap()));
        assert_eq!(a.contact(b'F').unwrap(), AlphabetContact::Twenties(TwentiesContact::new(19).unwrap()));
    }

    #[test]
    fn every_contact_round_trips() {
        let a = PurpleAlphabet::new("ZYXWVUTSRQPONMLKJIHGFEDCBA").unwrap();
        for i in 0..6 {
            let c = AlphabetContact::Sixes(SixesContact::new(i).unwrap());
            assert_eq!(a.contact(a.letter(c)), Ok(c));
        }
        for i in 0..20 {
            let c = AlphabetContact::Twenties(TwentiesContact::new(i).unwrap());
            assert_eq!(a.contact(a.letter(c)), Ok(c));
        }
    }

    #[test]
    fn invalid_alphabets() {
        assert_eq!(PurpleAlphabet::new("ABC").unwrap_err(), AlphabetError::InvalidLength { actual: 3 });
        assert_eq!(PurpleAlphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXYA").unwrap_err(), AlphabetError::DuplicateLetter { byte: b'A' });
        assert_eq!(PurpleAlphabet::new("ABCDEFGHIJKLMNOPQRSTUVWXY!").unwrap_err(), AlphabetError::InvalidLetter { index: 25, byte: b'!' });
        assert_eq!(PurpleAlphabet::new("abcdefghijklmnopqrstuvwx yz").unwrap_err(), AlphabetError::InvalidLength { actual: 27 });
    }

    #[test]
    fn invalid_external_letters() {
        let a = PurpleAlphabet::default();
        for byte in [b'a', b' ', b'0', 0, 255] {
            assert_eq!(a.contact(byte), Err(AlphabetError::InvalidInputLetter { byte }));
        }
    }
}
