//! Historical SG-41 message-indicator masking and recovery.
//!
//! The disguise key is a *daily* key, distinct from the mechanical SG-41 key.
//! All character indexing is ASCII A-Z; shifts in the disguise table wrap at 26.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MessageError {
    #[error("invalid {field} letter at position {index}: {value:?}; expected A-Z")]
    InvalidLetter {
        field: &'static str,
        index: usize,
        value: u8,
    },

    #[error("disguise alphabet contains duplicate letter {0:?}")]
    DuplicateLetter(char),

    #[error("invalid disguise digit at position {index}: {value}; expected 1-9")]
    InvalidDigit { index: usize, value: u8 },

    #[error("message indicator redundancy check failed")]
    IndicatorCheckFailed,
}

fn validate_letters<const N: usize>(
    letters: &[u8; N],
    field: &'static str,
) -> Result<(), MessageError> {
    for (index, &value) in letters.iter().enumerate() {
        if !value.is_ascii_uppercase() {
            return Err(MessageError::InvalidLetter {
                field,
                index,
                value,
            });
        }
    }

    Ok(())
}

fn successor(letter: u8) -> u8 {
    b'A' + (letter - b'A' + 1) % 26
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisguiseKey {
    alphabet: [u8; 26],
    digits: [u8; 26],
    positions: [u8; 26],
}

impl DisguiseKey {
    pub fn new(alphabet: [u8; 26], digits: [u8; 26]) -> Result<Self, MessageError> {
        validate_letters(&alphabet, "disguise alphabet")?;

        let mut positions = [0; 26];
        let mut seen = [false; 26];

        for (index, &letter) in alphabet.iter().enumerate() {
            let slot = usize::from(letter - b'A');

            if seen[slot] {
                return Err(MessageError::DuplicateLetter(char::from(letter)));
            }

            seen[slot] = true;
            positions[slot] = index as u8;
        }

        for (index, &value) in digits.iter().enumerate() {
            if !(1..=9).contains(&value) {
                return Err(MessageError::InvalidDigit { index, value });
            }
        }

        Ok(Self {
            alphabet,
            digits,
            positions,
        })
    }

    pub fn alphabet(&self) -> &[u8; 26] {
        &self.alphabet
    }

    pub fn digits(&self) -> &[u8; 26] {
        &self.digits
    }

    fn position(&self, letter: u8) -> usize {
        usize::from(self.positions[usize::from(letter - b'A')])
    }

    fn shifts(&self, ciphertext_prefix: &[u8; 3]) -> [u8; 8] {
        let mut shifts = [0; 8];

        for (group, &letter) in ciphertext_prefix.iter().enumerate() {
            let position = self.position(letter);

            for offset in 0..3 {
                let index = group * 3 + offset;

                if index < shifts.len() {
                    shifts[index] = self.digits[(position + offset) % 26];
                }
            }
        }

        shifts
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageIndicator([u8; 4]);

impl MessageIndicator {
    pub fn new(letters: [u8; 4]) -> Result<Self, MessageError> {
        validate_letters(&letters, "message indicator")?;
        Ok(Self(letters))
    }

    pub fn letters(&self) -> &[u8; 4] {
        &self.0
    }
}

/// Mask a four-letter indicator, returning the eight meaningful header letters.
///
/// The caller must append exactly two random A-Z filler letters to produce
/// the complete historical ten-letter transmitted header.
pub fn mask_indicator(
    key: &DisguiseKey,
    indicator: &MessageIndicator,
    ciphertext_prefix: [u8; 3],
) -> Result<[u8; 8], MessageError> {
    validate_letters(&ciphertext_prefix, "ciphertext prefix")?;

    let shifts = key.shifts(&ciphertext_prefix);
    let mut masked = [0; 8];

    for index in 0..8 {
        let source = if index < 4 {
            indicator.0[index]
        } else {
            successor(indicator.0[index - 4])
        };

        masked[index] = key.alphabet[(key.position(source) + usize::from(shifts[index])) % 26];
    }

    Ok(masked)
}

/// Recover an indicator from its eight meaningful masked letters.
/// The redundant four letters must match ordinary-alphabet successors.
pub fn unmask_indicator(
    key: &DisguiseKey,
    masked: [u8; 8],
    ciphertext_prefix: [u8; 3],
) -> Result<MessageIndicator, MessageError> {
    validate_letters(&masked, "masked indicator")?;
    validate_letters(&ciphertext_prefix, "ciphertext prefix")?;

    let shifts = key.shifts(&ciphertext_prefix);
    let mut source = [0; 8];

    for index in 0..8 {
        let position = (key.position(masked[index]) + 26 - usize::from(shifts[index])) % 26;
        source[index] = key.alphabet[position];
    }

    for index in 0..4 {
        if source[index + 4] != successor(source[index]) {
            return Err(MessageError::IndicatorCheckFailed);
        }
    }

    Ok(MessageIndicator([source[0], source[1], source[2], source[3]]))
}

/// Append two caller-provided random letters to construct the wire header.
pub fn make_header(masked: [u8; 8], filler: [u8; 2]) -> Result<[u8; 10], MessageError> {
    validate_letters(&masked, "masked indicator")?;
    validate_letters(&filler, "header filler")?;

    let mut header = [0; 10];
    header[..8].copy_from_slice(&masked);
    header[8..].copy_from_slice(&filler);
    Ok(header)
}

/// Ignore the two historical random filler letters when recovering an indicator.
pub fn unmask_header(
    key: &DisguiseKey,
    header: [u8; 10],
    ciphertext_prefix: [u8; 3],
) -> Result<MessageIndicator, MessageError> {
    validate_letters(&header, "transmitted header")?;
    let masked = [header[0], header[1], header[2], header[3], header[4], header[5], header[6], header[7]];
    unmask_indicator(key, masked, ciphertext_prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> DisguiseKey {
        DisguiseKey::new(
            *b"QWERTYUIOPASDFGHJKLZXCVBNM",
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 1, 2, 3, 4, 5, 6, 7, 8],
        )
        .unwrap()
    }

    #[test]
    fn masking_round_trip() {
        let key = test_key();

        for indicator in [*b"KNVP", *b"ZZZZ", *b"ABCD", *b"ZAZA"] {
            for prefix in [*b"CMQ", *b"NMQ", *b"QWE", *b"ZZZ"] {
                let indicator = MessageIndicator::new(indicator).unwrap();
                let masked = mask_indicator(&key, &indicator, prefix).unwrap();
                assert_eq!(unmask_indicator(&key, masked, prefix).unwrap(), indicator);
                let header = make_header(masked, *b"WT").unwrap();
                assert_eq!(unmask_header(&key, header, prefix).unwrap(), indicator);
            }
        }
    }

    #[test]
    fn wraparound_digit_sequence() {
        let key = test_key();
        let shifts = key.shifts(b"MNM");
        // M is final alphabet entry (position 25); its lookup wraps to 0 and 1.
        assert_eq!(&shifts[..3], &[8, 1, 2]);
    }

    #[test]
    fn key_rejects_invalid_input() {
        assert!(matches!(
            DisguiseKey::new(*b"AAAAAAAAAAAAAAAAAAAAAAAAAA", [1; 26]),
            Err(MessageError::DuplicateLetter('A'))
        ));
        assert!(matches!(
            DisguiseKey::new(*b"ABCDEFGHIJKLMNOPQRSTUVWXYZ", [0; 26]),
            Err(MessageError::InvalidDigit { .. })
        ));
        assert!(MessageIndicator::new(*b"ABcD").is_err());
    }

    #[test]
    fn detects_corrupted_redundancy() {
        let key = test_key();
        let indicator = MessageIndicator::new(*b"KNVP").unwrap();
        let mut masked = mask_indicator(&key, &indicator, *b"CMQ").unwrap();
        masked[4] = if masked[4] == b'A' { b'B' } else { b'A' };
        assert_eq!(unmask_indicator(&key, masked, *b"CMQ"), Err(MessageError::IndicatorCheckFailed));
    }

    #[test]
    fn rejects_non_ascii_letters() {
        let key = test_key();
        let indicator = MessageIndicator::new(*b"KNVP").unwrap();
        assert!(mask_indicator(&key, &indicator, *b"C M").is_err());
        assert!(make_header(*b"ABCDEFGH", *b"W0").is_err());
    }
}
