//! Complete SG-41 message transmission and reception.
//!
//! The ten-letter disguised indicator precedes the ciphertext. Callers
//! supply random padding and header filler; this module does not invent RNG.

use super::error::TransmissionError;
use super::message::{DisguiseKey, MessageIndicator, make_header, mask_indicator, unmask_header};
use super::procedure::{DailyKey, MonthlyPinTable, StationNumbers, historical_config};
use super::text::{parse_ciphertext, prepare_plaintext};

/// Maximum number of actual machine-produced ciphertext letters, including padding.
pub const MAX_MESSAGE_LETTERS: usize = 600;

/// The transmitted header plus ciphertext, with metadata needed to identify padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncipheredMessage {
    pub wire: String,
    pub ciphertext: String,
    pub unpadded_len: usize,
}

/// Deciphered machine letters. Original plaintext length cannot be inferred
/// from the wire, because the random ciphertext padding is not marked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecipheredMessage {
    pub indicator: MessageIndicator,
    pub plaintext_with_padding: String,
    pub ciphertext: String,
}

/// Encipher a single historical message.
///
/// `padding` is *plaintext* supplied by the caller. It is encrypted through
/// the advancing machine, and must be exactly the number of letters required
/// to complete a five-letter ciphertext group. Neither it nor `filler` is
/// generated internally.
///
/// A message must yield at least three ciphertext letters, because its first
/// three letters are needed to encode the transmitted indicator.
pub fn encipher_message(
    monthly: &MonthlyPinTable,
    daily: &DailyKey,
    sender: StationNumbers,
    disguise: &DisguiseKey,
    indicator: &MessageIndicator,
    plaintext: &str,
    padding: &str,
    filler: [u8; 2],
) -> Result<EncipheredMessage, TransmissionError> {
    let prepared = prepare_plaintext(plaintext)
        .map_err(|(index, ch)| TransmissionError::InvalidPlaintext { index, ch })?;

    let required = (5 - prepared.len() % 5) % 5;
    if padding.len() != required || !padding.bytes().all(|ch| ch.is_ascii_uppercase()) {
        return Err(TransmissionError::InvalidPadding { expected: required });
    }

    let length = prepared.len() + padding.len();
    check_length(length)?;

    // Validate even if a message contains no ciphertext yet.
    let config = historical_config(monthly, daily, indicator, sender)?;
    let mut core = config.build_core();
    let mut ciphertext = String::with_capacity(length);

    for letter in prepared.chars().chain(padding.chars()) {
        ciphertext.push(core.encipher_char(letter).expect("validated A-Z input").output);
    }

    let bytes = ciphertext.as_bytes();
    let prefix = [bytes[0], bytes[1], bytes[2]];
    let masked = mask_indicator(disguise, indicator, prefix)?;
    let header = make_header(masked, filler)?;

    let mut wire = String::with_capacity(10 + length);
    wire.push_str(std::str::from_utf8(&header).expect("header is ASCII"));
    wire.push_str(&ciphertext);

    Ok(EncipheredMessage { wire, ciphertext, unpadded_len: prepared.len() })
}

/// Decipher a transmitted message using the *sender's* station numbers.
///
/// All returned plaintext letters include the final 0–4 random padding
/// letters, which cannot be identified or stripped without external metadata.
pub fn decipher_message(
    monthly: &MonthlyPinTable,
    daily: &DailyKey,
    sender: StationNumbers,
    disguise: &DisguiseKey,
    wire: &str,
) -> Result<DecipheredMessage, TransmissionError> {
    let normalized = parse_ciphertext(wire)
        .map_err(|(index, ch)| TransmissionError::InvalidCiphertext { index, ch })?;
    if normalized.len() < 10 {
        return Err(TransmissionError::MissingHeader);
    }

    let body = &normalized[10..];
    check_length(body.len())?;
    if body.len() % 5 != 0 {
        return Err(TransmissionError::InvalidGrouping);
    }

    let bytes = normalized.as_bytes();
    let header: [u8; 10] = bytes[..10].try_into().expect("ten-byte header");
    let prefix = [bytes[10], bytes[11], bytes[12]];
    let indicator = unmask_header(disguise, header, prefix)?;
    let config = historical_config(monthly, daily, &indicator, sender)?;
    let mut core = config.build_core();
    let mut plaintext = String::with_capacity(body.len());

    for letter in body.chars() {
        plaintext.push(core.decipher_char(letter).expect("validated A-Z input").output);
    }

    Ok(DecipheredMessage {
        indicator,
        plaintext_with_padding: plaintext,
        ciphertext: body.to_owned(),
    })
}

fn check_length(length: usize) -> Result<(), TransmissionError> {
    if length < 3 {
        return Err(TransmissionError::TooShort(length));
    }
    if length > MAX_MESSAGE_LETTERS {
        return Err(TransmissionError::TooLong(length));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (MonthlyPinTable, DailyKey, StationNumbers, DisguiseKey, MessageIndicator) {
        let monthly = MonthlyPinTable::new(std::array::from_fn(|_| "0".repeat(25))).unwrap();
        let daily = DailyKey::new(*b"ACHUKW").unwrap();
        let station = StationNumbers::new(18, 37).unwrap();
        let disguise = DisguiseKey::new(
            *b"SYIZBJEHOCKUGPDRVFTXLNMWAQ",
            [9,6,5,8,5,1,3,8,1,5,7,8,3,4,7,9,4,2,8,9,5,6,3,2,6,2],
        ).unwrap();
        let indicator = MessageIndicator::new(*b"KNVP").unwrap();
        (monthly, daily, station, disguise, indicator)
    }

    #[test]
    fn round_trip_preserves_ciphertext_and_known_padding() {
        let (monthly, daily, station, disguise, indicator) = setup();
        let message = encipher_message(&monthly, &daily, station, &disguise, &indicator,
            "HALLO WELTS", "ABCD", *b"WT").unwrap();
        assert_eq!(message.unpadded_len, 11);
        assert_eq!(message.ciphertext.len(), 15);
        assert_eq!(message.wire.len(), 25);

        let received = decipher_message(&monthly, &daily, station, &disguise, &message.wire).unwrap();
        assert_eq!(received.indicator, indicator);
        assert_eq!(received.ciphertext, message.ciphertext);
        assert_eq!(received.plaintext_with_padding, "HALLOJWELTSABCD");
    }

    #[test]
    fn detects_missing_header_and_too_short_body() {
        let (monthly, daily, station, disguise, _) = setup();
        assert!(matches!(decipher_message(&monthly, &daily, station, &disguise, "ABC"), Err(TransmissionError::MissingHeader)));
        assert!(matches!(decipher_message(&monthly, &daily, station, &disguise, "ABCDEFGHIJ"), Err(TransmissionError::TooShort(0))));
    }

    #[test]
    fn invalid_padding_and_length_are_rejected() {
        let (monthly, daily, station, disguise, indicator) = setup();
        assert!(matches!(encipher_message(&monthly, &daily, station, &disguise, &indicator,
            "ABCD", "", *b"WT"), Err(TransmissionError::InvalidPadding { expected: 1 })));
        assert!(matches!(encipher_message(&monthly, &daily, station, &disguise, &indicator,
            &"A".repeat(601), "ABCD", *b"WT"), Err(TransmissionError::TooLong(605))));
    }
}
