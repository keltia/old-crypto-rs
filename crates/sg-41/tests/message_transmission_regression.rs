//! Transmission regression tests using synthetic pin rows, not a historical
//! full-message known-answer vector. The historical March 1945 indicator
//! vector is checked separately in `message_indicator_historical.rs`.

use sg_41::{
    DailyKey, DisguiseKey, MessageIndicator, MonthlyPinTable, StationNumbers,
    TransmissionError, MAX_MESSAGE_LETTERS, decipher_message, encipher_message,
    format_ciphertext,
};

fn reference_settings() -> (MonthlyPinTable, DailyKey, StationNumbers, DisguiseKey, MessageIndicator) {
    let monthly = MonthlyPinTable::new(std::array::from_fn(|_| "0".repeat(25))).unwrap();
    let daily = DailyKey::new(*b"ACHUKW").unwrap();
    let sender = StationNumbers::new(18, 37).unwrap();
    let disguise = DisguiseKey::new(
        *b"SYIZBJEHOCKUGPDRVFTXLNMWAQ",
        [9, 6, 5, 8, 5, 1, 3, 8, 1, 5, 7, 8, 3, 4, 7, 9, 4, 2, 8, 9, 5, 6, 3, 2, 6, 2],
    ).unwrap();
    let indicator = MessageIndicator::new(*b"KNVP").unwrap();

    (monthly, daily, sender, disguise, indicator)
}

#[test]
fn maximum_length_message_round_trips_without_padding() {
    let (monthly, daily, sender, disguise, indicator) = reference_settings();
    let plaintext = "A".repeat(MAX_MESSAGE_LETTERS);

    let transmitted = encipher_message(
        &monthly, &daily, sender, &disguise, &indicator,
        &plaintext, "", *b"WT",
    ).unwrap();

    assert_eq!(transmitted.unpadded_len, MAX_MESSAGE_LETTERS);
    assert_eq!(transmitted.ciphertext.len(), MAX_MESSAGE_LETTERS);
    assert_eq!(transmitted.wire.len(), MAX_MESSAGE_LETTERS + 10);

    let grouped = format_ciphertext(&transmitted.wire);
    let received = decipher_message(&monthly, &daily, sender, &disguise, &grouped).unwrap();

    assert_eq!(received.indicator, indicator);
    assert_eq!(received.ciphertext, transmitted.ciphertext);
    assert_eq!(received.plaintext_with_padding, plaintext);
}

#[test]
fn oversized_ciphertext_is_rejected() {
    let (monthly, daily, sender, disguise, indicator) = reference_settings();
    let plaintext = "A".repeat(MAX_MESSAGE_LETTERS + 1);

    assert!(matches!(
        encipher_message(
            &monthly, &daily, sender, &disguise, &indicator,
            &plaintext, "ABCD", *b"WT",
        ),
        Err(TransmissionError::TooLong(605)),
    ));
}

#[test]
fn modified_disguised_indicator_fails_consistency_check() {
    let (monthly, daily, sender, disguise, indicator) = reference_settings();
    let transmitted = encipher_message(
        &monthly, &daily, sender, &disguise, &indicator,
        "HALLO WELTS", "ABCD", *b"WT",
    ).unwrap();

    let mut wire = transmitted.wire.into_bytes();
    wire[0] = if wire[0] == b'A' { b'B' } else { b'A' };
    let altered = String::from_utf8(wire).unwrap();

    assert!(decipher_message(&monthly, &daily, sender, &disguise, &altered).is_err());
}

#[test]
fn missing_ciphertext_groups_are_rejected() {
    let (monthly, daily, sender, disguise, indicator) = reference_settings();
    let transmitted = encipher_message(
        &monthly, &daily, sender, &disguise, &indicator,
        "HALLO WELTS", "ABCD", *b"WT",
    ).unwrap();

    let truncated = &transmitted.wire[..transmitted.wire.len() - 1];
    assert!(matches!(
        decipher_message(&monthly, &daily, sender, &disguise, truncated),
        Err(TransmissionError::InvalidGrouping),
    ));
}
