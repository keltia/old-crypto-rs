//! Independent historical SG-41 indicator known-answer test (16 March 1945).

use serde::Deserialize;
use sg_41::{DisguiseKey, MessageIndicator, make_header, mask_indicator, unmask_header, unmask_indicator};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Station {
    wheel_5: u8,
    wheel_6: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalVector {
    date: String,
    daily_key: String,
    disguise_alphabet: String,
    disguise_digits: String,
    sending_station: Station,
    message_indicator: String,
    successor_indicator: String,
    ciphertext_prefix: String,
    shifts: String,
    masked_indicator: String,
    filler: String,
    transmitted_header: String,
}

fn ascii_array<const N: usize>(s: &str) -> [u8; N] {
    s.as_bytes().try_into().expect("historical fixture field length")
}

#[test]
fn march_16_1945_indicator_known_answer() {
    let fixture: HistoricalVector = noyalib::from_str(include_str!("fixtures/message-1945-03-16.yaml"))
        .expect("valid historical YAML fixture");

    assert_eq!(fixture.date, "1945-03-16");
    assert_eq!(fixture.daily_key, "ACHUKW");
    assert_eq!((fixture.sending_station.wheel_5, fixture.sending_station.wheel_6), (18, 37));
    assert_eq!(fixture.successor_indicator, "LOWQ");
    assert_eq!(fixture.shifts, "57832629");

    let alphabet = ascii_array::<26>(&fixture.disguise_alphabet);
    let digits: [u8; 26] = fixture
        .disguise_digits
        .bytes()
        .map(|digit| digit.checked_sub(b'0').expect("ASCII digit"))
        .collect::<Vec<_>>()
        .try_into()
        .expect("26 disguise digits");
    let key = DisguiseKey::new(alphabet, digits).expect("historical disguise key is valid");
    let indicator = MessageIndicator::new(ascii_array::<4>(&fixture.message_indicator)).unwrap();
    let prefix = ascii_array::<3>(&fixture.ciphertext_prefix);

    let masked = mask_indicator(&key, &indicator, prefix).unwrap();
    assert_eq!(masked, ascii_array::<8>(&fixture.masked_indicator));

    let header = make_header(masked, ascii_array::<2>(&fixture.filler)).unwrap();
    assert_eq!(header, ascii_array::<10>(&fixture.transmitted_header));

    assert_eq!(unmask_indicator(&key, masked, prefix).unwrap(), indicator);
    assert_eq!(unmask_header(&key, header, prefix).unwrap(), indicator);
}
