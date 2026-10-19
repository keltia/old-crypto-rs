use std::{fs, path::Path};

use m209::{DRUM_BAR_COUNT, DrumBar, Lug, M209Config, WHEEL_COUNT};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    pins: [String; WHEEL_COUNT],
    indicators: String,
    lugs: Vec<[u8; 2]>,
}

/// Parse the complete mechanical key without accepting missing drum bars.
pub fn parse_key(contents: &str) -> Result<M209Config, Box<dyn std::error::Error>> {
    let key: KeyFile = noyalib::from_str(contents)?;

    if key.lugs.len() != DRUM_BAR_COUNT {
        return Err(format!(
            "expected {DRUM_BAR_COUNT} drum bars, received {}",
            key.lugs.len()
        ).into());
    }

    let bars: [DrumBar; DRUM_BAR_COUNT] = key.lugs
        .into_iter()
        .map(|[left, right]| {
            let left = Lug::new(left).ok_or(m209::KeyError::InvalidLug(left))?;
            let right = Lug::new(right).ok_or(m209::KeyError::InvalidLug(right))?;

            Ok(DrumBar::new(left, right))
        })
        .collect::<Result<Vec<_>, m209::KeyError>>()?
        .try_into()
        .map_err(|_: Vec<DrumBar>| "invalid number of drum bars")?;

    M209Config::from_letters(
        key.pins.each_ref().map(String::as_str),
        &key.indicators,
        bars,
    )
    .map_err(Into::into)
}

pub fn load_key(path: &Path) -> Result<M209Config, Box<dyn std::error::Error>> {
    parse_key(&fs::read_to_string(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_out_of_range_lugs() {
        let valid = include_str!("../../config/reference.yaml");
        let invalid = valid.replacen("- [3, 6]", "- [7, 6]", 1);
        let error = parse_key(&invalid).unwrap_err();

        assert!(error.to_string().contains("lug 7"));
    }

    #[test]
    fn reference_key_reproduces_historical_check() {
        let config = parse_key(include_str!("../../config/reference.yaml")).unwrap();
        let mut machine = config.build_machine();

        let result: String = (0..26)
            .map(|_| machine.convert_contact(m209::Contact::A).letter())
            .collect();

        assert_eq!(result, "TNJUWAUQTKCZKNUTOTBCWARMIO");
    }

    #[test]
    fn rejects_too_few_or_too_many_drum_bars() {
        let valid = include_str!("../../config/reference.yaml");

        let too_few = valid.replacen("  - [3, 6]\n", "", 1);
        let too_many = format!("{valid}  - [0, 0]\n");

        assert!(parse_key(&too_few).is_err());
        assert!(parse_key(&too_many).is_err());
    }

    #[test]
    fn rejects_invalid_right_lug_and_unknown_key() {
        let valid = include_str!("../../config/reference.yaml");
        let invalid = valid.replacen("- [3, 6]", "- [3, 7]", 1);
        let error = parse_key(&invalid).unwrap_err();

        assert!(error.to_string().contains("lug 7"));

        let unknown = format!("{valid}unexpected: true\n");
        assert!(parse_key(&unknown).is_err());
    }

    #[test]
    fn rejects_incomplete_and_unknown_keys() {
        assert!(parse_key("pins: []\nindicators: AAAAAA\nlugs: []").is_err());
        assert!(parse_key("unknown: true").is_err());
    }
}
