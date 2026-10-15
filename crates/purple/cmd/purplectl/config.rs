//! YAML key-sheet loader for purplectl.
use purple::{PurpleAlphabet, PurpleConfig, PurpleMotion, SwitchPosition, TwentiesSwitchId};
use serde::Deserialize;
use std::{error::Error, fs, path::Path};

const REFERENCE_ALPHABET: &str = "NOKTYUXEQLHBRMPDICJASVWGZF";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    alphabet: String,
    sixes: u8,
    /// Physical twenties switches #1, #2, #3.
    twenties: [u8; 3],
    /// Fast, middle, slow physical switch numbers.
    motion: [u8; 3],
}

fn switch_id(value: u8) -> Result<TwentiesSwitchId, Box<dyn Error>> {
    match value {
        1 => Ok(TwentiesSwitchId::One),
        2 => Ok(TwentiesSwitchId::Two),
        3 => Ok(TwentiesSwitchId::Three),
        _ => Err(format!("invalid twenties switch identity {value}; expected 1..=3").into()),
    }
}

fn make_config(raw: FileConfig) -> Result<PurpleConfig, Box<dyn Error>> {
    let alphabet = PurpleAlphabet::new(&raw.alphabet)?;
    let sixes = SwitchPosition::new(raw.sixes)?;
    let twenties = raw.twenties.map(SwitchPosition::new);
    let [one, two, three] = twenties;
    let motion = PurpleMotion::new(
        switch_id(raw.motion[0])?,
        switch_id(raw.motion[1])?,
        switch_id(raw.motion[2])?,
    )?;
    Ok(PurpleConfig::new(alphabet, sixes, [one?, two?, three?], motion))
}

pub fn parse_config(yaml: &str) -> Result<PurpleConfig, Box<dyn Error>> {
    let raw: FileConfig = noyalib::from_str(yaml)?;
    make_config(raw)
}

pub fn load_config(path: Option<&Path>) -> Result<PurpleConfig, Box<dyn Error>> {
    match path {
        Some(path) => parse_config(&fs::read_to_string(path)?),
        None => make_config(FileConfig {
            alphabet: REFERENCE_ALPHABET.into(),
            sixes: 9,
            twenties: [1, 24, 6],
            motion: [2, 3, 1],
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use purple::Purple;

    const KEY: &str = include_str!("../../config/reference.yaml");

    #[test]
    fn reference_file_matches_default() {
        assert_eq!(parse_config(KEY).unwrap(), load_config(None).unwrap());
    }
    #[test]
    fn reference_vector() {
        let cipher = Purple::new(parse_config(KEY).unwrap());
        assert_eq!(cipher.encrypt_text("THEPURPLEMACHINEISNOWONLINE").unwrap(),
                   "OGIVTSIAAHMWMHTVIBYYJUOJFUE");
    }
    #[test]
    fn rejects_bad_switch_configuration() {
        assert!(parse_config(&KEY.replace("motion: [2, 3, 1]", "motion: [2, 2, 1]")).is_err());
        assert!(parse_config(&KEY.replace("sixes: 9", "sixes: 26")).is_err());
    }
    #[test]
    fn rejects_unrecognized_fields() {
        assert!(parse_config(&format!("{KEY}unknown: true\n")).is_err());
    }
}
