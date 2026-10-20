//! Strict YAML loading for a single six-wheel SG-41 key.

use std::{fs, path::Path};

use serde::Deserialize;
use sg_41::{Sg41Config, WHEEL_COUNT, WindowLabel};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    /// Six physical window labels; numbers must include two digits.
    windows: [String; WHEEL_COUNT],
    /// The six Table 5 pin patterns, in wheel order.
    pins: [String; WHEEL_COUNT],
}

pub fn parse_key(contents: &str) -> Result<Sg41Config, Box<dyn std::error::Error>> {
    let key: KeyFile = noyalib::from_str(contents)?;

    let mut windows = [WindowLabel::Number(0); WHEEL_COUNT];

    for (index, label) in key.windows.iter().enumerate() {
        windows[index] = if index < 4 {
            let bytes = label.as_bytes();

            if bytes.len() != 1 || !bytes[0].is_ascii_uppercase() {
                return Err(format!("wheel {} requires one uppercase letter", index + 1).into());
            }

            WindowLabel::Letter(bytes[0] as char)
        } else {
            if label.len() != 2 || !label.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(format!("wheel {} requires a two-digit marking", index + 1).into());
            }

            WindowLabel::Number(label.parse::<u8>()?)
        };
    }

    Ok(Sg41Config::from_key_settings(
        windows,
        key.pins.each_ref().map(String::as_str),
    )?)
}

pub fn load_key(path: &Path) -> Result<Sg41Config, Box<dyn std::error::Error>> {
    parse_key(&fs::read_to_string(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE: &str = include_str!("../../config/reference.yaml");

    #[test]
    fn historical_key_parses_and_encrypts() {
        let config = parse_key(REFERENCE).unwrap();
        let mut core = config.build_core();
        let cipher: String = "SCHLUESSELGERAETVIEREINSWANDERER"
            .chars()
            .map(|ch| core.encipher_char(ch).unwrap().output)
            .collect();

        assert_eq!(cipher, "IHEPLRETQSDSNDCWHPIVVGLYMHOWSJQS");
    }

    #[test]
    fn invalid_and_missing_key_settings_are_rejected() {
        assert!(parse_key("windows: []\npins: []").is_err());
        assert!(parse_key(&format!("{REFERENCE}unexpected: true\n")).is_err());
        assert!(parse_key(&REFERENCE.replacen("\"01\"", "\"1\"", 1)).is_err());
        assert!(parse_key(&REFERENCE.replacen("\"00\"", "\"01\"", 1)).is_err());
        assert!(parse_key(&REFERENCE.replacen(
            "0001101011000100010001101",
            "000110101100010001000110x",
            1,
        )).is_err());
    }
}
