//! YAML-backed CLI operations for historical SG-41 transmissions.

use std::{error::Error, fs, path::Path};

use serde::Deserialize;
use sg_41::{
    DailyKey, DisguiseKey, MessageIndicator, MonthlyPinTable, StationNumbers,
    decipher_message, encipher_message, display_plaintext, format_ciphertext,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StationFile {
    wheel_5: u8,
    wheel_6: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MessageKeyFile {
    /// The 26 monthly rows in A-Z order, each a 25-character 0/1 string.
    monthly_rows: [String; 26],
    daily_key: String,
    sending_station: StationFile,
    disguise_alphabet: String,
    disguise_digits: String,
}

pub struct MessageKeys {
    monthly: MonthlyPinTable,
    daily: DailyKey,
    sender: StationNumbers,
    disguise: DisguiseKey,
}

fn letters<const N: usize>(value: &str, field: &str) -> Result<[u8; N], Box<dyn Error>> {
    if value.len() != N || !value.bytes().all(|letter| letter.is_ascii_uppercase()) {
        return Err(format!("{field} must contain exactly {N} uppercase A-Z letters").into());
    }

    Ok(value.as_bytes().try_into()?)
}

fn parse_keys(contents: &str) -> Result<MessageKeys, Box<dyn Error>> {
    let file: MessageKeyFile = noyalib::from_str(contents)?;
    let monthly = MonthlyPinTable::new(file.monthly_rows)?;
    let daily = DailyKey::new(letters::<6>(&file.daily_key, "daily_key")?)?;
    let sender = StationNumbers::new(file.sending_station.wheel_5, file.sending_station.wheel_6)?;
    let alphabet = letters::<26>(&file.disguise_alphabet, "disguise_alphabet")?;

    if file.disguise_digits.len() != 26 || !file.disguise_digits.bytes().all(|b| (b'1'..=b'9').contains(&b)) {
        return Err("disguise_digits must contain exactly 26 digits from 1 to 9".into());
    }

    let mut digits = [0u8; 26];
    for (slot, byte) in digits.iter_mut().zip(file.disguise_digits.bytes()) {
        *slot = byte - b'0';
    }

    let disguise = DisguiseKey::new(alphabet, digits)?;
    Ok(MessageKeys { monthly, daily, sender, disguise })
}

pub fn load_keys(path: &Path) -> Result<MessageKeys, Box<dyn Error>> {
    parse_keys(&fs::read_to_string(path)?)
}

pub fn encrypt(
    keys: &MessageKeys,
    indicator: &str,
    padding: &str,
    filler: &str,
    plaintext: &str,
) -> Result<String, Box<dyn Error>> {
    let indicator = MessageIndicator::new(letters::<4>(indicator, "indicator")?)?;
    let filler = letters::<2>(filler, "filler")?;
    let message = encipher_message(
        &keys.monthly, &keys.daily, keys.sender, &keys.disguise,
        &indicator, plaintext, padding, filler,
    )?;

    Ok(format_ciphertext(&message.wire))
}

pub fn decrypt(keys: &MessageKeys, wire: &str, raw_output: bool) -> Result<String, Box<dyn Error>> {
    let message = decipher_message(
        &keys.monthly, &keys.daily, keys.sender, &keys.disguise, wire,
    )?;

    if raw_output {
        Ok(message.plaintext_with_padding)
    } else {
        Ok(display_plaintext(&message.plaintext_with_padding))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> String {
        let rows = (0..26).map(|_| "  - '0000000000000000000000000'\n").collect::<String>();
        format!(
            "monthly_rows:\n{rows}daily_key: ACHUKW\nsending_station:\n  wheel_5: 18\n  wheel_6: 37\ndisguise_alphabet: SYIZBJEHOCKUGPDRVFTXLNMWAQ\ndisguise_digits: '96585138157834794289563262'\n"
        )
    }

    #[test]
    fn yaml_message_round_trip() {
        let keys = parse_keys(&fixture()).unwrap();
        let wire = encrypt(&keys, "KNVP", "ABCD", "WT", "HALLO WELTS").unwrap();
        assert_eq!(decrypt(&keys, &wire, true).unwrap(), "HALLOJWELTSABCD");
        assert_eq!(decrypt(&keys, &wire, false).unwrap(), "HALLO WELTSABCD");
    }

    #[test]
    fn invalid_yaml_key_and_indicator_are_rejected() {
        assert!(parse_keys(&fixture().replace("ACHUKW", "ACHUK!")).is_err());
        let keys = parse_keys(&fixture()).unwrap();
        assert!(encrypt(&keys, "KNV!", "ABCD", "WT", "HALLO WELTS").is_err());
        assert!(encrypt(&keys, "KNVP", "", "WT", "HALLO WELTS").is_err());
    }
}
