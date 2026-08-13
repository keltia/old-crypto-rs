//! Configuration management

use serde::Deserialize;
use sigaba::{
    IndexRotorSetting, LargeRotorSet, LargeRotorSetting, Orientation, SigabaConfig,
    SigabaIndexPosition, SigabaIndexRotorId, SigabaRotorId, SigabaRotorPosition,
};
use std::error::Error;
use std::path::Path;
use std::{fmt, fs};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    rotor_set: RotorSet,
    cipher: [LargeRotor; 5],
    control: [LargeRotor; 5],
    index: [IndexRotor; 5],
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RotorSet {
    PekelneyReference,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LargeRotor {
    /// ECM designation: N0..N9 for normal or R0..R9 for reversed.
    rotor: String,
    /// Visible position, written as a letter from A through Z.
    position: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndexRotor {
    id: u8,
    /// Visible position from 0 through 9.
    position: u8,
}

#[derive(Debug)]
pub struct ConfigFileError(String);

impl fmt::Display for ConfigFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ConfigFileError {}

pub fn load_config(path: &Path) -> Result<SigabaConfig, Box<dyn Error>> {
    let yaml = fs::read_to_string(path)?;
    parse_config(&yaml).map_err(Into::into)
}

pub fn parse_config(yaml: &str) -> Result<SigabaConfig, ConfigFileError> {
    let raw: FileConfig = serde_yml::from_str(yaml)
        .map_err(|error| ConfigFileError(format!("invalid YAML configuration: {error}")))?;

    let rotor_set = match raw.rotor_set {
        RotorSet::PekelneyReference => LargeRotorSet::PekelneyReference,
    };
    let cipher = convert_large_bank("cipher", raw.cipher)?;
    let control = convert_large_bank("control", raw.control)?;
    let index = convert_index_bank(raw.index)?;

    SigabaConfig::new(rotor_set, cipher, control, index)
        .map_err(|error| ConfigFileError(format!("invalid SIGABA configuration: {error}")))
}

pub fn convert_large_bank(
    bank: &str,
    raw: [LargeRotor; 5],
) -> Result<[LargeRotorSetting; 5], ConfigFileError> {
    let mut settings = Vec::with_capacity(5);
    for (slot, rotor) in raw.into_iter().enumerate() {
        let (id, orientation) = parse_rotor_designation(bank, slot, &rotor.rotor)?;
        let position = parse_large_position(bank, slot, &rotor.position)?;
        settings.push(LargeRotorSetting::new(id, position, orientation));
    }
    settings
        .try_into()
        .map_err(|_| ConfigFileError(format!("{bank} bank must contain exactly five rotors")))
}

pub fn parse_rotor_designation(
    bank: &str,
    slot: usize,
    value: &str,
) -> Result<(SigabaRotorId, Orientation), ConfigFileError> {
    let bytes = value.as_bytes();
    let orientation = match bytes.first().copied() {
        Some(b'N') => Orientation::Normal,
        Some(b'R') => Orientation::Reversed,
        _ => return Err(invalid_rotor_designation(bank, slot, value)),
    };
    if bytes.len() != 2 || !bytes[1].is_ascii_digit() {
        return Err(invalid_rotor_designation(bank, slot, value));
    }
    let id = SigabaRotorId::new(bytes[1] - b'0')
        .ok_or_else(|| invalid_rotor_designation(bank, slot, value))?;
    Ok((id, orientation))
}

pub fn invalid_rotor_designation(bank: &str, slot: usize, value: &str) -> ConfigFileError {
    ConfigFileError(format!(
        "{bank} rotor slot {} has designation {value:?}; expected N0 through N9 or R0 through R9",
        slot + 1
    ))
}

pub fn parse_large_position(
    bank: &str,
    slot: usize,
    value: &str,
) -> Result<SigabaRotorPosition, ConfigFileError> {
    let bytes = value.as_bytes();
    if bytes.len() != 1 || !bytes[0].is_ascii_alphabetic() {
        return Err(ConfigFileError(format!(
            "{bank} rotor slot {} has position {value:?}; expected A through Z",
            slot + 1
        )));
    }
    let coordinate = bytes[0].to_ascii_uppercase() - b'A';
    SigabaRotorPosition::new(coordinate).ok_or_else(|| {
        ConfigFileError(format!(
            "{bank} rotor slot {} has position {value:?}; expected A through Z",
            slot + 1
        ))
    })
}

pub fn convert_index_bank(raw: [IndexRotor; 5]) -> Result<[IndexRotorSetting; 5], ConfigFileError> {
    let mut settings = Vec::with_capacity(5);
    for (slot, rotor) in raw.into_iter().enumerate() {
        let id = SigabaIndexRotorId::new(rotor.id).ok_or_else(|| {
            ConfigFileError(format!(
                "index rotor slot {} has id {}; expected 0 through 4",
                slot + 1,
                rotor.id
            ))
        })?;
        let position = SigabaIndexPosition::new(rotor.position).ok_or_else(|| {
            ConfigFileError(format!(
                "index rotor slot {} has position {}; expected 0 through 9",
                slot + 1,
                rotor.position
            ))
        })?;
        settings.push(IndexRotorSetting::new(id, position));
    }
    settings
        .try_into()
        .map_err(|_| ConfigFileError("index bank must contain exactly five rotors".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigaba::Sigaba;

    const REFERENCE: &str = include_str!("../../config/reference.yaml");

    #[test]
    fn reference_yaml_matches_known_answer() {
        let machine = Sigaba::new(parse_config(REFERENCE).unwrap());
        assert_eq!(machine.encrypt_text("HELLO WORLD").unwrap(), "FLQGFQUEQCH");
    }

    #[test]
    fn lowercase_positions_are_accepted() {
        let yaml = REFERENCE.replace("position: O", "position: o");
        assert!(parse_config(&yaml).is_ok());
    }

    #[test]
    fn invalid_position_reports_bank_and_slot() {
        let yaml = REFERENCE.replacen("position: O", "position: AA", 1);
        let error = parse_config(&yaml).unwrap_err().to_string();
        assert!(error.contains("cipher rotor slot 1"), "{error}");
    }

    #[test]
    fn duplicate_rotors_are_rejected_by_typed_configuration() {
        let yaml = REFERENCE.replacen("rotor: N1", "rotor: N0", 1);
        let error = parse_config(&yaml).unwrap_err().to_string();
        assert!(error.contains("duplicated"), "{error}");
    }

    #[test]
    fn standard_reversed_designation_is_accepted() {
        let yaml = REFERENCE.replacen("rotor: N2", "rotor: R2", 1);
        assert!(parse_config(&yaml).is_ok());
    }

    #[test]
    fn malformed_rotor_designation_reports_bank_and_slot() {
        let yaml = REFERENCE.replacen("rotor: N0", "rotor: normal-0", 1);
        let error = parse_config(&yaml).unwrap_err().to_string();
        assert!(error.contains("cipher rotor slot 1"), "{error}");
        assert!(error.contains("N0 through N9 or R0 through R9"), "{error}");
    }
}
