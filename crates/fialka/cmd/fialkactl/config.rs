//! Strict YAML key sheets for the Fialka simulator.
use fialka::{
    Commutator, CoreSetting, CoreSide, FialkaConfig, RingSetting,
    RotorConfig, RotorId, RotorPosition, RotorSeries,
};
use serde::Deserialize;
use std::{error::Error, fs, path::Path};

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Series {
    Polish3k,
    Czechoslovak6k,
}
impl From<Series> for RotorSeries {
    fn from(value: Series) -> Self {
        match value {
            Series::Polish3k => Self::Polish3K,
            Series::Czechoslovak6k => Self::Czechoslovak6K,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RotorKey {
    /// Rotor identity in historical order, 0..9 (A, B, V, G, D, E, Zh, Z, I, K).
    body: usize,
    core: usize,
    /// Visible core side: 1 or 2.
    side: u8,
    /// Zero-based core angular setting, 0..29.
    core_setting: u8,
    /// Zero-based ring setting, 0..29.
    ring_setting: u8,
    /// Zero-based visible rotor position, 0..29.
    position: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    series: Series,
    /// Optional ten rotor entries in physical slot order (left to right).
    rotors: Option<[RotorKey; 10]>,
    /// Optional 30-element zero-based commutator permutation.
    commutator: Option<[u8; 30]>,
}

fn numbered_setting<T>(name: &str, number: u8, make: impl FnOnce(u8) -> Option<T>) -> Result<T, Box<dyn Error>> {
    make(number).ok_or_else(|| format!("invalid {name}: {number}; expected 0..29").into())
}

fn rotor_key(key: RotorKey) -> Result<RotorConfig, Box<dyn Error>> {
    let body = *RotorId::ALL.get(key.body).ok_or("rotor body must be 0..9")?;
    let core = *RotorId::ALL.get(key.core).ok_or("rotor core must be 0..9")?;
    let side = match key.side {
        1 => CoreSide::One,
        2 => CoreSide::Two,
        _ => return Err("core side must be 1 or 2".into()),
    };
    Ok(RotorConfig::new(
        body,
        core,
        side,
        numbered_setting("core setting", key.core_setting, CoreSetting::new)?,
        numbered_setting("ring setting", key.ring_setting, RingSetting::new)?,
        numbered_setting("position", key.position, RotorPosition::new)?,
    ))
}

pub fn parse_config(yaml: &str) -> Result<FialkaConfig, Box<dyn Error>> {
    let parsed: FileConfig = noyalib::from_str(yaml)?;
    let commutator = match parsed.commutator {
        Some(wiring) => Commutator::new(wiring)?,
        None => Commutator::identity(),
    };
    let series = parsed.series.into();
    match parsed.rotors {
        None => Ok(FialkaConfig::overall_base(series, commutator)),
        Some(rotors) => {
            let converted = rotors.into_iter().map(rotor_key).collect::<Result<Vec<_>, Box<dyn Error>>>()?;
            let array: [RotorConfig; 10] = converted.try_into().map_err(|_| "expected ten rotors")?;
            Ok(FialkaConfig::new(series, array, commutator)?)
        }
    }
}

pub fn load_config(path: Option<&Path>) -> Result<FialkaConfig, Box<dyn Error>> {
    match path {
        Some(path) => parse_config(&fs::read_to_string(path)?),
        None => Ok(FialkaConfig::overall_base(
            RotorSeries::Polish3K,
            Commutator::identity(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const REFERENCE: &str = include_str!("../../config/reference.yaml");

    #[test]
    fn reference_matches_default() {
        assert_eq!(parse_config(REFERENCE).unwrap(), load_config(None).unwrap());
    }
    #[test]
    fn czech_series_is_supported() {
        let config = parse_config("series: czechoslovak6k\n").unwrap();
        assert_eq!(config.rotor_series(), RotorSeries::Czechoslovak6K);
    }
    #[test]
    fn rejects_unknown_fields_and_bad_permutations() {
        assert!(parse_config("series: polish3k\nunknown: true\n").is_err());
        let bad = format!("series: polish3k\ncommutator: [{}]\n", [0; 30].iter().map(u8::to_string).collect::<Vec<_>>().join(", "));
        assert!(parse_config(&bad).is_err());
    }
}
