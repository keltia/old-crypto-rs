//! Validated daily keys and named key stores for wartime message procedures.
//!
//! This module manages keys only. Deriving message indicators and constructing
//! message envelopes belong to subsequent implementation stages.

use std::collections::BTreeMap;

use serde::Deserialize;
use thiserror::Error;

use crate::{
    Contact, DRUM_BAR_COUNT, DrumBar, KeyError, Lug, M209Config, WHEEL_COUNT, WheelId,
};

/// Validation and decoding failures for named M-209 key lists.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KeyListError {
    #[error("key identifier must be exactly two uppercase ASCII letters: {0:?}")]
    InvalidIdentifier(String),

    #[error("duplicate key identifier {0}")]
    DuplicateIdentifier(KeyId),

    #[error("unknown key identifier {0}")]
    UnknownIdentifier(KeyId),

    #[error("key check must be exactly 26 uppercase ASCII letters")]
    InvalidCheck,

    #[error("key {id} failed its 26-letter check: expected {expected}, computed {computed}")]
    CheckMismatch {
        id: KeyId,
        expected: String,
        computed: String,
    },

    #[error("expected {expected} drum bars, received {actual}")]
    InvalidBarCount { expected: usize, actual: usize },

    #[error("invalid mechanical key: {0}")]
    Mechanical(#[from] KeyError),

    #[error("invalid key-list YAML: {0}")]
    Yaml(String),

    #[error("key store must contain at least one key")]
    EmptyStore,
}

/// Exactly two uppercase ASCII letters used to select a daily key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId([u8; 2]);

impl KeyId {
    pub fn parse(value: &str) -> Result<Self, KeyListError> {
        let bytes = value.as_bytes();

        match bytes {
            [first, second] if first.is_ascii_uppercase() && second.is_ascii_uppercase() => {
                Ok(Self([*first, *second]))
            }
            _ => Err(KeyListError::InvalidIdentifier(value.to_owned())),
        }
    }

    pub const fn letters(self) -> [u8; 2] {
        self.0
    }
}

impl std::fmt::Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.0[0] as char, self.0[1] as char)
    }
}

/// A named mechanical key with a verified 26-character check sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyList {
    id: KeyId,
    config: M209Config,
    check: String,
}

impl KeyList {
    /// Verify the published check by enciphering 26 A contacts at `AAAAAA`.
    pub fn new(id: KeyId, config: M209Config, check: &str) -> Result<Self, KeyListError> {
        if check.len() != 26 || !check.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(KeyListError::InvalidCheck);
        }

        // A key-list check always starts at AAAAAA, independently of any
        // external message indicator or the config's stored initial positions.
        let positions = core::array::from_fn(|index| {
            WheelId::new((index + 1) as u8)
                .expect("physical wheel identity")
                .position_for_letter('A')
                .expect("all six historical wheel alphabets contain A")
        });

        let check_config = M209Config::new(*config.pins(), positions, *config.bars())?;
        let mut machine = check_config.build_machine();
        let computed: String = (0..26)
            .map(|_| machine.convert_contact(Contact::A).letter())
            .collect();

        if computed != check {
            return Err(KeyListError::CheckMismatch {
                id,
                expected: check.to_owned(),
                computed,
            });
        }

        Ok(Self { id, config: check_config, check: check.to_owned() })
    }

    pub const fn id(&self) -> KeyId {
        self.id
    }

    pub const fn config(&self) -> &M209Config {
        &self.config
    }

    pub fn check(&self) -> &str {
        &self.check
    }
}

/// Validated collection of uniquely identified M-209 daily keys.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyStore {
    keys: BTreeMap<KeyId, KeyList>,
}

impl KeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: KeyList) -> Result<(), KeyListError> {
        if self.keys.contains_key(&key.id()) {
            return Err(KeyListError::DuplicateIdentifier(key.id()));
        }

        self.keys.insert(key.id(), key);
        Ok(())
    }

    pub fn get(&self, id: KeyId) -> Result<&KeyList, KeyListError> {
        self.keys.get(&id).ok_or(KeyListError::UnknownIdentifier(id))
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Strictly parse YAML, validate all mechanical data, checks, and key IDs.
    pub fn from_yaml(contents: &str) -> Result<Self, KeyListError> {
        let source: KeyStoreFile = noyalib::from_str(contents)
            .map_err(|error| KeyListError::Yaml(error.to_string()))?;

        if source.keys.is_empty() {
            return Err(KeyListError::EmptyStore);
        }

        let mut store = Self::new();

        for entry in source.keys {
            let id = KeyId::parse(&entry.id)?;

            if store.keys.contains_key(&id) {
                return Err(KeyListError::DuplicateIdentifier(id));
            }

            if entry.lugs.len() != DRUM_BAR_COUNT {
                return Err(KeyListError::InvalidBarCount {
                    expected: DRUM_BAR_COUNT,
                    actual: entry.lugs.len(),
                });
            }

            let bars: Vec<DrumBar> = entry.lugs
                .into_iter()
                .map(|[left, right]| {
                    Ok(DrumBar::new(Lug::try_from(left)?, Lug::try_from(right)?))
                })
                .collect::<Result<_, KeyError>>()?;

            let bars: [DrumBar; DRUM_BAR_COUNT] = bars.try_into().map_err(|bars: Vec<_>| {
                KeyListError::InvalidBarCount {
                    expected: DRUM_BAR_COUNT,
                    actual: bars.len(),
                }
            })?;

            let config = M209Config::from_letters(
                entry.pins.each_ref().map(String::as_str),
                "AAAAAA",
                bars,
            )?;

            store.insert(KeyList::new(id, config, &entry.check)?)?;
        }

        Ok(store)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyStoreFile {
    keys: Vec<KeyFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    id: String,
    pins: [String; WHEEL_COUNT],
    lugs: Vec<[u8; 2]>,
    check: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{MANUAL_1944_CHECK, MANUAL_1944_PINS, manual_1944_drum};

    fn reference_key(id: &str) -> KeyList {
        KeyList::new(
            KeyId::parse(id).unwrap(),
            M209Config::from_letters(MANUAL_1944_PINS, "AAAAAA", manual_1944_drum()).unwrap(),
            MANUAL_1944_CHECK,
        )
        .unwrap()
    }

    #[test]
    fn identifiers_require_exactly_two_uppercase_ascii_letters() {
        for invalid in ["", "A", "AAA", "aB", "A1", "ÄB", "A B"] {
            assert!(KeyId::parse(invalid).is_err(), "{invalid:?}");
        }

        assert_eq!(KeyId::parse("XA").unwrap().to_string(), "XA");
    }

    #[test]
    fn reference_check_is_verified_and_wrong_check_is_rejected() {
        let key = reference_key("XA");
        assert_eq!(key.check(), MANUAL_1944_CHECK);
        assert!(matches!(
            KeyList::new(key.id(), key.config().clone(), "AAAAAAAAAAAAAAAAAAAAAAAAAA"),
            Err(KeyListError::CheckMismatch { .. })
        ));
    }

    #[test]
    fn duplicate_and_missing_identifiers_are_rejected() {
        let mut store = KeyStore::new();
        store.insert(reference_key("XA")).unwrap();
        assert_eq!(store.len(), 1);
        assert!(matches!(store.insert(reference_key("XA")), Err(KeyListError::DuplicateIdentifier(_))));
        assert!(matches!(store.get(KeyId::parse("XB").unwrap()), Err(KeyListError::UnknownIdentifier(_))));
    }

    #[test]
    fn yaml_reference_key_builds_independent_machines() {
        let store = KeyStore::from_yaml(include_str!("../config/key-list-reference.yaml")).unwrap();
        let key = store.get(KeyId::parse("XA").unwrap()).unwrap();
        let mut first = key.config().build_machine();
        let second = key.config().build_machine();
        first.convert_contact(Contact::A);
        assert_ne!(first.positions(), second.positions());
    }

    #[test]
    fn yaml_rejects_unknown_fields_and_duplicate_identifiers() {
        let valid = include_str!("../config/key-list-reference.yaml");
        assert!(KeyStore::from_yaml(&valid.replace("keys:", "extra: true\nkeys:")).is_err());
        let item = valid.split_once("  - id: XA\n").unwrap().1;
        let double = format!("{valid}  - id: XA\n{item}");
        assert!(matches!(KeyStore::from_yaml(&double), Err(KeyListError::DuplicateIdentifier(_))));
    }

    #[test]
    fn yaml_rejects_bad_lugs_and_wrong_bar_count() {
        let valid = include_str!("../config/key-list-reference.yaml");
        assert!(matches!(KeyStore::from_yaml(&valid.replacen("[3, 6]", "[3, 7]", 1)), Err(KeyListError::Mechanical(KeyError::InvalidLug(7)))));
        assert!(matches!(KeyStore::from_yaml(&valid.replacen("      - [3, 6]\n", "", 1)), Err(KeyListError::InvalidBarCount { .. })));
    }
}
