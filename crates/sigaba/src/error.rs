//! SIGABA library error types.

use core::fmt;

use crate::config::LargeRotorBank;
use crate::data::{IndexRotorId, LargeRotorId};
use crate::rotor_set::RotorKind;

/// Invalid SIGABA key/configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A large rotor appears more than once across cipher/control banks.
    DuplicateLargeRotor {
        id: LargeRotorId,
        first_bank: LargeRotorBank,
        first_slot: usize,
        second_bank: LargeRotorBank,
        second_slot: usize,
    },
    /// An index rotor appears in more than one index slot.
    DuplicateIndexRotor {
        id: IndexRotorId,
        first_slot: usize,
        second_slot: usize,
    },
    /// A validated reference wiring could not be constructed.
    InvalidReferenceWiring,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DuplicateLargeRotor {
                id,
                first_bank,
                first_slot,
                second_bank,
                second_slot,
            } => write!(
                f,
                "large rotor {} is duplicated in {:?} slot {} and {:?} slot {}",
                id.get(),
                first_bank,
                first_slot + 1,
                second_bank,
                second_slot + 1,
            ),
            Self::DuplicateIndexRotor {
                id,
                first_slot,
                second_slot,
            } => write!(
                f,
                "index rotor {} is duplicated in slots {} and {}",
                id.get(),
                first_slot + 1,
                second_slot + 1,
            ),
            Self::InvalidReferenceWiring => {
                f.write_str("SIGABA reference rotor wiring is invalid")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Error returned while parsing or validating a rotor wiring dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotorSetError {
    /// The document is not valid rotor-set YAML.
    InvalidYaml(String),
    /// The document uses a schema version this crate does not understand.
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    /// The dataset name is empty or contains only whitespace.
    EmptyName,
    /// A rotor bank does not contain the required number of definitions.
    WrongRotorCount {
        kind: RotorKind,
        expected: usize,
        actual: usize,
    },
    /// A rotor identity is outside the range accepted for its bank.
    RotorIdOutOfRange {
        kind: RotorKind,
        id: i64,
        maximum: usize,
    },
    /// A rotor identity appears more than once in one bank.
    DuplicateRotorId {
        kind: RotorKind,
        id: usize,
        first_definition: usize,
        second_definition: usize,
    },
    /// A wiring contains the wrong number of contacts.
    WrongWiringLength {
        kind: RotorKind,
        id: usize,
        expected: usize,
        actual: usize,
    },
    /// A wiring contains a symbol outside its contact alphabet.
    InvalidWiringSymbol {
        kind: RotorKind,
        id: usize,
        position: usize,
        symbol: char,
    },
    /// A wiring maps two inputs to the same output contact.
    DuplicateWiringContact {
        kind: RotorKind,
        id: usize,
        symbol: char,
        first_position: usize,
        second_position: usize,
    },
}

impl fmt::Display for RotorSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(f, "invalid rotor-set YAML: {error}"),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                f,
                "unsupported rotor-set schema version {found}; expected {supported}"
            ),
            Self::EmptyName => f.write_str("rotor-set name must not be empty"),
            Self::WrongRotorCount {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "{kind}-rotor set contains {actual} definitions; expected {expected}"
            ),
            Self::RotorIdOutOfRange { kind, id, maximum } => {
                write!(f, "{kind}-rotor id {id} is outside 0..{maximum}")
            }
            Self::DuplicateRotorId {
                kind,
                id,
                first_definition,
                second_definition,
            } => write!(
                f,
                "{kind}-rotor id {id} is duplicated in definitions {} and {}",
                first_definition + 1,
                second_definition + 1
            ),
            Self::WrongWiringLength {
                kind,
                id,
                expected,
                actual,
            } => write!(
                f,
                "{kind}-rotor {id} wiring contains {actual} contacts; expected {expected}"
            ),
            Self::InvalidWiringSymbol {
                kind,
                id,
                position,
                symbol,
            } => write!(
                f,
                "{kind}-rotor {id} wiring has invalid symbol {symbol:?} at position {}",
                position + 1
            ),
            Self::DuplicateWiringContact {
                kind,
                id,
                symbol,
                first_position,
                second_position,
            } => write!(
                f,
                "{kind}-rotor {id} wiring repeats contact {symbol:?} at positions {} and {}",
                first_position + 1,
                second_position + 1
            ),
        }
    }
}

impl std::error::Error for RotorSetError {}

/// Error from the historical SIGABA text adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TextError {
    /// The validated configuration could not construct its static reference wiring.
    InvalidConfiguration,
    /// Plaintext contained a character not representable by the wartime
    /// alphabet/space keyboard path used here.
    UnsupportedPlaintext(char),
    /// Ciphertext contained something other than A-Z or grouping whitespace.
    UnsupportedCiphertext(char),
}

impl fmt::Display for TextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidConfiguration => f.write_str("invalid SIGABA configuration"),
            Self::UnsupportedPlaintext(ch) => write!(
                f,
                "character {ch:?} is not supported by the SIGABA plaintext text layer"
            ),
            Self::UnsupportedCiphertext(ch) => write!(
                f,
                "character {ch:?} is not valid SIGABA ciphertext"
            ),
        }
    }
}

impl std::error::Error for TextError {}

impl From<ConfigError> for TextError {
    fn from(_: ConfigError) -> Self {
        Self::InvalidConfiguration
    }
}
