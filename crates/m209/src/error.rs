//! Errors for invalid M-209 machine settings and key components.

use thiserror::Error;

use crate::{KeyId, WheelId};

/// Error for an invalid M-209 key component.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    #[error("M-209 contact {0} is outside 0..26")]
    InvalidContact(u8),
    #[error("{0:?} is not an uppercase A-Z contact")]
    InvalidLetter(char),
    #[error("M-209 wheel {0} is outside 1..=6")]
    InvalidWheel(u8),
    #[error("position {index} is outside wheel {wheel:?} range")]
    InvalidPosition { wheel: WheelId, index: u8 },
    #[error("letter {letter:?} does not occur on wheel {wheel:?}")]
    InvalidWheelLetter { wheel: WheelId, letter: char },
    #[error("pin bits {bits:#x} exceed wheel {wheel:?} capacity")]
    InvalidPinBits { wheel: WheelId, bits: u32 },
    #[error("wheel identity mismatch: expected {expected:?}, got {actual:?}")]
    WheelMismatch { expected: WheelId, actual: WheelId },
    #[error("M-209 indicator must contain exactly six ASCII letters (got {0} bytes)")]
    InvalidIndicatorLength(usize),
    #[error("M-209 lug {0} is outside 0..=6")]
    InvalidLug(u8),
}


/// Invalid messages and missing keys are reported without guessing defaults.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("invalid message characters: {0}")]
    Text(#[from] TextError),

    #[error("invalid key list: {0}")]
    Key(#[from] KeyListError),

    #[error("invalid message indicator: {0}")]
    Indicator(#[from] IndicatorError),

    #[error("a message must contain two opening groups, body, and two closing groups")]
    TooShort,

    #[error("ciphertext body must contain complete five-letter groups")]
    IncompleteBodyGroup,

    #[error("the closing indicator groups differ from the opening groups")]
    MismatchedIndicators,

    #[error("the two system-indicator letters must match")]
    InvalidSystemIndicator,

    #[error("ciphertext body must not be empty")]
    EmptyBody,
}

/// Errors encountered before or during indicator derivation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndicatorError {
    #[error("system indicator must be a single uppercase ASCII letter: {0:?}")]
    InvalidSystemLetter(char),

    #[error("external wheel indicator is invalid: {0}")]
    InvalidExternalIndicator(#[from] KeyError),

    #[error("only {selected} of six wheel positions could be derived from twelve letters")]
    InsufficientLetters { selected: usize },
}

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

/// Errors in text prepared for the M-209 alphabet.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum TextError {
    #[error("invalid plaintext character {character:?} at character index {index}")]
    InvalidPlaintext { index: usize, character: char },

    #[error("invalid ciphertext character {character:?} at character index {index}")]
    InvalidCiphertext { index: usize, character: char },
}
