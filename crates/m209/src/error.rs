//! Errors for invalid M-209 machine settings and key components.

use thiserror::Error;

use crate::{IndicatorError, KeyListError, TextError, WheelId};

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
