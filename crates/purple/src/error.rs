//! Errors returned by the PURPLE cipher machine.

use thiserror::Error;

use crate::TwentiesSwitchId;

/// Error encountered when validating a PURPLE alphabet or external letter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum AlphabetError {
    #[error("alphabet must have 26 bytes, got {actual}")]
    InvalidLength { actual: usize },

    #[error("invalid alphabet byte {byte} at index {index}")]
    InvalidLetter { index: usize, byte: u8 },

    #[error("duplicate alphabet letter {}", char::from(*byte))]
    DuplicateLetter { byte: u8 },

    #[error("input byte {byte} is not an uppercase ASCII letter")]
    InvalidInputLetter { byte: u8 },
}

/// Error returned when a numeric contact is outside its bank.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("contact {value} is outside 0..{count}")]
pub struct ContactError {
    /// The rejected zero-based contact number.
    pub value: u8,

    /// Number of contacts in the requested bank.
    pub count: u8,
}

/// Invalid speed assignment: a physical twenties switch was selected more than once.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("twenties switch {repeated:?} occurs more than once in motion order")]
pub struct MotionError {
    /// The physical switch used by more than one speed.
    pub repeated: TwentiesSwitchId,
}

/// Invalid historical switch position (the valid range is 1–25).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
#[error("switch position {0} is outside 1..=25")]
pub struct PositionError(pub u8);
