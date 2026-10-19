//! Errors for invalid M-209 machine settings and key components.

use thiserror::Error;

use crate::WheelId;

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
