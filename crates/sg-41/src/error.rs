//! Errors validating SG-41 wheel geometry and pin settings.

use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WheelError {
    #[error("invalid SG-41 wheel number {0}; expected 1 through 6")]
    InvalidWheel(u8),

    #[error("invalid index {index} for wheel {wheel}; expected 0 through {max}")]
    InvalidIndex { wheel: u8, index: u8, max: u8 },

    #[error("invalid window label {label:?} for wheel {wheel}")]
    InvalidLabel { wheel: u8, label: char },

    #[error("invalid window marking {marking:?} for wheel {wheel}")]
    InvalidMarking { wheel: u8, marking: u8 },

    #[error("pin pattern for wheel {wheel} must contain exactly {expected} bits, got {actual}")]
    PinCount { wheel: u8, expected: usize, actual: usize },

    #[error("pin pattern for wheel {wheel} contains invalid bit {value:?} at row {row}")]
    InvalidPinBit { wheel: u8, row: usize, value: char },

    #[error("cannot use a position from wheel {position_wheel} with wheel {pattern_wheel} pins")]
    WheelMismatch { pattern_wheel: u8, position_wheel: u8 },
}

/// Invalid or inconsistent SG-41 key settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Wheel(#[from] WheelError),
}

/// Message indicators related errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum MessageError {
    #[error("invalid {field} letter at position {index}: {value:?}; expected A-Z")]
    InvalidLetter {
        field: &'static str,
        index: usize,
        value: u8,
    },

    #[error("disguise alphabet contains duplicate letter {0:?}")]
    DuplicateLetter(char),

    #[error("invalid disguise digit at position {index}: {value}; expected 1-9")]
    InvalidDigit { index: usize, value: u8 },

    #[error("message indicator redundancy check failed")]
    IndicatorCheckFailed,
}
