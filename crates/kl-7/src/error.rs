//! KL-7 configuration, maze, text and facade errors.

use crate::{contact::Contact26, data::RotorId, notch_ring::NotchRingId};
use thiserror::Error;

/// Error returned when validating a KL-7 configuration.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum ConfigError {
    /// Duplicate rotor core assigned to multiple slots in the drum.
    #[error("rotor core {0} assigned to multiple drum slots")]
    DuplicateRotorCore(RotorId),
    /// Duplicate notch ring assigned to multiple movable slots.
    #[error("notch ring {0} assigned to multiple movable slots")]
    DuplicateNotchRing(NotchRingId),
    /// Invalid rotor slot index.
    #[error("invalid rotor slot index: {0}")]
    InvalidRotorSlot(usize),
    /// Invalid rotor name or identifier.
    #[error("invalid rotor name: '{0}'")]
    InvalidRotorName(String),
    /// Invalid notch ring identifier.
    #[error("invalid notch ring number: {0}")]
    InvalidNotchRingNumber(u8),
    /// Invalid position label or number.
    #[error("invalid position: '{0}'")]
    InvalidPosition(String),
    /// YAML format or parsing error.
    #[error("YAML error: {0}")]
    Yaml(String),
}

/// Error encountered during maze signal routing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum MazeError {
    /// Signal entered an infinite loop without exiting at an alphabet contact.
    #[error("re-entry maze infinite loop detected starting from letter {start_letter} after {passes} passes")]
    InfiniteLoop { start_letter: Contact26, passes: usize },
}

/// Error returned by the KL-7 text processing layer.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum TextError {
    /// Plaintext contained an unsupported character.
    #[error("character '{0}' is not supported in KL-7 plaintext")]
    UnsupportedPlaintext(char),
    /// Ciphertext contained an invalid character.
    #[error("character '{0}' is not valid KL-7 ciphertext")]
    UnsupportedCiphertext(char),
    /// An electrical conduction error occurred in the re-entry maze.
    #[error("re-entry maze error: {0}")]
    Maze(#[from] MazeError),
}

/// Error type returned by KL-7 public encryption/decryption operations.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum Kl7Error {
    /// An electrical conduction error occurred in the re-entry maze.
    #[error("maze error: {0}")]
    Maze(#[from] MazeError),
    /// An unsupported or invalid character was encountered.
    #[error("invalid character: '{0}'")]
    InvalidCharacter(char),
    /// A text layer formatting or validation error occurred.
    #[error("text error: {0}")]
    Text(#[from] TextError),
}
