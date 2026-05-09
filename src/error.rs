
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("failed to derive transposition widths")]
    BadDerivationKey,
    #[error("failed to derive keys")]
    BadKeyStream,
    #[error("checkerboard symbols exhausted")]
    CheckerboardExhausted,
    #[error("{0} digits expected")]
    DigitsExpected(usize),
    #[error("Empty input")]
    EmptyInput,
    #[error("Keys must be not be empty")]
    EmptyKeys,
    #[error("Incompatible variants, like 5x5 but Latin36.")]
    IncompatibleVariants,
    #[error("Key must be at least {0} characters long")]
    KeyTooShort(usize),
    #[error("Alphabet must be {0} characters long")]
    AlphabetTooShort(usize),
    #[error("Every input must have the same length: {0} vs {1}")]
    LengthMismatch(usize, usize),
    #[error("Input {0} must be at least {1} characters long")]
    TooShort(usize, usize),
    #[error("Failed to generate rows")]
    RowGenerationFailed,
}

