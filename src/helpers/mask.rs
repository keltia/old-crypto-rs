//!

/// Trait to implement masking algorithms for transposition ciphers.
///
pub trait TranspositionMask {
    fn mask(width: usize, rows: usize, order: &[usize]) -> Vec<bool>;
}

