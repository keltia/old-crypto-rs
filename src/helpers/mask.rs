//! Trait to implement masking algorithms for disrupted transposition ciphers.
//!

pub trait TranspositionMask {
    fn mask(width: usize, rows: usize, order: &[usize]) -> Vec<bool>;
}


