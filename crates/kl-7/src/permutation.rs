//! Validated fixed-size permutations used by KL-7 rotor and baseplate wiring.

use core::fmt;

/// Error returned when constructing an invalid fixed-size permutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermutationError {
    /// A value was outside the permutation's `0..N` coordinate system.
    OutOfRange {
        index: usize,
        value: u8,
        size: usize,
    },
    /// The same output value appeared more than once.
    Duplicate {
        value: u8,
        first_index: usize,
        second_index: usize,
    },
}

impl fmt::Display for PermutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OutOfRange { index, value, size } => write!(
                f,
                "permutation value {value} at index {index} is outside 0..{size}"
            ),
            Self::Duplicate {
                value,
                first_index,
                second_index,
            } => write!(
                f,
                "permutation value {value} occurs at both indices {first_index} and {second_index}"
            ),
        }
    }
}

impl std::error::Error for PermutationError {}

/// A validated `N`-element permutation with a precomputed inverse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permutation<const N: usize> {
    forward: [u8; N],
    inverse: [u8; N],
}

impl<const N: usize> Permutation<N> {
    /// Validate a mapping and precompute its inverse.
    pub fn new(forward: [u8; N]) -> Result<Self, PermutationError> {
        assert!(N <= usize::from(u8::MAX) + 1);

        let mut inverse = [0_u8; N];
        let mut first_seen = [usize::MAX; N];

        for (index, &value) in forward.iter().enumerate() {
            let output = usize::from(value);

            if output >= N {
                return Err(PermutationError::OutOfRange {
                    index,
                    value,
                    size: N,
                });
            }

            if first_seen[output] != usize::MAX {
                return Err(PermutationError::Duplicate {
                    value,
                    first_index: first_seen[output],
                    second_index: index,
                });
            }

            first_seen[output] = index;
            inverse[output] = u8::try_from(index)
                .expect("permutation size is constrained to fit in u8");
        }

        Ok(Self { forward, inverse })
    }

    /// Apply the permutation in its source direction.
    #[must_use]
    pub const fn forward(&self, input: u8) -> u8 {
        self.forward[input as usize]
    }

    /// Apply the inverse permutation.
    #[must_use]
    pub const fn inverse(&self, input: u8) -> u8 {
        self.inverse[input as usize]
    }

    /// Return the validated forward mapping.
    #[must_use]
    pub const fn mapping(&self) -> &[u8; N] {
        &self.forward
    }

    /// Return the precomputed inverse mapping.
    #[must_use]
    pub const fn inverse_mapping(&self) -> &[u8; N] {
        &self.inverse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_36_permutation() {
        let mut id = [0_u8; 36];
        for (i, val) in id.iter_mut().enumerate() {
            *val = i as u8;
        }
        let p = Permutation::<36>::new(id).unwrap();
        for i in 0..36 {
            assert_eq!(p.forward(i as u8), i as u8);
            assert_eq!(p.inverse(i as u8), i as u8);
        }
    }

    #[test]
    fn permutation_detects_duplicate() {
        let mut bad = [0_u8; 36];
        for (i, val) in bad.iter_mut().enumerate() {
            *val = i as u8;
        }
        bad[35] = 0; // duplicate 0
        assert!(matches!(
            Permutation::<36>::new(bad),
            Err(PermutationError::Duplicate { .. })
        ));
    }

    #[test]
    fn permutation_detects_out_of_range() {
        let mut bad = [0_u8; 36];
        for (i, val) in bad.iter_mut().enumerate() {
            *val = i as u8;
        }
        bad[0] = 36;
        assert!(matches!(
            Permutation::<36>::new(bad),
            Err(PermutationError::OutOfRange { .. })
        ));
    }
}
