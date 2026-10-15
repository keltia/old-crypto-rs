//! Validated fixed-size permutations used by cipher components and rotor wirings.

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
///
/// Construction performs all range and duplicate checks once. Thereafter the
/// forward and inverse tables are guaranteed to be bijections over `0..N`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Permutation<const N: usize> {
    forward: [u8; N],
    inverse: [u8; N],
}

impl<const N: usize> Permutation<N> {
    /// Validate a mapping and precompute its inverse table.
    pub fn new(forward: [u8; N]) -> Result<Self, PermutationError> {
        assert!(N <= usize::from(u8::MAX) + 1, "permutation size exceeds u8 representation");

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
            inverse[output] = index as u8;
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

    /// Access the forward table (alias for `mapping`).
    #[must_use]
    pub const fn as_array(&self) -> &[u8; N] {
        &self.forward
    }

    /// Access the inverse table (alias for `inverse_mapping`).
    #[must_use]
    pub const fn as_inverse_array(&self) -> &[u8; N] {
        &self.inverse
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_permutations_work_for_various_sizes() {
        let p10 = Permutation::<10>::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        let p26 = Permutation::<26>::new([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
            13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        ])
        .unwrap();

        for input in 0..10_u8 {
            assert_eq!(p10.forward(input), input);
            assert_eq!(p10.inverse(input), input);
        }

        for input in 0..26_u8 {
            assert_eq!(p26.forward(input), input);
            assert_eq!(p26.inverse(input), input);
        }
    }

    #[test]
    fn inverse_is_precomputed_correctly() {
        let p = Permutation::<10>::new([9, 0, 8, 1, 7, 2, 6, 3, 5, 4]).unwrap();

        for input in 0..10_u8 {
            let output = p.forward(input);
            assert_eq!(p.inverse(output), input);
        }
    }

    #[test]
    fn round_trip_for_36_permutation() {
        let mut id = [0_u8; 36];
        for (i, val) in id.iter_mut().enumerate() {
            *val = i as u8;
        }
        let p = Permutation::<36>::new(id).unwrap();
        for i in 0..36_u8 {
            assert_eq!(p.forward(i), i);
            assert_eq!(p.inverse(i), i);
        }
    }

    #[test]
    fn duplicate_values_report_both_indices() {
        let error = Permutation::<10>::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 8]).unwrap_err();

        assert_eq!(
            error,
            PermutationError::Duplicate {
                value: 8,
                first_index: 8,
                second_index: 9,
            }
        );
    }

    #[test]
    fn out_of_range_values_report_source_index() {
        let error = Permutation::<10>::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 10]).unwrap_err();

        assert_eq!(
            error,
            PermutationError::OutOfRange {
                index: 9,
                value: 10,
                size: 10,
            }
        );
    }

    #[test]
    fn mappings_accessible_via_methods() {
        let mapping = [1, 2, 3, 4, 5, 6, 7, 8, 9, 0];
        let p = Permutation::<10>::new(mapping).unwrap();

        assert_eq!(p.mapping(), &mapping);
        assert_eq!(p.as_array(), &mapping);
        assert_eq!(p.inverse_mapping(), &[9, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(p.as_inverse_array(), &[9, 0, 1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
