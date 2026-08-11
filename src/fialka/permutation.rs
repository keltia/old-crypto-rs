//! Validated fixed-size permutations used by Fialka components.

use std::{error::Error, fmt};

use super::{CONTACT_COUNT, Contact};

/// Failure while constructing a fixed-size permutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PermutationError {
    /// A table entry is not a valid index for the permutation.
    OutOfRange {
        index: usize,
        value: u8,
        size: usize,
    },

    /// The same output value occurs more than once.
    Duplicate {
        value: u8,
        first_index: usize,
        second_index: usize,
    },

    /// A `u8` table cannot represent a permutation larger than 256 elements.
    TooLarge { size: usize },
}

impl fmt::Display for PermutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OutOfRange { index, value, size } => {
                write!(f, "permutation value {value} at index {index} is outside 0..{size}")
            }
            Self::Duplicate {
                value,
                first_index,
                second_index,
            } => write!(
                f,
                "permutation value {value} occurs at both indices {first_index} and {second_index}"
            ),
            Self::TooLarge { size } => write!(
                f,
                "permutation size {size} cannot be represented by u8 entries"
            ),
        }
    }
}

impl Error for PermutationError {}

/// A validated permutation and its precomputed inverse.
///
/// Construction performs all range and duplicate checks once.  Thereafter the
/// forward and inverse tables are guaranteed to be bijections over `0..N`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Permutation<const N: usize> {
    forward: [u8; N],
    inverse: [u8; N],
}

impl<const N: usize> Permutation<N> {
    /// Validate a mapping and construct its inverse table.
    pub(crate) fn new(forward: [u8; N]) -> Result<Self, PermutationError> {
        if N > usize::from(u8::MAX) + 1 {
            return Err(PermutationError::TooLarge { size: N });
        }

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

    /// Apply the permutation to an already validated index.
    #[must_use]
    pub(crate) fn forward(&self, input: usize) -> usize {
        usize::from(self.forward[input])
    }

    /// Apply the inverse permutation to an already validated index.
    #[must_use]
    pub(crate) fn inverse(&self, input: usize) -> usize {
        usize::from(self.inverse[input])
    }

    /// Access the forward table, primarily for reference-data tests.
    #[must_use]
    pub(crate) const fn as_array(&self) -> &[u8; N] {
        &self.forward
    }
}

impl Permutation<CONTACT_COUNT> {
    /// Apply a Fialka-sized permutation to a checked machine contact.
    #[must_use]
    pub(crate) fn forward_contact(&self, input: Contact) -> Contact {
        // A validated Permutation<30> can only return 0..29.
        Contact::new(self.forward(usize::from(input)) as u8).unwrap()
    }

    /// Apply the inverse Fialka-sized permutation to a checked machine contact.
    #[must_use]
    pub(crate) fn inverse_contact(&self, input: Contact) -> Contact {
        // A validated Permutation<30> can only return 0..29.
        Contact::new(self.inverse(usize::from(input)) as u8).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constructs_identity() {
        let mapping = std::array::from_fn(|index| index as u8);
        let permutation = Permutation::<30>::new(mapping).unwrap();

        assert_eq!(permutation.as_array(), &mapping);
        for input in 0..30 {
            assert_eq!(permutation.forward(input), input);
            assert_eq!(permutation.inverse(input), input);
        }
    }

    #[test]
    fn constructs_inverse() {
        let permutation = Permutation::<5>::new([2, 4, 1, 0, 3]).unwrap();

        assert_eq!(permutation.inverse(0), 3);
        assert_eq!(permutation.inverse(1), 2);
        assert_eq!(permutation.inverse(2), 0);
        assert_eq!(permutation.inverse(3), 4);
        assert_eq!(permutation.inverse(4), 1);
    }

    #[test]
    fn rejects_out_of_range_value() {
        let error = Permutation::<5>::new([0, 1, 2, 3, 5]).unwrap_err();

        assert_eq!(
            error,
            PermutationError::OutOfRange {
                index: 4,
                value: 5,
                size: 5,
            }
        );
    }

    #[test]
    fn rejects_duplicate_value() {
        let error = Permutation::<5>::new([0, 1, 2, 1, 4]).unwrap_err();

        assert_eq!(
            error,
            PermutationError::Duplicate {
                value: 1,
                first_index: 1,
                second_index: 3,
            }
        );
    }

    #[test]
    fn forward_and_inverse_cancel_exhaustively_for_fialka_contacts() {
        let mapping = std::array::from_fn(|index| ((index * 7) % CONTACT_COUNT) as u8);
        let permutation = Permutation::<CONTACT_COUNT>::new(mapping).unwrap();

        for value in 0..CONTACT_COUNT as u8 {
            let contact = Contact::new(value).unwrap();
            assert_eq!(
                permutation.inverse_contact(permutation.forward_contact(contact)),
                contact
            );
            assert_eq!(
                permutation.forward_contact(permutation.inverse_contact(contact)),
                contact
            );
        }
    }
}
