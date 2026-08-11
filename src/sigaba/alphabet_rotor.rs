//! Fixed-position normal-orientation SIGABA large rotor.
//!
//! Step 4 deliberately models only the simplest electrical case:
//! - one 26-contact rotor;
//! - normal physical insertion;
//! - fixed angular position;
//! - no stepping.
//!
//! Reversed insertion and orientation-sensitive stepping are added in later
//! steps once their coordinate conventions are independently verified.

use super::{
    contact::{Contact26, Position26},
    data::{large_rotor, LargeRotorId, LargeRotorSet},
    permutation::{Permutation, PermutationError},
};

/// One mounted 26-contact SIGABA rotor in normal orientation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AlphabetRotor {
    wiring: Permutation<26>,
    position: Position26,
}

impl AlphabetRotor {
    /// Construct a rotor from a validated permutation and visible position.
    #[must_use]
    pub(crate) const fn new(wiring: Permutation<26>, position: Position26) -> Self {
        Self { wiring, position }
    }

    /// Construct one rotor from a named reference data set.
    pub(crate) fn from_reference(
        set: LargeRotorSet,
        id: LargeRotorId,
        position: Position26,
    ) -> Result<Self, PermutationError> {
        Ok(Self::new(large_rotor(set, id)?, position))
    }

    /// Current visible position.
    #[must_use]
    pub(crate) const fn position(&self) -> Position26 {
        self.position
    }

    /// Transform from the rotor's input side to its output side.
    ///
    /// With normal insertion and `A=0`, a rotor at visible position `p`
    /// implements:
    ///
    /// ```text
    /// out = P(in + p) - p
    /// ```
    #[must_use]
    pub(crate) fn forward(&self, input: Contact26) -> Contact26 {
        let shifted = input.offset(i16::from(self.position.get()));
        let wired = self.wiring.forward(shifted.get());
        Contact26::new(wired)
            .expect("validated 26-contact permutation returned an in-range contact")
            .offset(-i16::from(self.position.get()))
    }

    /// Transform in the inverse electrical direction.
    ///
    /// This is the exact inverse of [`Self::forward`]:
    ///
    /// ```text
    /// out = P^-1(in + p) - p
    /// ```
    #[must_use]
    pub(crate) fn reverse(&self, input: Contact26) -> Contact26 {
        let shifted = input.offset(i16::from(self.position.get()));
        let wired = self.wiring.inverse(shifted.get());
        Contact26::new(wired)
            .expect("validated 26-contact inverse returned an in-range contact")
            .offset(-i16::from(self.position.get()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigaba::data::{LargeRotorId, LargeRotorSet};

    fn c(value: u8) -> Contact26 {
        Contact26::new(value).unwrap()
    }

    fn p(value: u8) -> Position26 {
        Position26::new(value).unwrap()
    }

    #[test]
    fn position_a_is_exactly_the_underlying_permutation() {
        let rotor = AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(0).unwrap(),
            Position26::A,
        )
        .unwrap();

        // Rotor 0 begins Y C H ... M.
        assert_eq!(rotor.forward(c(0)).get(), b'Y' - b'A');
        assert_eq!(rotor.forward(c(1)).get(), b'C' - b'A');
        assert_eq!(rotor.forward(c(25)).get(), b'M' - b'A');
    }

    #[test]
    fn reverse_at_position_a_is_the_permutation_inverse() {
        let rotor = AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(0).unwrap(),
            Position26::A,
        )
        .unwrap();

        for input in 0..26 {
            let input = c(input);
            assert_eq!(rotor.reverse(rotor.forward(input)), input);
        }
    }

    #[test]
    fn nonzero_position_uses_rotor_frame_offset() {
        let rotor_a = AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(0).unwrap(),
            p(0),
        )
        .unwrap();
        let rotor_b = AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(0).unwrap(),
            p(1),
        )
        .unwrap();

        for input in 0..26 {
            let input = c(input);

            // P_p(x) = P_0(x+p)-p
            let expected = rotor_a.forward(input.offset(1)).offset(-1);
            assert_eq!(rotor_b.forward(input), expected);
        }
    }

    #[test]
    fn every_reference_rotor_is_bijective_at_every_position() {
        for id in LargeRotorId::ALL {
            for position in 0..26 {
                let rotor = AlphabetRotor::from_reference(
                    LargeRotorSet::PekelneyReference,
                    id,
                    p(position),
                )
                .unwrap();

                let mut seen = [false; 26];

                for input in 0..26 {
                    let output = rotor.forward(c(input));
                    let index = usize::from(output.get());
                    assert!(
                        !seen[index],
                        "rotor {} position {} produced duplicate output {}",
                        id.get(),
                        position,
                        output.get()
                    );
                    seen[index] = true;
                }

                assert!(seen.into_iter().all(|value| value));
            }
        }
    }

    #[test]
    fn forward_and_reverse_are_exhaustive_inverses() {
        for id in LargeRotorId::ALL {
            for position in 0..26 {
                let rotor = AlphabetRotor::from_reference(
                    LargeRotorSet::PekelneyReference,
                    id,
                    p(position),
                )
                .unwrap();

                for input in 0..26 {
                    let input = c(input);
                    assert_eq!(
                        rotor.reverse(rotor.forward(input)),
                        input,
                        "forward/reverse mismatch for rotor {} position {} input {}",
                        id.get(),
                        position,
                        input.get()
                    );
                    assert_eq!(
                        rotor.forward(rotor.reverse(input)),
                        input,
                        "reverse/forward mismatch for rotor {} position {} input {}",
                        id.get(),
                        position,
                        input.get()
                    );
                }
            }
        }
    }

    #[test]
    fn position_accessor_preserves_the_visible_setting() {
        for position in 0..26 {
            let rotor = AlphabetRotor::from_reference(
                LargeRotorSet::PekelneyReference,
                LargeRotorId::new(4).unwrap(),
                p(position),
            )
            .unwrap();

            assert_eq!(rotor.position(), p(position));
        }
    }
}
