//! SIGABA 10-contact index rotor and five-wheel index bank.
//!
//! The index rotors are electrically and mechanically distinct from the
//! 26-contact cipher/control rotors:
//!
//! - 10 contacts numbered `0..9`;
//! - fixed position during message processing;
//! - no reversed-orientation handling in the CSP-889 model at this stage.
//!
//! Each mounted wheel at position `p` implements:
//!
//! ```text
//! forward = P(x + p) - p
//! reverse = P^-1(x + p) - p
//! ```
//!
//! The five-wheel index bank composes these fixed-position permutations.
//! No stepping behavior is present here.

use super::{
    contact::{Contact10, Position10},
    data::{index_rotor, IndexRotorId},
    permutation::{Permutation, PermutationError},
};

/// One mounted 10-contact SIGABA index rotor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexRotor {
    wiring: Permutation<10>,
    position: Position10,
}

impl IndexRotor {
    /// Construct from a validated wiring and fixed visible position.
    #[must_use]
    pub(crate) const fn new(wiring: Permutation<10>, position: Position10) -> Self {
        Self { wiring, position }
    }

    /// Construct one of the five historical SIGABA index rotors.
    pub(crate) fn from_reference(
        id: IndexRotorId,
        position: Position10,
    ) -> Result<Self, PermutationError> {
        Ok(Self::new(index_rotor(id)?, position))
    }

    /// Fixed visible index-wheel position.
    #[must_use]
    pub(crate) const fn position(&self) -> Position10 {
        self.position
    }

    /// Traverse the wheel in the source/forward direction.
    #[must_use]
    pub(crate) fn forward(&self, input: Contact10) -> Contact10 {
        let shifted = input.offset(i16::from(self.position.get()));
        let wired = self.wiring.forward(shifted.get());
        Contact10::new(wired)
            .expect("validated 10-contact permutation returned an in-range contact")
            .offset(-i16::from(self.position.get()))
    }

    /// Traverse the wheel in the inverse direction.
    #[must_use]
    pub(crate) fn reverse(&self, input: Contact10) -> Contact10 {
        let shifted = input.offset(i16::from(self.position.get()));
        let wired = self.wiring.inverse(shifted.get());
        Contact10::new(wired)
            .expect("validated 10-contact inverse returned an in-range contact")
            .offset(-i16::from(self.position.get()))
    }
}

/// Five fixed-position SIGABA index rotors.
///
/// Slot storage is left-to-right.  `forward()` traverses slots `0 -> 4`;
/// `reverse()` traverses slots `4 -> 0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct IndexBank {
    rotors: [IndexRotor; 5],
}

impl IndexBank {
    #[must_use]
    pub(crate) const fn new(rotors: [IndexRotor; 5]) -> Self {
        Self { rotors }
    }

    /// Traverse all five index wheels left-to-right.
    #[must_use]
    pub(crate) fn forward(&self, mut input: Contact10) -> Contact10 {
        for rotor in &self.rotors {
            input = rotor.forward(input);
        }
        input
    }

    /// Traverse all five index wheels right-to-left.
    #[must_use]
    pub(crate) fn reverse(&self, mut input: Contact10) -> Contact10 {
        for rotor in self.rotors.iter().rev() {
            input = rotor.reverse(input);
        }
        input
    }

    #[must_use]
    pub(crate) const fn rotor(&self, slot: usize) -> &IndexRotor {
        &self.rotors[slot]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(value: u8) -> Contact10 {
        Contact10::new(value).unwrap()
    }

    fn p(value: u8) -> Position10 {
        Position10::new(value).unwrap()
    }

    fn rotor(id: u8, pos: u8) -> IndexRotor {
        IndexRotor::from_reference(IndexRotorId::new(id).unwrap(), p(pos)).unwrap()
    }

    #[test]
    fn position_zero_matches_historical_wiring_exactly() {
        let rotor = rotor(0, 0);

        // Index rotor 1: 7591482630
        let expected = [7, 5, 9, 1, 4, 8, 2, 6, 3, 0];

        for input in 0..10 {
            assert_eq!(rotor.forward(c(input)).get(), expected[input as usize]);
        }
    }

    #[test]
    fn nonzero_position_uses_ten_contact_rotor_frame() {
        let rotor_0 = rotor(2, 0);
        let rotor_1 = rotor(2, 1);

        for input in 0..10 {
            let input = c(input);
            let expected = rotor_0.forward(input.offset(1)).offset(-1);
            assert_eq!(rotor_1.forward(input), expected);
        }
    }

    #[test]
    fn every_historical_index_rotor_is_bijective_at_every_position() {
        for id in IndexRotorId::ALL {
            for pos in 0..10 {
                let rotor = IndexRotor::from_reference(id, p(pos)).unwrap();
                let mut seen = [false; 10];

                for input in 0..10 {
                    let output = rotor.forward(c(input));
                    let index = usize::from(output.get());

                    assert!(
                        !seen[index],
                        "index rotor {} position {} duplicate output {}",
                        id.get(),
                        pos,
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
        for id in IndexRotorId::ALL {
            for pos in 0..10 {
                let rotor = IndexRotor::from_reference(id, p(pos)).unwrap();

                for input in 0..10 {
                    let input = c(input);

                    assert_eq!(
                        rotor.reverse(rotor.forward(input)),
                        input,
                        "forward/reverse mismatch index rotor {} pos {} input {}",
                        id.get(),
                        pos,
                        input.get()
                    );

                    assert_eq!(
                        rotor.forward(rotor.reverse(input)),
                        input,
                        "reverse/forward mismatch index rotor {} pos {} input {}",
                        id.get(),
                        pos,
                        input.get()
                    );
                }
            }
        }
    }

    #[test]
    fn five_wheel_bank_is_bijective() {
        let bank = IndexBank::new([
            rotor(0, 1),
            rotor(1, 2),
            rotor(2, 3),
            rotor(3, 4),
            rotor(4, 5),
        ]);

        let mut seen = [false; 10];

        for input in 0..10 {
            let output = bank.forward(c(input));
            let index = usize::from(output.get());
            assert!(!seen[index]);
            seen[index] = true;
        }

        assert!(seen.into_iter().all(|value| value));
    }

    #[test]
    fn five_wheel_bank_forward_and_reverse_are_inverses() {
        let bank = IndexBank::new([
            rotor(4, 9),
            rotor(2, 7),
            rotor(0, 5),
            rotor(3, 3),
            rotor(1, 1),
        ]);

        for input in 0..10 {
            let input = c(input);
            assert_eq!(bank.reverse(bank.forward(input)), input);
            assert_eq!(bank.forward(bank.reverse(input)), input);
        }
    }

    #[test]
    fn bank_traversal_order_is_explicit_and_stable() {
        let bank = IndexBank::new([
            rotor(0, 0),
            rotor(1, 0),
            rotor(2, 0),
            rotor(3, 0),
            rotor(4, 0),
        ]);

        for input in 0..10 {
            let mut expected = c(input);
            for id in 0..5 {
                expected = rotor(id, 0).forward(expected);
            }

            assert_eq!(bank.forward(c(input)), expected);
        }
    }

    #[test]
    fn rotor_accessor_preserves_slots_and_positions() {
        let bank = IndexBank::new([
            rotor(0, 9),
            rotor(1, 8),
            rotor(2, 7),
            rotor(3, 6),
            rotor(4, 5),
        ]);

        assert_eq!(bank.rotor(0).position(), p(9));
        assert_eq!(bank.rotor(1).position(), p(8));
        assert_eq!(bank.rotor(2).position(), p(7));
        assert_eq!(bank.rotor(3).position(), p(6));
        assert_eq!(bank.rotor(4).position(), p(5));
    }

    #[test]
    fn full_exhaustive_bank_composition_remains_invertible_over_position_grid() {
        // Exercise a representative but broad cross-section of all five-wheel
        // positions without making the test combinatorially huge.
        for base in 0..10 {
            let bank = IndexBank::new([
                rotor(0, base),
                rotor(1, (base + 1) % 10),
                rotor(2, (base + 2) % 10),
                rotor(3, (base + 3) % 10),
                rotor(4, (base + 4) % 10),
            ]);

            for input in 0..10 {
                let input = c(input);
                assert_eq!(bank.reverse(bank.forward(input)), input);
            }
        }
    }
}
