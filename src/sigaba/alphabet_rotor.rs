//! SIGABA 26-contact alphabet/control rotor.
//!
//! This layer models:
//! - one 26-contact rotor;
//! - normal or physically reversed insertion;
//! - fixed angular position;
//! - no stepping.
//!
//! The reversal equations follow the Pekelney ECM Mark II simulator, which was
//! derived from the surviving machine:
//!
//! ```text
//! normal forward : P(x + p) - p
//! normal reverse : P^-1(x + p) - p
//!
//! reversed forward : p - P^-1(p - x)
//! reversed reverse : p - P(p - x)
//! ```
//!
//! Physical reversal therefore is not equivalent to merely swapping `P` and
//! `P^-1`: the rotor's coordinate frame is reflected as well.
//!
//! Sources:
//! - Richard Pekelney's ECM Mark II simulator, as preserved/ported by
//!   Joe Dunn (`Rotor<N>::encrypt` / `decrypt`).
//! - Wing On Chan, *Cryptanalysis of SIGABA*, §2, for the physical description
//!   of normal/reversed insertion and visible alphabet direction.

use super::{
    contact::{Contact26, Position26},
    data::{large_rotor, LargeRotorId, LargeRotorSet},
    permutation::{Permutation, PermutationError},
};

/// Physical insertion orientation of a 26-contact SIGABA rotor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Orientation {
    /// Rotor inserted normally; lettering is upright to the operator.
    #[default]
    Normal,
    /// Rotor physically flipped over; lettering appears upside down.
    Reversed,
}

/// One mounted 26-contact SIGABA rotor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AlphabetRotor {
    wiring: Permutation<26>,
    position: Position26,
    orientation: Orientation,
}

impl AlphabetRotor {
    /// Construct a mounted rotor from a validated wiring.
    #[must_use]
    pub(crate) const fn new(
        wiring: Permutation<26>,
        position: Position26,
        orientation: Orientation,
    ) -> Self {
        Self {
            wiring,
            position,
            orientation,
        }
    }

    /// Construct one rotor from a named reference data set.
    pub(crate) fn from_reference(
        set: LargeRotorSet,
        id: LargeRotorId,
        position: Position26,
        orientation: Orientation,
    ) -> Result<Self, PermutationError> {
        Ok(Self::new(
            large_rotor(set, id)?,
            position,
            orientation,
        ))
    }

    /// Current visible position.
    #[must_use]
    pub(crate) const fn position(&self) -> Position26 {
        self.position
    }

    /// Physical insertion orientation.
    #[must_use]
    pub(crate) const fn orientation(&self) -> Orientation {
        self.orientation
    }

    /// Advance this mounted rotor by one mechanical step.
    ///
    /// SIGABA's visible alphabet moves in opposite directions depending on
    /// physical insertion:
    ///
    /// - normal:   O -> N -> M ...
    /// - reversed: O -> P -> Q ...
    ///
    /// The electrical transform already interprets `position` in the mounted
    /// rotor's visible coordinate frame, so stepping changes only that value.
    pub(crate) fn step(&mut self) {
        let amount = match self.orientation {
            Orientation::Normal => -1,
            Orientation::Reversed => 1,
        };
        self.position = self.position.offset(amount);
    }

    /// Transform in the source/forward electrical direction.
    #[must_use]
    pub(crate) fn forward(&self, input: Contact26) -> Contact26 {
        match self.orientation {
            Orientation::Normal => {
                // P(x + p) - p
                let shifted = input.offset(i16::from(self.position.get()));
                let wired = self.wiring.forward(shifted.get());
                c(wired).offset(-i16::from(self.position.get()))
            }
            Orientation::Reversed => {
                // p - P^-1(p - x)
                let reflected =
                    c(self.position.get()).offset(-i16::from(input.get()));
                let wired = self.wiring.inverse(reflected.get());
                c(self.position.get()).offset(-i16::from(wired))
            }
        }
    }

    /// Transform in the inverse electrical direction.
    #[must_use]
    pub(crate) fn reverse(&self, input: Contact26) -> Contact26 {
        match self.orientation {
            Orientation::Normal => {
                // P^-1(x + p) - p
                let shifted = input.offset(i16::from(self.position.get()));
                let wired = self.wiring.inverse(shifted.get());
                c(wired).offset(-i16::from(self.position.get()))
            }
            Orientation::Reversed => {
                // p - P(p - x)
                let reflected =
                    c(self.position.get()).offset(-i16::from(input.get()));
                let wired = self.wiring.forward(reflected.get());
                c(self.position.get()).offset(-i16::from(wired))
            }
        }
    }
}

fn c(value: u8) -> Contact26 {
    Contact26::new(value)
        .expect("validated 26-contact permutation returned an in-range contact")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(value: u8) -> Contact26 {
        Contact26::new(value).unwrap()
    }

    fn position(value: u8) -> Position26 {
        Position26::new(value).unwrap()
    }

    fn rotor(id: u8, pos: u8, orientation: Orientation) -> AlphabetRotor {
        AlphabetRotor::from_reference(
            LargeRotorSet::PekelneyReference,
            LargeRotorId::new(id).unwrap(),
            position(pos),
            orientation,
        )
        .unwrap()
    }

    #[test]
    fn normal_position_a_is_exactly_the_underlying_permutation() {
        let rotor = rotor(0, 0, Orientation::Normal);

        // Rotor 0: YCHLQSUGBDIXNZKERPVJTAWFOM
        assert_eq!(rotor.forward(contact(0)).get(), b'Y' - b'A');
        assert_eq!(rotor.forward(contact(1)).get(), b'C' - b'A');
        assert_eq!(rotor.forward(contact(25)).get(), b'M' - b'A');
    }

    #[test]
    fn normal_nonzero_position_uses_rotor_frame_offset() {
        let rotor_a = rotor(0, 0, Orientation::Normal);
        let rotor_b = rotor(0, 1, Orientation::Normal);

        for input in 0..26 {
            let input = contact(input);
            let expected = rotor_a.forward(input.offset(1)).offset(-1);
            assert_eq!(rotor_b.forward(input), expected);
        }
    }

    #[test]
    fn reversed_position_a_uses_reflected_inverse_wiring() {
        let reversed = rotor(0, 0, Orientation::Reversed);

        // Independent hand/reference checks from:
        //   y = -P^-1(-x) mod 26
        assert_eq!(reversed.forward(contact(0)).get(), 5);  // A -> F
        assert_eq!(reversed.forward(contact(1)).get(), 13); // B -> N
        assert_eq!(reversed.forward(contact(14)).get(), 1); // O -> B
        assert_eq!(reversed.forward(contact(25)).get(), 18); // Z -> S
    }

    #[test]
    fn reversed_nonzero_position_matches_reference_equation() {
        let reversed = rotor(0, 14, Orientation::Reversed);

        // p=O(14), y = p - P^-1(p-x)
        assert_eq!(reversed.forward(contact(0)).get(), 16);  // A -> Q
        assert_eq!(reversed.forward(contact(1)).get(), 2);   // B -> C
        assert_eq!(reversed.forward(contact(14)).get(), 19); // O -> T
        assert_eq!(reversed.forward(contact(25)).get(), 23); // Z -> X

        // inverse path: p - P(p-x)
        assert_eq!(reversed.reverse(contact(0)).get(), 4);   // A -> E
        assert_eq!(reversed.reverse(contact(1)).get(), 15);  // B -> P
        assert_eq!(reversed.reverse(contact(14)).get(), 16); // O -> Q
        assert_eq!(reversed.reverse(contact(25)).get(), 10); // Z -> K
    }

    #[test]
    fn reversed_is_not_merely_normal_inverse() {
        let normal = rotor(0, 0, Orientation::Normal);
        let reversed = rotor(0, 0, Orientation::Reversed);

        // This is a regression guard against implementing physical reversal as
        // simply P^-1(x).
        assert_ne!(reversed.forward(contact(1)), normal.reverse(contact(1)));
    }

    #[test]
    fn every_reference_rotor_is_bijective_in_both_orientations_and_positions() {
        for id in LargeRotorId::ALL {
            for orientation in [Orientation::Normal, Orientation::Reversed] {
                for pos in 0..26 {
                    let rotor = AlphabetRotor::from_reference(
                        LargeRotorSet::PekelneyReference,
                        id,
                        position(pos),
                        orientation,
                    )
                    .unwrap();

                    let mut seen = [false; 26];

                    for input in 0..26 {
                        let output = rotor.forward(contact(input));
                        let index = usize::from(output.get());
                        assert!(
                            !seen[index],
                            "rotor {} {:?} position {} duplicate output {}",
                            id.get(),
                            orientation,
                            pos,
                            output.get()
                        );
                        seen[index] = true;
                    }

                    assert!(seen.into_iter().all(|value| value));
                }
            }
        }
    }

    #[test]
    fn forward_and_reverse_are_exhaustive_inverses_for_both_orientations() {
        for id in LargeRotorId::ALL {
            for orientation in [Orientation::Normal, Orientation::Reversed] {
                for pos in 0..26 {
                    let rotor = AlphabetRotor::from_reference(
                        LargeRotorSet::PekelneyReference,
                        id,
                        position(pos),
                        orientation,
                    )
                    .unwrap();

                    for input in 0..26 {
                        let input = contact(input);
                        assert_eq!(
                            rotor.reverse(rotor.forward(input)),
                            input,
                            "forward/reverse mismatch rotor {} {:?} position {} input {}",
                            id.get(),
                            orientation,
                            pos,
                            input.get()
                        );
                        assert_eq!(
                            rotor.forward(rotor.reverse(input)),
                            input,
                            "reverse/forward mismatch rotor {} {:?} position {} input {}",
                            id.get(),
                            orientation,
                            pos,
                            input.get()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn accessors_preserve_mounting_state() {
        for orientation in [Orientation::Normal, Orientation::Reversed] {
            for pos in 0..26 {
                let rotor = rotor(4, pos, orientation);
                assert_eq!(rotor.position(), position(pos));
                assert_eq!(rotor.orientation(), orientation);
            }
        }
    }
    #[test]
    fn normal_rotor_steps_in_decreasing_visible_alphabet_direction() {
        let mut rotor = rotor(0, 14, Orientation::Normal); // O
        rotor.step();
        assert_eq!(rotor.position(), position(13)); // N
        rotor.step();
        assert_eq!(rotor.position(), position(12)); // M
    }

    #[test]
    fn reversed_rotor_steps_in_increasing_visible_alphabet_direction() {
        let mut rotor = rotor(0, 14, Orientation::Reversed); // O
        rotor.step();
        assert_eq!(rotor.position(), position(15)); // P
        rotor.step();
        assert_eq!(rotor.position(), position(16)); // Q
    }

    #[test]
    fn stepping_wraps_in_both_orientations() {
        let mut normal = rotor(0, 0, Orientation::Normal);
        normal.step();
        assert_eq!(normal.position(), position(25));

        let mut reversed = rotor(0, 25, Orientation::Reversed);
        reversed.step();
        assert_eq!(reversed.position(), position(0));
    }

}
