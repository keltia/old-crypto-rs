//! Simulation of the Japanese PURPLE (Angooki Taipu B) cipher machine.
//!
//! Typed contacts, switch positions, and shared validated permutations are provided.
//! Stateful message operation and the public API will follow.

#![forbid(unsafe_code)]

mod alphabet;
mod contact;
mod config;
mod core;
mod motion;
mod machine;
pub mod data;
mod position;
mod public;
mod switch;
mod stepping;

pub use alphabet::{AlphabetContact, AlphabetError, PurpleAlphabet};
pub use core::PurpleCore;
pub use config::PurpleConfig;
pub use public::Purple;
pub use contact::{ContactError, SixesContact, TwentiesContact};
pub use motion::{MotionError, PurpleMotion};
pub use machine::PurpleMachine;
pub use position::{PositionError, SwitchPosition, TwentiesSwitchId};
pub use switch::{SixesSwitch, TwentiesSwitch};
pub use stepping::PurpleStepping;
pub use old_crypto_rs::helpers::{Permutation, PermutationError};

/// Validated permutation for one position of the sixes switch.
pub type SixesPermutation = Permutation<6>;
/// Validated permutation for one position of a twenties switch.
pub type TwentiesPermutation = Permutation<20>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_smoke_test() {
        assert_eq!(env!("CARGO_PKG_NAME"), "purple");
    }

    #[test]
    fn shared_sixes_permutation_round_trip() {
        let mapping = [3, 0, 5, 1, 4, 2];
        let permutation = SixesPermutation::new(mapping).unwrap();
        assert_eq!(permutation.mapping(), &mapping);
        for contact in 0..6 {
            assert_eq!(permutation.inverse(permutation.forward(contact)), contact);
        }
    }

    #[test]
    fn shared_twenties_permutation_round_trip() {
        let mapping = std::array::from_fn(|i| ((i + 7) % 20) as u8);
        let permutation = TwentiesPermutation::new(mapping).unwrap();
        for contact in 0..20 {
            assert_eq!(permutation.inverse(permutation.forward(contact)), contact);
        }
    }

    #[test]
    fn shared_validation_rejects_duplicate_and_out_of_range() {
        assert!(matches!(
            SixesPermutation::new([0, 1, 2, 3, 4, 4]),
            Err(PermutationError::Duplicate { .. })
        ));
        assert!(matches!(
            SixesPermutation::new([0, 1, 2, 3, 4, 6]),
            Err(PermutationError::OutOfRange { .. })
        ));
    }
}
