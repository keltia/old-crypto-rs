//! Strongly typed CSP-889 key/configuration.
//!
//! A valid wartime ECM Mark II key has:
//!
//! - five large rotors in the cipher bank;
//! - the other five large rotors in the control bank;
//! - each large rotor identity `0..9` used exactly once overall;
//! - all five index rotors `0..4` used exactly once;
//! - one position and orientation per large rotor;
//! - one decimal position per index rotor.
//!
//! The typed IDs and position types enforce individual ranges.  This module
//! enforces the cross-bank uniqueness/partition invariants and constructs the
//! staged `SigabaCore` without exposing raw integer arrays.

use core::fmt;

use super::{
    alphabet_rotor::{AlphabetRotor, Orientation},
    cipher_bank::CipherBank,
    contact::{Position10, Position26},
    control_bank::ControlBank,
    data::{IndexRotorId, LargeRotorId},
    index_rotor::{IndexBank, IndexRotor},
    machine::SigabaCore,
    maze::SteppingMaze,
    rotor_set::RotorSet,
};

#[cfg(test)]
use super::data::LargeRotorSet;

/// One mounted 26-contact cipher/control rotor description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LargeRotorSetting {
    pub(crate) id: LargeRotorId,
    pub(crate) position: Position26,
    pub(crate) orientation: Orientation,
}

impl LargeRotorSetting {
    #[must_use]
    pub const fn new(
        id: LargeRotorId,
        position: Position26,
        orientation: Orientation,
    ) -> Self {
        Self {
            id,
            position,
            orientation,
        }
    }
}

/// One mounted 10-contact index rotor description.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexRotorSetting {
    pub(crate) id: IndexRotorId,
    pub(crate) position: Position10,
}

impl IndexRotorSetting {
    #[must_use]
    pub const fn new(id: IndexRotorId, position: Position10) -> Self {
        Self { id, position }
    }
}

/// Invalid SIGABA key/configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A large rotor appears more than once across cipher/control banks.
    DuplicateLargeRotor {
        id: LargeRotorId,
        first_bank: LargeRotorBank,
        first_slot: usize,
        second_bank: LargeRotorBank,
        second_slot: usize,
    },
    /// An index rotor appears in more than one index slot.
    DuplicateIndexRotor {
        id: IndexRotorId,
        first_slot: usize,
        second_slot: usize,
    },
    /// A validated reference wiring could not be constructed.
    InvalidReferenceWiring,
}

/// Which 26-contact bank contains a large rotor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LargeRotorBank {
    Cipher,
    Control,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DuplicateLargeRotor {
                id,
                first_bank,
                first_slot,
                second_bank,
                second_slot,
            } => write!(
                f,
                "large rotor {} is duplicated in {:?} slot {} and {:?} slot {}",
                id.get(),
                first_bank,
                first_slot + 1,
                second_bank,
                second_slot + 1,
            ),
            Self::DuplicateIndexRotor {
                id,
                first_slot,
                second_slot,
            } => write!(
                f,
                "index rotor {} is duplicated in slots {} and {}",
                id.get(),
                first_slot + 1,
                second_slot + 1,
            ),
            Self::InvalidReferenceWiring => {
                f.write_str("SIGABA reference rotor wiring is invalid")
            }
        }
    }
}

impl std::error::Error for ConfigError {}

/// Complete validated CSP-889 rotor key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigabaConfig {
    rotor_set: RotorSet,
    cipher: [LargeRotorSetting; 5],
    control: [LargeRotorSetting; 5],
    index: [IndexRotorSetting; 5],
}

impl SigabaConfig {
    /// Validate and construct a complete key.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when a large or index rotor identity is used
    /// more than once.
    pub fn new<R: Into<RotorSet>>(
        rotor_set: R,
        cipher: [LargeRotorSetting; 5],
        control: [LargeRotorSetting; 5],
        index: [IndexRotorSetting; 5],
    ) -> Result<Self, ConfigError> {
        validate_large_partition(&cipher, &control)?;
        validate_index_permutation(&index)?;

        Ok(Self {
            rotor_set: rotor_set.into(),
            cipher,
            control,
            index,
        })
    }

    /// Build a fresh mutable machine at this key's initial state.
    pub(crate) fn build_core(&self) -> SigabaCore {
        let cipher = CipherBank::new([
            Self::build_large(self.cipher[0]),
            Self::build_large(self.cipher[1]),
            Self::build_large(self.cipher[2]),
            Self::build_large(self.cipher[3]),
            Self::build_large(self.cipher[4]),
        ]);

        let control = ControlBank::new([
            Self::build_large(self.control[0]),
            Self::build_large(self.control[1]),
            Self::build_large(self.control[2]),
            Self::build_large(self.control[3]),
            Self::build_large(self.control[4]),
        ]);

        let index = IndexBank::new([
            self.build_index(self.index[0]),
            self.build_index(self.index[1]),
            self.build_index(self.index[2]),
            self.build_index(self.index[3]),
            self.build_index(self.index[4]),
        ]);

        SigabaCore::new(
            cipher,
            SteppingMaze::new(control, index),
        )
    }

    #[must_use]
    pub const fn cipher_settings(&self) -> &[LargeRotorSetting; 5] {
        &self.cipher
    }

    #[must_use]
    pub const fn control_settings(&self) -> &[LargeRotorSetting; 5] {
        &self.control
    }

    #[must_use]
    pub const fn index_settings(&self) -> &[IndexRotorSetting; 5] {
        &self.index
    }

    #[must_use]
    pub fn rotor_set(&self) -> &RotorSet {
        &self.rotor_set
    }

    fn build_large(setting: LargeRotorSetting) -> AlphabetRotor {
        AlphabetRotor::new(
            setting.id,
            setting.position,
            setting.orientation,
        )
    }

    fn build_index(&self, setting: IndexRotorSetting) -> IndexRotor {
        IndexRotor::new(
            self.rotor_set.index_rotor(setting.id),
            setting.position,
        )
    }
}

fn validate_large_partition(
    cipher: &[LargeRotorSetting; 5],
    control: &[LargeRotorSetting; 5],
) -> Result<(), ConfigError> {
    let mut seen: [Option<(LargeRotorBank, usize)>; 10] = [None; 10];

    for (bank, settings) in [
        (LargeRotorBank::Cipher, cipher),
        (LargeRotorBank::Control, control),
    ] {
        for (slot, setting) in settings.iter().enumerate() {
            let idx = usize::from(setting.id.get());

            if let Some((first_bank, first_slot)) = seen[idx] {
                return Err(ConfigError::DuplicateLargeRotor {
                    id: setting.id,
                    first_bank,
                    first_slot,
                    second_bank: bank,
                    second_slot: slot,
                });
            }

            seen[idx] = Some((bank, slot));
        }
    }

    // There are exactly ten slots and each ID is range-checked to 0..9.
    // Therefore uniqueness implies that all ten identities are present exactly
    // once; no separate "missing rotor" state can exist.
    debug_assert!(seen.into_iter().all(|entry| entry.is_some()));

    Ok(())
}

fn validate_index_permutation(
    index: &[IndexRotorSetting; 5],
) -> Result<(), ConfigError> {
    let mut seen: [Option<usize>; 5] = [None; 5];

    for (slot, setting) in index.iter().enumerate() {
        let idx = usize::from(setting.id.get());

        if let Some(first_slot) = seen[idx] {
            return Err(ConfigError::DuplicateIndexRotor {
                id: setting.id,
                first_slot,
                second_slot: slot,
            });
        }

        seen[idx] = Some(slot);
    }

    // Five slots, five possible typed identities: uniqueness implies exact
    // coverage.
    debug_assert!(seen.into_iter().all(|entry| entry.is_some()));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lid(value: u8) -> LargeRotorId {
        LargeRotorId::new(value).unwrap()
    }

    fn iid(value: u8) -> IndexRotorId {
        IndexRotorId::new(value).unwrap()
    }

    fn p26(value: u8) -> Position26 {
        Position26::new(value).unwrap()
    }

    fn p10(value: u8) -> Position10 {
        Position10::new(value).unwrap()
    }

    fn large(
        id: u8,
        position: u8,
        orientation: Orientation,
    ) -> LargeRotorSetting {
        LargeRotorSetting::new(lid(id), p26(position), orientation)
    }

    fn idx(id: u8, position: u8) -> IndexRotorSetting {
        IndexRotorSetting::new(iid(id), p10(position))
    }

    fn valid_config() -> SigabaConfig {
        SigabaConfig::new(
            LargeRotorSet::PekelneyReference,
            [
                large(0, 0, Orientation::Normal),
                large(1, 1, Orientation::Reversed),
                large(2, 2, Orientation::Normal),
                large(3, 3, Orientation::Reversed),
                large(4, 4, Orientation::Normal),
            ],
            [
                large(5, 5, Orientation::Reversed),
                large(6, 6, Orientation::Normal),
                large(7, 7, Orientation::Reversed),
                large(8, 8, Orientation::Normal),
                large(9, 9, Orientation::Reversed),
            ],
            [
                idx(0, 9),
                idx(1, 8),
                idx(2, 7),
                idx(3, 6),
                idx(4, 5),
            ],
        )
        .unwrap()
    }

    #[test]
    fn valid_partition_builds_machine_with_requested_positions() {
        let config = valid_config();
        let core = config.build_core();

        assert_eq!(core.cipher_positions(), [0, 1, 2, 3, 4]);
        assert_eq!(core.control_positions(), [5, 6, 7, 8, 9]);
    }

    #[test]
    fn duplicate_within_cipher_bank_is_rejected() {
        let result = SigabaConfig::new(
            LargeRotorSet::PekelneyReference,
            [
                large(0, 0, Orientation::Normal),
                large(0, 1, Orientation::Normal),
                large(2, 2, Orientation::Normal),
                large(3, 3, Orientation::Normal),
                large(4, 4, Orientation::Normal),
            ],
            [
                large(5, 0, Orientation::Normal),
                large(6, 0, Orientation::Normal),
                large(7, 0, Orientation::Normal),
                large(8, 0, Orientation::Normal),
                large(9, 0, Orientation::Normal),
            ],
            [
                idx(0, 0),
                idx(1, 0),
                idx(2, 0),
                idx(3, 0),
                idx(4, 0),
            ],
        );

        assert_eq!(
            result,
            Err(ConfigError::DuplicateLargeRotor {
                id: lid(0),
                first_bank: LargeRotorBank::Cipher,
                first_slot: 0,
                second_bank: LargeRotorBank::Cipher,
                second_slot: 1,
            }),
        );
    }

    #[test]
    fn duplicate_across_cipher_and_control_is_rejected() {
        let result = SigabaConfig::new(
            LargeRotorSet::PekelneyReference,
            [
                large(0, 0, Orientation::Normal),
                large(1, 0, Orientation::Normal),
                large(2, 0, Orientation::Normal),
                large(3, 0, Orientation::Normal),
                large(4, 0, Orientation::Normal),
            ],
            [
                large(4, 0, Orientation::Normal),
                large(6, 0, Orientation::Normal),
                large(7, 0, Orientation::Normal),
                large(8, 0, Orientation::Normal),
                large(9, 0, Orientation::Normal),
            ],
            [
                idx(0, 0),
                idx(1, 0),
                idx(2, 0),
                idx(3, 0),
                idx(4, 0),
            ],
        );

        assert_eq!(
            result,
            Err(ConfigError::DuplicateLargeRotor {
                id: lid(4),
                first_bank: LargeRotorBank::Cipher,
                first_slot: 4,
                second_bank: LargeRotorBank::Control,
                second_slot: 0,
            }),
        );
    }

    #[test]
    fn duplicate_index_rotor_is_rejected() {
        let result = SigabaConfig::new(
            LargeRotorSet::PekelneyReference,
            [
                large(0, 0, Orientation::Normal),
                large(1, 0, Orientation::Normal),
                large(2, 0, Orientation::Normal),
                large(3, 0, Orientation::Normal),
                large(4, 0, Orientation::Normal),
            ],
            [
                large(5, 0, Orientation::Normal),
                large(6, 0, Orientation::Normal),
                large(7, 0, Orientation::Normal),
                large(8, 0, Orientation::Normal),
                large(9, 0, Orientation::Normal),
            ],
            [
                idx(0, 0),
                idx(1, 0),
                idx(2, 0),
                idx(2, 0),
                idx(4, 0),
            ],
        );

        assert_eq!(
            result,
            Err(ConfigError::DuplicateIndexRotor {
                id: iid(2),
                first_slot: 2,
                second_slot: 3,
            }),
        );
    }

    #[test]
    fn slot_order_and_mounting_metadata_are_preserved() {
        let config = valid_config();

        assert_eq!(config.cipher_settings()[1].id, lid(1));
        assert_eq!(
            config.cipher_settings()[1].orientation,
            Orientation::Reversed,
        );
        assert_eq!(config.cipher_settings()[1].position, p26(1));

        assert_eq!(config.control_settings()[0].id, lid(5));
        assert_eq!(
            config.control_settings()[0].orientation,
            Orientation::Reversed,
        );

        assert_eq!(config.index_settings()[0], idx(0, 9));
        assert_eq!(config.index_settings()[4], idx(4, 5));
    }

    #[test]
    fn two_machines_built_from_same_config_start_identically() {
        let config = valid_config();

        let mut left = config.build_core();
        let mut right = config.build_core();

        for value in 0..26 {
            let input = super::super::contact::Contact26::new(value).unwrap();
            assert_eq!(
                left.encipher_contact(input),
                right.encipher_contact(input),
            );
            assert_eq!(left.cipher_positions(), right.cipher_positions());
            assert_eq!(left.control_positions(), right.control_positions());
        }
    }

    #[test]
    fn every_valid_large_partition_is_exactly_the_full_identity_set() {
        let config = valid_config();
        let mut seen = [false; 10];

        for setting in config
            .cipher_settings()
            .iter()
            .chain(config.control_settings())
        {
            seen[usize::from(setting.id.get())] = true;
        }

        assert!(seen.into_iter().all(|present| present));
    }

    #[test]
    fn every_valid_index_order_contains_all_five_identities() {
        let config = valid_config();
        let mut seen = [false; 5];

        for setting in config.index_settings() {
            seen[usize::from(setting.id.get())] = true;
        }

        assert!(seen.into_iter().all(|present| present));
    }
}
