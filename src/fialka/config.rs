//! Strongly typed M-125-3 key/configuration assembly.
//!
//! This module deliberately models only configuration that the current
//! 30-contact implementation can execute faithfully. Text/register handling is
//! a layer above the electrical machine, and the M-125-3 `30 <-> 10` reduction
//! mode remains deferred until its routing is implemented.

use std::{error::Error, fmt};

use super::{
    Commutator, CoreSetting, CoreSide, FialkaCore, FialkaMachine, Proton2Rotor, RingSetting,
    RotorDrum, RotorId, RotorPosition,
};

/// Historically documented adjustable-rotor series available to the machine.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RotorSeries {
    /// Polish 3K-series rotors.
    Polish3K,
    /// Czechoslovak 6K-series rotors.
    Czechoslovak6K,
}

impl RotorSeries {
    fn rotor(self, id: RotorId) -> super::RotorCore {
        match self {
            Self::Polish3K => super::data::polish::rotor(id),
            Self::Czechoslovak6K => super::data::czech::rotor(id),
        }
    }

    fn body(self, id: RotorId) -> super::RotorBody {
        match self {
            Self::Polish3K => super::data::polish::body(id),
            Self::Czechoslovak6K => super::data::czech::body(id),
        }
    }
}

/// Keyed configuration of one physical rotor slot.
///
/// Body and core identities are separate because PROTON-2 permits wiring cores
/// to be installed in different wheel bodies. The slot itself is represented
/// by this value's index in [`FialkaConfig::rotors`]: index 0 is physical slot
/// 1 (leftmost), index 9 is slot 10 (rightmost).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RotorConfig {
    body_id: RotorId,
    core_id: RotorId,
    core_side: CoreSide,
    core_setting: CoreSetting,
    ring_setting: RingSetting,
    position: RotorPosition,
}

impl RotorConfig {
    /// Construct one fully specified keyed rotor slot.
    #[must_use]
    pub const fn new(
        body_id: RotorId,
        core_id: RotorId,
        core_side: CoreSide,
        core_setting: CoreSetting,
        ring_setting: RingSetting,
        position: RotorPosition,
    ) -> Self {
        Self {
            body_id,
            core_id,
            core_side,
            core_setting,
            ring_setting,
            position,
        }
    }

    /// Overall/basic setting for a body with its matching wiring core.
    #[must_use]
    pub fn overall_base(id: RotorId) -> Self {
        Self::new(
            id,
            id,
            CoreSide::One,
            CoreSetting::A,
            RingSetting::A,
            RotorPosition::new(0).expect("zero is a valid Fialka rotor position"),
        )
    }

    #[must_use]
    pub const fn body_id(self) -> RotorId {
        self.body_id
    }

    #[must_use]
    pub const fn core_id(self) -> RotorId {
        self.core_id
    }

    #[must_use]
    pub const fn core_side(self) -> CoreSide {
        self.core_side
    }

    #[must_use]
    pub const fn core_setting(self) -> CoreSetting {
        self.core_setting
    }

    #[must_use]
    pub const fn ring_setting(self) -> RingSetting {
        self.ring_setting
    }

    #[must_use]
    pub const fn position(self) -> RotorPosition {
        self.position
    }
}

/// Errors rejected before a keyed Fialka machine is assembled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FialkaConfigError {
    /// The same mechanical wheel body occurs in more than one physical slot.
    DuplicateBody {
        body: RotorId,
        first_slot: usize,
        second_slot: usize,
    },
    /// The same removable electrical core occurs in more than one slot.
    DuplicateCore {
        core: RotorId,
        first_slot: usize,
        second_slot: usize,
    },
}

impl fmt::Display for FialkaConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::DuplicateBody {
                body,
                first_slot,
                second_slot,
            } => write!(
                f,
                "Fialka wheel body {body:?} is used in both slots {} and {}",
                first_slot + 1,
                second_slot + 1
            ),
            Self::DuplicateCore {
                core,
                first_slot,
                second_slot,
            } => write!(
                f,
                "Fialka wiring core {core:?} is used in both slots {} and {}",
                first_slot + 1,
                second_slot + 1
            ),
        }
    }
}

impl Error for FialkaConfigError {}

/// Complete validated key material for the implemented 30-contact M-125-3.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FialkaConfig {
    rotor_series: RotorSeries,
    rotors: [RotorConfig; 10],
    commutator: Commutator,
}

impl FialkaConfig {
    /// Validate and store a complete machine configuration.
    ///
    /// Every one of the ten mechanical bodies and every one of the ten wiring
    /// cores must occur exactly once. Their orders may differ, which is how
    /// PROTON-2 core mixing is represented.
    pub fn new(
        rotor_series: RotorSeries,
        rotors: [RotorConfig; 10],
        commutator: Commutator,
    ) -> Result<Self, FialkaConfigError> {
        validate_unique_identities(&rotors)?;
        Ok(Self {
            rotor_series,
            rotors,
            commutator,
        })
    }

    /// Overall/base configuration in historical rotor-identity order А..К.
    ///
    /// This is chiefly useful for tests and reference work; it is not a claim
    /// about an operational daily key.
    #[must_use]
    pub fn overall_base(rotor_series: RotorSeries, commutator: Commutator) -> Self {
        let rotors = std::array::from_fn(|index| RotorConfig::overall_base(RotorId::ALL[index]));
        Self::new(rotor_series, rotors, commutator)
            .expect("the canonical А..К base configuration is unique")
    }

    #[must_use]
    pub const fn rotor_series(&self) -> RotorSeries {
        self.rotor_series
    }

    #[must_use]
    pub const fn rotors(&self) -> &[RotorConfig; 10] {
        &self.rotors
    }

    #[must_use]
    pub const fn commutator(&self) -> &Commutator {
        &self.commutator
    }

    /// Assemble the ten physical slots from the validated key.
    #[must_use]
    pub(crate) fn build_drum(&self) -> RotorDrum {
        RotorDrum::new(std::array::from_fn(|index| {
            let keyed = self.rotors[index];
            Proton2Rotor::new(
                self.rotor_series.body(keyed.body_id),
                self.rotor_series.rotor(keyed.core_id),
                keyed.core_side,
                keyed.core_setting,
                keyed.ring_setting,
                keyed.position,
            )
        }))
    }

    /// Assemble an immutable/frozen electrical core from this key.
    #[must_use]
    pub(crate) fn build_core(&self) -> FialkaCore {
        FialkaCore::new(self.build_drum(), self.commutator.clone())
    }

    /// Assemble a stateful machine from this key.
    #[must_use]
    pub(crate) fn build_machine(&self) -> FialkaMachine {
        FialkaMachine::new(self.build_drum(), self.commutator.clone())
    }
}

fn validate_unique_identities(rotors: &[RotorConfig; 10]) -> Result<(), FialkaConfigError> {
    let mut body_slots = [None; 10];
    let mut core_slots = [None; 10];

    for (slot, rotor) in rotors.iter().copied().enumerate() {
        let body_index = rotor.body_id.index();
        if let Some(first_slot) = body_slots[body_index] {
            return Err(FialkaConfigError::DuplicateBody {
                body: rotor.body_id,
                first_slot,
                second_slot: slot,
            });
        }
        body_slots[body_index] = Some(slot);

        let core_index = rotor.core_id.index();
        if let Some(first_slot) = core_slots[core_index] {
            return Err(FialkaConfigError::DuplicateCore {
                core: rotor.core_id,
                first_slot,
                second_slot: slot,
            });
        }
        core_slots[core_index] = Some(slot);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::{Contact, CONTACT_COUNT, RotorSlot};

    fn contact(value: u8) -> Contact {
        Contact::new(value).unwrap()
    }

    fn base_rotors() -> [RotorConfig; 10] {
        std::array::from_fn(|index| RotorConfig::overall_base(RotorId::ALL[index]))
    }

    #[test]
    fn overall_base_builds_physical_slots_one_through_ten_in_a_to_k_order() {
        let config = FialkaConfig::overall_base(RotorSeries::Polish3K, Commutator::identity());
        let drum = config.build_drum();

        for (index, slot) in RotorSlot::ALL.into_iter().enumerate() {
            let id = RotorId::ALL[index];
            let rotor = drum.rotor(slot);
            assert_eq!(rotor.body_id().rotor_id(), id);
            assert_eq!(rotor.core_id(), id);
            assert_eq!(rotor.core_side(), CoreSide::One);
            assert_eq!(rotor.core_setting(), CoreSetting::A);
            assert_eq!(rotor.ring_setting(), RingSetting::A);
            assert_eq!(rotor.position().get(), 0);
        }
    }

    #[test]
    fn base_config_core_matches_direct_polish_3k_assembly() {
        let config = FialkaConfig::overall_base(RotorSeries::Polish3K, Commutator::identity());
        let configured = config.build_core();

        let manual_drum = RotorDrum::new(std::array::from_fn(|index| {
            let id = RotorId::ALL[index];
            Proton2Rotor::new(
                super::super::data::polish::body(id),
                super::super::data::polish::rotor(id),
                CoreSide::One,
                CoreSetting::A,
                RingSetting::A,
                RotorPosition::new(0).unwrap(),
            )
        }));
        let manual = FialkaCore::new(manual_drum, Commutator::identity());

        for raw in 0..CONTACT_COUNT as u8 {
            let input = contact(raw);
            assert_eq!(configured.encode_contact(input), manual.encode_contact(input));
            assert_eq!(configured.decode_contact(input), manual.decode_contact(input));
        }
    }

    #[test]
    fn duplicate_wheel_body_is_rejected_with_physical_slots() {
        let mut rotors = base_rotors();
        rotors[9] = RotorConfig::new(
            RotorId::A,
            RotorId::K,
            CoreSide::One,
            CoreSetting::A,
            RingSetting::A,
            RotorPosition::new(0).unwrap(),
        );

        assert_eq!(
            FialkaConfig::new(RotorSeries::Polish3K, rotors, Commutator::identity()),
            Err(FialkaConfigError::DuplicateBody {
                body: RotorId::A,
                first_slot: 0,
                second_slot: 9,
            })
        );
    }

    #[test]
    fn duplicate_wiring_core_is_rejected_with_physical_slots() {
        let mut rotors = base_rotors();
        rotors[9] = RotorConfig::new(
            RotorId::K,
            RotorId::A,
            CoreSide::One,
            CoreSetting::A,
            RingSetting::A,
            RotorPosition::new(0).unwrap(),
        );

        assert_eq!(
            FialkaConfig::new(RotorSeries::Polish3K, rotors, Commutator::identity()),
            Err(FialkaConfigError::DuplicateCore {
                core: RotorId::A,
                first_slot: 0,
                second_slot: 9,
            })
        );
    }

    #[test]
    fn complete_core_permutation_between_bodies_is_valid() {
        let rotors = std::array::from_fn(|index| {
            RotorConfig::new(
                RotorId::ALL[index],
                RotorId::ALL[(index + 1) % 10],
                if index % 2 == 0 { CoreSide::One } else { CoreSide::Two },
                CoreSetting::new(((index * 3) % 30) as u8).unwrap(),
                RingSetting::new(((index * 5) % 30) as u8).unwrap(),
                RotorPosition::new(((index * 7) % 30) as u8).unwrap(),
            )
        });

        let config = FialkaConfig::new(
            RotorSeries::Polish3K,
            rotors,
            Commutator::identity(),
        )
        .unwrap();
        let drum = config.build_drum();

        for (index, slot) in RotorSlot::ALL.into_iter().enumerate() {
            assert_eq!(drum.rotor(slot).body_id().rotor_id(), RotorId::ALL[index]);
            assert_eq!(drum.rotor(slot).core_id(), RotorId::ALL[(index + 1) % 10]);
        }
    }

    #[test]
    fn rotor_series_selects_both_matching_electrical_and_mechanical_data() {
        let polish = FialkaConfig::overall_base(RotorSeries::Polish3K, Commutator::identity());
        let czech =
            FialkaConfig::overall_base(RotorSeries::Czechoslovak6K, Commutator::identity());

        let polish_a = polish.build_drum().rotor(RotorSlot::ONE).clone();
        let czech_a = czech.build_drum().rotor(RotorSlot::ONE).clone();

        // The published 3K and 6K A rotors differ electrically at contact 1
        // and mechanically in their blocking-pin pattern.
        assert_ne!(polish_a.right_to_left(contact(0)), czech_a.right_to_left(contact(0)));
        assert_ne!(polish_a.blocking_pins(), czech_a.blocking_pins());
    }

    #[test]
    fn non_reciprocal_commutator_is_preserved_by_configuration() {
        let mapping = std::array::from_fn(|index| ((index * 7) % CONTACT_COUNT) as u8);
        let card = Commutator::new(mapping).unwrap();
        let config = FialkaConfig::overall_base(RotorSeries::Polish3K, card.clone());

        assert_eq!(config.commutator(), &card);
    }

    #[test]
    fn build_machine_starts_from_configured_positions() {
        let rotors = std::array::from_fn(|index| {
            RotorConfig::new(
                RotorId::ALL[index],
                RotorId::ALL[index],
                CoreSide::One,
                CoreSetting::A,
                RingSetting::A,
                RotorPosition::new(((index * 3 + 2) % 30) as u8).unwrap(),
            )
        });
        let config =
            FialkaConfig::new(RotorSeries::Czechoslovak6K, rotors, Commutator::identity()).unwrap();
        let machine = config.build_machine();

        assert_eq!(
            machine.drum().positions().map(RotorPosition::get),
            std::array::from_fn(|index| ((index * 3 + 2) % 30) as u8)
        );
    }
}
