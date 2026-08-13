//! Mechanical stepping of the ten-wheel Fialka drum.
//!
//! This module deliberately models only rotor motion and blocking propagation.
//! It does not perform any electrical transformation.  Perera/Hamer document
//! two independent stepping chains:
//!
//! - even slots: 2 -> 4 -> 6 -> 8 -> 10, driven by slot 2;
//! - odd slots:  9 -> 7 -> 5 -> 3 -> 1, driven by slot 9.
//!
//! Even-numbered slots rotate their upper letters away from the keyboard;
//! odd-numbered slots rotate them towards the keyboard.  A blocking pin on any
//! upstream wheel suppresses the motion of every downstream wheel in that
//! chain.  Blocking decisions are made from the complete pre-step state, then
//! all selected wheels are moved together.

use super::{Contact, Proton2Rotor, RotorPosition, CONTACT_COUNT};

const ROTOR_COUNT: usize = 10;

/// Physical slot in the Fialka drum, numbered 1 through 10 from left to right.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RotorSlot(u8);

impl RotorSlot {
    pub(crate) const ONE: Self = Self(0);
    pub(crate) const TWO: Self = Self(1);
    pub(crate) const THREE: Self = Self(2);
    pub(crate) const FOUR: Self = Self(3);
    pub(crate) const FIVE: Self = Self(4);
    pub(crate) const SIX: Self = Self(5);
    pub(crate) const SEVEN: Self = Self(6);
    pub(crate) const EIGHT: Self = Self(7);
    pub(crate) const NINE: Self = Self(8);
    pub(crate) const TEN: Self = Self(9);

    pub(crate) const ALL: [Self; ROTOR_COUNT] = [
        Self::ONE,
        Self::TWO,
        Self::THREE,
        Self::FOUR,
        Self::FIVE,
        Self::SIX,
        Self::SEVEN,
        Self::EIGHT,
        Self::NINE,
        Self::TEN,
    ];

    /// Construct from a zero-based slot index.
    #[must_use]
    pub(crate) const fn new(index: u8) -> Option<Self> {
        if index < ROTOR_COUNT as u8 {
            Some(Self(index))
        } else {
            None
        }
    }

    /// Zero-based array index.
    #[must_use]
    pub(crate) const fn index(self) -> usize {
        self.0 as usize
    }

    /// Historical one-based physical slot number.
    #[must_use]
    pub(crate) const fn number(self) -> u8 {
        self.0 + 1
    }

    #[must_use]
    pub(crate) const fn direction(self) -> RotationDirection {
        if self.number() % 2 == 0 {
            RotationDirection::AwayFromKeyboard
        } else {
            RotationDirection::TowardsKeyboard
        }
    }
}

/// Direction in which the upper letter of a wheel moves when its slot steps.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum RotationDirection {
    /// Odd-numbered slots: visible position increases, e.g. А -> Б.
    TowardsKeyboard,
    /// Even-numbered slots: visible position decreases, e.g. А -> Й.
    AwayFromKeyboard,
}

/// Set of physical slots selected to move on one keypress.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) struct RotorStepSet(u16);

impl RotorStepSet {
    const fn empty() -> Self {
        Self(0)
    }

    fn insert(&mut self, slot: RotorSlot) {
        self.0 |= 1_u16 << slot.index();
    }

    #[must_use]
    pub(crate) const fn contains(self, slot: RotorSlot) -> bool {
        self.0 & (1_u16 << slot.index()) != 0
    }

    #[must_use]
    pub(crate) const fn bits(self) -> u16 {
        self.0
    }
}

/// Mechanical ten-wheel drum.
///
/// Array order is always physical left-to-right slot order: index 0 is slot 1
/// and index 9 is slot 10.  Rotor/core identities may be in any keyed order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RotorDrum {
    rotors: [Proton2Rotor; ROTOR_COUNT],
}

impl RotorDrum {
    #[must_use]
    pub(crate) const fn new(rotors: [Proton2Rotor; ROTOR_COUNT]) -> Self {
        Self { rotors }
    }

    #[must_use]
    pub(crate) fn rotor(&self, slot: RotorSlot) -> &Proton2Rotor {
        &self.rotors[slot.index()]
    }

    #[must_use]
    pub(crate) fn positions(&self) -> [RotorPosition; ROTOR_COUNT] {
        std::array::from_fn(|index| self.rotors[index].position())
    }

    /// Determine all wheels that will move from the current pre-step state.
    ///
    /// The returned set is a snapshot: no rotor is moved while propagation is
    /// being calculated.  This avoids making a later wheel observe an already
    /// advanced upstream wheel during the same keypress.
    #[must_use]
    pub(crate) fn determine_steps(&self) -> RotorStepSet {
        let mut result = RotorStepSet::empty();

        self.determine_chain_steps(
            [
                RotorSlot::TWO,
                RotorSlot::FOUR,
                RotorSlot::SIX,
                RotorSlot::EIGHT,
                RotorSlot::TEN,
            ],
            &mut result,
        );

        self.determine_chain_steps(
            [
                RotorSlot::NINE,
                RotorSlot::SEVEN,
                RotorSlot::FIVE,
                RotorSlot::THREE,
                RotorSlot::ONE,
            ],
            &mut result,
        );

        result
    }

    /// Advance the drum once, as after one typed character.
    pub(crate) fn step(&mut self) {
        let steps = self.determine_steps();
        self.apply_steps(steps);
    }

    fn determine_chain_steps<const N: usize>(
        &self,
        chain: [RotorSlot; N],
        result: &mut RotorStepSet,
    ) {
        let mut propagation_open = true;

        for slot in chain {
            if propagation_open {
                result.insert(slot);
            }

            if self.blocked_at_drive(slot) {
                propagation_open = false;
            }
        }
    }

    /// Whether the wheel body currently presents a blocking pin to its chain's
    /// drive cog.
    fn blocked_at_drive(&self, slot: RotorSlot) -> bool {
        let rotor = self.rotor(slot);
        rotor.body().has_blocking_pin(self.drive_contact(slot))
    }

    /// Physical body coordinate currently aligned with a chain's drive cog.
    ///
    /// In the overall base setting with a visible А, the even chain engages
    /// source position 18 and the odd chain source position 21.  The wheel
    /// body's angular displacement is the visible position plus the ring
    /// setting; the removable wiring-core setting is electrical only and does
    /// not move the body's blocking pins.
    fn drive_contact(&self, slot: RotorSlot) -> Contact {
        let base = match slot.direction() {
            RotationDirection::AwayFromKeyboard => Contact::new(17).unwrap(), // source position 18
            RotationDirection::TowardsKeyboard => Contact::new(20).unwrap(), // source position 21
        };
        let rotor = self.rotor(slot);
        let displacement =
            i16::from(rotor.position().get()) + i16::from(rotor.ring_setting().get());
        base.offset(displacement)
    }

    fn apply_steps(&mut self, steps: RotorStepSet) {
        for slot in RotorSlot::ALL {
            if !steps.contains(slot) {
                continue;
            }

            let rotor = &mut self.rotors[slot.index()];
            let delta = match slot.direction() {
                RotationDirection::TowardsKeyboard => 1_i16,
                RotationDirection::AwayFromKeyboard => -1_i16,
            };
            let next = (i16::from(rotor.position().get()) + delta)
                .rem_euclid(CONTACT_COUNT as i16) as u8;
            rotor.set_position(RotorPosition::new(next).unwrap());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoreSetting, CoreSide, RingSetting, RotorId, data::polish};

    fn position(value: u8) -> RotorPosition {
        RotorPosition::new(value).unwrap()
    }

    fn base_rotor(id: RotorId) -> Proton2Rotor {
        Proton2Rotor::new(
            polish::body(id),
            polish::rotor(id),
            CoreSide::One,
            CoreSetting::A,
            RingSetting::A,
            position(0),
        )
    }

    fn base_drum() -> RotorDrum {
        RotorDrum::new(std::array::from_fn(|index| base_rotor(RotorId::ALL[index])))
    }

    fn one_based_positions(drum: &RotorDrum) -> [u8; ROTOR_COUNT] {
        drum.positions().map(|position| position.get() + 1)
    }

    #[test]
    fn slot_numbering_and_directions_are_physical_left_to_right() {
        for (index, slot) in RotorSlot::ALL.into_iter().enumerate() {
            assert_eq!(slot.index(), index);
            assert_eq!(slot.number(), index as u8 + 1);
            assert_eq!(RotorSlot::new(index as u8), Some(slot));

            let expected = if slot.number() % 2 == 0 {
                RotationDirection::AwayFromKeyboard
            } else {
                RotationDirection::TowardsKeyboard
            };
            assert_eq!(slot.direction(), expected);
        }
        assert_eq!(RotorSlot::new(10), None);
    }

    #[test]
    fn first_step_matches_the_published_driver_directions() {
        let mut drum = base_drum();
        drum.step();

        // Driver 2 moves А -> Й (source position 30), while driver 9 moves
        // А -> Б (source position 2).  Their initial pins block all downstream
        // wheels in both chains.
        assert_eq!(
            one_based_positions(&drum),
            [1, 30, 1, 1, 1, 1, 1, 1, 2, 1]
        );
    }

    #[test]
    fn perera_hamer_even_chain_worked_example_is_reproduced() {
        let mut drum = base_drum();

        for _ in 0..4 {
            drum.step();
        }
        assert_eq!(one_based_positions(&drum), [1, 27, 1, 1, 1, 1, 1, 1, 5, 1]);

        // On the fifth keypress, slot 2 presents body-B source position 14,
        // which has no blocking pin, so slot 4 also moves А -> Й.  Slot 4
        // does not block, so slot 6 moves as well; slot 6 then blocks further
        // propagation to slots 8 and 10.
        let steps = drum.determine_steps();
        assert!(steps.contains(RotorSlot::TWO));
        assert!(steps.contains(RotorSlot::FOUR));
        assert!(steps.contains(RotorSlot::SIX));
        assert!(!steps.contains(RotorSlot::EIGHT));
        assert!(!steps.contains(RotorSlot::TEN));

        drum.step();
        assert_eq!(one_based_positions(&drum), [1, 26, 1, 30, 1, 30, 1, 1, 6, 1]);
    }

    #[test]
    fn published_twenty_keypress_3k_stepping_trace_matches_exactly() {
        // Crypto Museum and Perera/Hamer publish this trace for 3K wheels in
        // order АБВГДЕЖЗИК, all PROTON-2 settings at their base values, and
        // all visible wheel positions initially at А.
        const EXPECTED: [[u8; ROTOR_COUNT]; 21] = [
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            [1, 30, 1, 1, 1, 1, 1, 1, 2, 1],
            [1, 29, 1, 1, 1, 1, 1, 1, 3, 1],
            [1, 28, 1, 1, 1, 1, 1, 1, 4, 1],
            [1, 27, 1, 1, 1, 1, 1, 1, 5, 1],
            [1, 26, 1, 30, 1, 30, 1, 1, 6, 1],
            [1, 25, 1, 30, 1, 30, 1, 1, 7, 1],
            [1, 24, 1, 29, 1, 30, 2, 1, 8, 1],
            [1, 23, 1, 29, 1, 30, 3, 1, 9, 1],
            [1, 22, 1, 28, 1, 30, 3, 1, 10, 1],
            [1, 21, 1, 27, 1, 30, 4, 1, 11, 1],
            [1, 20, 1, 26, 1, 30, 4, 1, 12, 1],
            [1, 19, 1, 26, 1, 30, 4, 1, 13, 1],
            [1, 18, 1, 25, 1, 29, 4, 1, 14, 1],
            [1, 17, 1, 25, 1, 29, 4, 1, 15, 1],
            [2, 16, 2, 24, 2, 29, 5, 1, 16, 1],
            [2, 15, 2, 24, 2, 29, 5, 1, 17, 1],
            [2, 14, 2, 23, 2, 28, 6, 30, 18, 30],
            [2, 13, 2, 22, 2, 28, 6, 30, 19, 30],
            [2, 12, 2, 22, 2, 28, 7, 30, 20, 30],
            [2, 11, 2, 22, 2, 28, 8, 30, 21, 30],
        ];

        let mut drum = base_drum();
        assert_eq!(one_based_positions(&drum), EXPECTED[0]);

        for (step, expected) in EXPECTED.iter().enumerate().skip(1) {
            drum.step();
            assert_eq!(one_based_positions(&drum), *expected, "after keypress {step}");
        }
    }

    #[test]
    fn blocking_decisions_use_the_complete_pre_step_state() {
        let drum = base_drum();
        let steps = drum.determine_steps();

        // In the initial state both unconditional drivers move, while their
        // current blocking pins close both propagation chains.
        assert!(steps.contains(RotorSlot::TWO));
        assert!(steps.contains(RotorSlot::NINE));
        for slot in [
            RotorSlot::ONE,
            RotorSlot::THREE,
            RotorSlot::FOUR,
            RotorSlot::FIVE,
            RotorSlot::SIX,
            RotorSlot::SEVEN,
            RotorSlot::EIGHT,
            RotorSlot::TEN,
        ] {
            assert!(!steps.contains(slot));
        }
    }

    #[test]
    fn ring_setting_moves_the_mechanical_pin_frame_but_core_setting_does_not() {
        let mut rotors = std::array::from_fn(|index| base_rotor(RotorId::ALL[index]));

        // Slot 2/body Б: with position А and base ring, source position 18 is
        // at the drive cog and blocks slot 4.  Shifting the ring by +4 moves
        // source position 22 to the cog; body Б also has a pin there, so use a
        // +5 shift instead, presenting source position 23 (also a pin).  A +6
        // shift presents source position 24, which has no pin.
        rotors[RotorSlot::TWO.index()] = Proton2Rotor::new(
            polish::body(RotorId::B),
            polish::rotor(RotorId::B),
            CoreSide::One,
            CoreSetting::new(11).unwrap(),
            RingSetting::new(6).unwrap(),
            position(0),
        );
        let drum = RotorDrum::new(rotors);
        let steps = drum.determine_steps();
        assert!(steps.contains(RotorSlot::FOUR));

        // The non-base core setting above deliberately has no effect on this
        // mechanical decision.
    }

    #[test]
    fn step_set_never_uses_bits_outside_ten_physical_slots() {
        let mut drum = base_drum();
        for _ in 0..300 {
            assert_eq!(drum.determine_steps().bits() & !0x03ff, 0);
            drum.step();
        }
    }
}
