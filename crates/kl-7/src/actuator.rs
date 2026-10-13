//! Actuator switch array for sensing KL-7 notch rings.
//!
//! The KL-7 stepping unit contains 7 sensing switch assemblies (numbered 1 through 7),
//! corresponding to the 7 movable rotor slots (drum positions 0, 1, 2, 4, 5, 6, 7).
//! The stationary rotor 4 (drum position 3) has no actuator switch.
//!
//! Each actuator switch consists of a two-level switch pile-up ($S_a$ and $S_b$).
//! In cipher mode (Encipher / Decipher), the upper $S_a$ section is energized,
//! sensing the cams (`true`) and notches (`false`) of the mounted notch rings.

use super::{
    contact::Position36,
    notch_ring::NotchRing,
    rotor::Rotor,
};

/// The number of actuator sensing switches (for the 7 movable rotors).
pub const ACTUATOR_SWITCH_COUNT: usize = 7;

/// Mapping from actuator switch index (0..6) to drum slot index (0..7).
pub const MOVABLE_ROTOR_SLOTS: [usize; ACTUATOR_SWITCH_COUNT] = [0, 1, 2, 4, 5, 6, 7];

/// The sensed boolean states of the 7 actuator switches ($S_a$).
///
/// `true` indicates the switch is actuated by a cam (active / closed).
/// `false` indicates the switch sits in a notch (inactive / open).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ActuatorState {
    states: [bool; ACTUATOR_SWITCH_COUNT],
}

impl ActuatorState {
    /// Construct from raw 7-boolean array.
    #[must_use]
    pub const fn from_array(states: [bool; ACTUATOR_SWITCH_COUNT]) -> Self {
        Self { states }
    }

    /// Return the raw boolean array of 7 switch states.
    #[must_use]
    pub const fn states(&self) -> &[bool; ACTUATOR_SWITCH_COUNT] {
        &self.states
    }

    /// Get switch state for switch index `0..6`.
    #[must_use]
    pub const fn get(&self, switch_idx: usize) -> bool {
        self.states[switch_idx]
    }

    /// Construct an actuator state by sensing notch rings mounted on the movable rotors.
    ///
    /// - `rotors`: The 8 rotors currently in the drum (indices 0..7).
    /// - `rings`: The 7 notch rings assigned to the movable rotors (indices 0..6).
    /// - `ring_offsets`: The 7 notch ring offsets (indices 0..6).
    #[must_use]
    pub fn sense(
        rotors: &[Rotor; 8],
        rings: &[NotchRing; ACTUATOR_SWITCH_COUNT],
        ring_offsets: &[Position36; ACTUATOR_SWITCH_COUNT],
    ) -> Self {
        let mut states = [false; ACTUATOR_SWITCH_COUNT];
        for i in 0..ACTUATOR_SWITCH_COUNT {
            let slot = MOVABLE_ROTOR_SLOTS[i];
            let rotor = &rotors[slot];
            let ring = &rings[i];
            let ring_offset = ring_offsets[i];
            states[i] = ring.is_cam_active(rotor.win_pos(), rotor.alpha_pos(), ring_offset);
        }
        Self { states }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::RotorId;
    use crate::notch_ring::NotchRingId;

    #[test]
    fn actuator_sensing_produces_consistent_switch_states() {
        let rotors = [
            Rotor::from_reference(RotorId::A, Position36::ZERO, Position36::ZERO),
            Rotor::from_reference(RotorId::B, Position36::ZERO, Position36::ZERO),
            Rotor::from_reference(RotorId::C, Position36::ZERO, Position36::ZERO),
            Rotor::from_reference(RotorId::D, Position36::ZERO, Position36::ZERO), // stationary
            Rotor::from_reference(RotorId::E, Position36::ZERO, Position36::ZERO),
            Rotor::from_reference(RotorId::F, Position36::ZERO, Position36::ZERO),
            Rotor::from_reference(RotorId::G, Position36::ZERO, Position36::ZERO),
            Rotor::from_reference(RotorId::H, Position36::ZERO, Position36::ZERO),
        ];

        let rings = [
            NotchRing::from_id(NotchRingId::Ring1),
            NotchRing::from_id(NotchRingId::Ring2),
            NotchRing::from_id(NotchRingId::Ring3),
            NotchRing::from_id(NotchRingId::Ring4),
            NotchRing::from_id(NotchRingId::Ring5),
            NotchRing::from_id(NotchRingId::Ring6),
            NotchRing::from_id(NotchRingId::Ring7),
        ];

        let ring_offsets = [Position36::ZERO; 7];

        let act = ActuatorState::sense(&rotors, &rings, &ring_offsets);
        assert_eq!(act.states().len(), 7);
    }
}
