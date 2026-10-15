//! Stepping solenoid relay logic for the TSEC/KL-7 8-rotor drum.
//!
//! # Stepping Rules (Cipher Mode: Encipher / Decipher)
//!
//! The 7 sensing switches ($S_a$, 0..6) read the notch cams on movable rotors
//! at drum slots 0, 1, 2, 4, 5, 6, 7.
//! Let `s[0..6]` denote the boolean state of switches 1..7 (`true` = cam, `false` = notch):
//!
//! - **Rotor 1 (slot 0)**: steps if `!s[6] && (!s[1] || !s[2])`
//!   (Switch 7 is inactive AND at least one of Switch 2 or 3 is inactive)
//! - **Rotor 2 (slot 1)**: steps if `!s[4] || !s[5]`
//!   (Switch 5 is inactive OR Switch 6 is inactive)
//! - **Rotor 3 (slot 2)**: steps if `s[1] || s[5]`
//!   (Switch 2 is active OR Switch 6 is active)
//! - **Rotor 4 (slot 3)**: **STATIONARY** (never steps; has wide metal ring without notches)
//! - **Rotor 5 (slot 4)**: steps if `!s[1] || !s[2]`
//!   (Switch 2 is inactive OR Switch 3 is inactive)
//! - **Rotor 6 (slot 5)**: steps if `!s[0] || s[2]`
//!   (Switch 1 is inactive OR Switch 3 is active)
//! - **Rotor 7 (slot 6)**: steps if `s[0] || s[4]`
//!   (Switch 1 is active OR Switch 5 is active)
//! - **Rotor 8 (slot 7)**: steps if `!s[3] && (!s[1] || !s[2])`
//!   (Switch 4 is inactive AND at least one of Switch 2 or 3 is inactive)
//!
//! # Anti-Stall Guarantee
//! The circuit logic guarantees that at least two stepping solenoids are energized
//! on every machine cycle, preventing the machine from stalling.

use super::actuator::ActuatorState;

/// Total number of rotor slots in the KL-7 drum.
pub const DRUM_ROTOR_COUNT: usize = 8;

/// Index of the stationary wide rotor in the drum (0-indexed: slot 3 = 4th rotor).
pub const STATIONARY_ROTOR_SLOT: usize = 3;

/// Set of rotors energized to step in one machine cycle.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RotorStepSet {
    steps: [bool; DRUM_ROTOR_COUNT],
}

impl RotorStepSet {
    /// Construct from raw 8-element boolean array.
    #[must_use]
    pub const fn from_array(steps: [bool; DRUM_ROTOR_COUNT]) -> Self {
        Self { steps }
    }

    /// Return raw boolean array for slots 0..7.
    #[must_use]
    pub const fn steps(&self) -> &[bool; DRUM_ROTOR_COUNT] {
        &self.steps
    }

    /// Check if a specific drum slot (0..7) is energized to step.
    #[must_use]
    pub const fn should_step(&self, slot: usize) -> bool {
        if slot < DRUM_ROTOR_COUNT {
            self.steps[slot]
        } else {
            false
        }
    }

    /// Count of rotors energized to step in this cycle.
    #[must_use]
    pub fn count(&self) -> usize {
        self.steps.iter().filter(|&&b| b).count()
    }

    /// Pack stepping flags into an 8-bit integer (bit 0 = slot 0 .. bit 7 = slot 7).
    #[must_use]
    pub fn bits(&self) -> u8 {
        let mut bits = 0u8;
        for (i, &step) in self.steps.iter().enumerate() {
            if step {
                bits |= 1 << i;
            }
        }
        bits
    }
}

/// Evaluate the stepping solenoid relay truth table given current actuator switch states.
#[must_use]
pub fn evaluate_stepping(actuators: &ActuatorState) -> RotorStepSet {
    let s = actuators.states();

    // Switch indices:
    // s[0] = Switch 1 (slot 0)
    // s[1] = Switch 2 (slot 1)
    // s[2] = Switch 3 (slot 2)
    // s[3] = Switch 4 (slot 4, rotor 5)
    // s[4] = Switch 5 (slot 5, rotor 6)
    // s[5] = Switch 6 (slot 6, rotor 7)
    // s[6] = Switch 7 (slot 7, rotor 8)

    let r2_or_r3_inactive = !s[1] || !s[2];

    let mut steps = [false; DRUM_ROTOR_COUNT];

    // Rotor 1 (slot 0)
    steps[0] = !s[6] && r2_or_r3_inactive;

    // Rotor 2 (slot 1)
    steps[1] = !s[4] || !s[5];

    // Rotor 3 (slot 2)
    steps[2] = s[1] || s[5];

    // Rotor 4 (slot 3) - Stationary
    steps[3] = false;

    // Rotor 5 (slot 4)
    steps[4] = r2_or_r3_inactive;

    // Rotor 6 (slot 5)
    steps[5] = !s[0] || s[2];

    // Rotor 7 (slot 6)
    steps[6] = s[0] || s[4];

    // Rotor 8 (slot 7)
    steps[7] = !s[3] && r2_or_r3_inactive;

    RotorStepSet::from_array(steps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotor_4_is_always_stationary() {
        for bits in 0..128u8 {
            let mut states = [false; 7];
            for (i, val) in states.iter_mut().enumerate() {
                *val = (bits & (1 << i)) != 0;
            }
            let actuators = ActuatorState::from_array(states);
            let steps = evaluate_stepping(&actuators);
            assert!(!steps.should_step(STATIONARY_ROTOR_SLOT));
        }
    }

    #[test]
    fn anti_stall_guarantee_exhaustive_test() {
        for bits in 0..128u8 {
            let mut states = [false; 7];
            for (i, val) in states.iter_mut().enumerate() {
                *val = (bits & (1 << i)) != 0;
            }
            let actuators = ActuatorState::from_array(states);
            let steps = evaluate_stepping(&actuators);
            let count = steps.count();
            assert!(
                count >= 2,
                "Stall detected for switch state {:07b}: count={}",
                bits,
                count
            );
        }
    }

    #[test]
    fn all_inactive_switches_stepping() {
        // When all switches are inactive (all false: notches)
        let actuators = ActuatorState::from_array([false; 7]);
        let steps = evaluate_stepping(&actuators);

        // r2_or_r3_inactive = true
        // slot 0: !s[6] && true = true
        // slot 1: !s[4] || !s[5] = true
        // slot 2: s[1] || s[5] = false
        // slot 3: false
        // slot 4: true
        // slot 5: !s[0] || s[2] = true
        // slot 6: s[0] || s[4] = false
        // slot 7: !s[3] && true = true
        assert!(steps.should_step(0));
        assert!(steps.should_step(1));
        assert!(!steps.should_step(2));
        assert!(!steps.should_step(3));
        assert!(steps.should_step(4));
        assert!(steps.should_step(5));
        assert!(!steps.should_step(6));
        assert!(steps.should_step(7));
    }

    #[test]
    fn all_active_switches_stepping() {
        // When all switches are active (all true: cams)
        let actuators = ActuatorState::from_array([true; 7]);
        let steps = evaluate_stepping(&actuators);

        // r2_or_r3_inactive = false
        // slot 0: false
        // slot 1: false
        // slot 2: true
        // slot 3: false
        // slot 4: false
        // slot 5: true
        // slot 6: true
        // slot 7: false
        assert!(!steps.should_step(0));
        assert!(!steps.should_step(1));
        assert!(steps.should_step(2));
        assert!(!steps.should_step(3));
        assert!(!steps.should_step(4));
        assert!(steps.should_step(5));
        assert!(steps.should_step(6));
        assert!(!steps.should_step(7));
    }
}
