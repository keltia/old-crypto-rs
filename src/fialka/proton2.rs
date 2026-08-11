//! Electrical model of the adjustable PROTON-2 Fialka rotor.
//!
//! The Fialka Reference Manual, section 3.7 (p. 90), specifies the
//! right-to-left rotor transform as:
//!
//! 1. add the current wheel position;
//! 2. add the ring setting;
//! 3. subtract the removable-core setting;
//! 4. apply the wiring matrix;
//! 5. add the core setting;
//! 6. subtract the ring setting;
//! 7. subtract the current wheel position.
//!
//! In zero-based coordinates this is `P(x + d) - d`, where
//! `d = position + ring - core_setting`.
//!
//! Section 3.3.5 (p. 73) defines the independent ring/core settings. When
//! core side 2 is visible from the left/outside of the wheel, the manual
//! requires the *mirrored* wiring matrix.  Physically flipping the core swaps
//! its two electrical faces and reverses angular coordinates about the white
//! index mark.  If `R(x) = -x (mod 30)`, the mirrored right-to-left mapping is
//! `R * P^-1 * R`; its return mapping is `R * P * R`.

use super::{
    Contact, CoreSetting, RingSetting, RotorBody, RotorBodyId, RotorCore, RotorId, RotorPosition,
};

/// Which face of a removable PROTON-2 wiring core is visible from the left
/// (flat-contact) side of the assembled wheel.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum CoreSide {
    /// Historical basic orientation: side 1 visible from the left.
    One,
    /// Reversed orientation: side 2 visible from the left.
    Two,
}

/// One fully configured adjustable PROTON-2 wheel.
///
/// The wheel body carries the mechanical advance-blocking pins, while the
/// removable core carries only the electrical permutation.  The actual
/// stepping/propagation algorithm remains outside this type until Step 7.
///
/// The body identity is distinct because the wiring core may be mixed between
/// wheels.  Step 6 attaches the historical advance-blocking pin pattern to the
/// body; slot-dependent motion and propagation remain Step 7 concerns.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Proton2Rotor {
    body: RotorBody,
    core: RotorCore,
    core_side: CoreSide,
    core_setting: CoreSetting,
    ring_setting: RingSetting,
    position: RotorPosition,
}

impl Proton2Rotor {
    /// Assemble a PROTON-2 wheel from its independent keyed settings.
    #[must_use]
    pub(crate) fn new(
        body: RotorBody,
        core: RotorCore,
        core_side: CoreSide,
        core_setting: CoreSetting,
        ring_setting: RingSetting,
        position: RotorPosition,
    ) -> Self {
        Self {
            body,
            core,
            core_side,
            core_setting,
            ring_setting,
            position,
        }
    }

    /// Mechanical wheel-body identity (the owner of the blocking-pin pattern).
    #[must_use]
    pub(crate) const fn body_id(&self) -> RotorBodyId {
        self.body.id()
    }

    /// Mechanical wheel body, including its advance-blocking pin pattern.
    #[must_use]
    pub(crate) const fn body(&self) -> RotorBody {
        self.body
    }

    /// Physical advance-blocking pin pattern of the body in base coordinates.
    #[must_use]
    pub(crate) const fn blocking_pins(&self) -> super::BlockingPins {
        self.body.blocking_pins()
    }

    /// Identity of the electrical wiring core currently installed in the body.
    #[must_use]
    pub(crate) const fn core_id(&self) -> RotorId {
        self.core.id()
    }

    #[must_use]
    pub(crate) const fn core_side(&self) -> CoreSide {
        self.core_side
    }

    #[must_use]
    pub(crate) const fn core_setting(&self) -> CoreSetting {
        self.core_setting
    }

    #[must_use]
    pub(crate) const fn ring_setting(&self) -> RingSetting {
        self.ring_setting
    }

    #[must_use]
    pub(crate) const fn position(&self) -> RotorPosition {
        self.position
    }

    /// Change only the dynamic/visible wheel position.
    pub(crate) fn set_position(&mut self, position: RotorPosition) {
        self.position = position;
    }

    /// Pass a signal through the wheel from right to left.
    #[must_use]
    pub(crate) fn right_to_left(&self, input: Contact) -> Contact {
        let displacement = self.electrical_displacement();
        let core_input = input.offset(displacement);
        let core_output = match self.core_side {
            CoreSide::One => self.core.right_to_left(core_input),
            CoreSide::Two => self.core.mirrored_right_to_left(core_input),
        };
        core_output.offset(-displacement)
    }

    /// Pass a signal through the wheel from left to right.
    #[must_use]
    pub(crate) fn left_to_right(&self, input: Contact) -> Contact {
        let displacement = self.electrical_displacement();
        let core_input = input.offset(displacement);
        let core_output = match self.core_side {
            CoreSide::One => self.core.left_to_right(core_input),
            CoreSide::Two => self.core.mirrored_left_to_right(core_input),
        };
        core_output.offset(-displacement)
    }

    /// Combined offset specified by the Reference Manual:
    /// `position + ring_setting - core_setting`.
    fn electrical_displacement(&self) -> i16 {
        i16::from(self.position.get()) + i16::from(self.ring_setting.get())
            - i16::from(self.core_setting.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::{CONTACT_COUNT, PositionedRotor, data::polish};

    fn contact(value: u8) -> Contact {
        Contact::new(value).unwrap()
    }

    fn position(value: u8) -> RotorPosition {
        RotorPosition::new(value).unwrap()
    }

    fn ring(value: u8) -> RingSetting {
        RingSetting::new(value).unwrap()
    }

    fn core_setting(value: u8) -> CoreSetting {
        CoreSetting::new(value).unwrap()
    }

    fn basic(id: RotorId, position: u8) -> Proton2Rotor {
        Proton2Rotor::new(
            polish::body(id),
            polish::rotor(id),
            CoreSide::One,
            CoreSetting::A,
            RingSetting::A,
            self::position(position),
        )
    }

    #[test]
    fn basic_proton2_configuration_matches_fixed_rotor_at_every_position() {
        for id in RotorId::ALL {
            for p in 0..CONTACT_COUNT as u8 {
                let proton = basic(id, p);
                let fixed = PositionedRotor::new(polish::rotor(id), position(p));

                for value in 0..CONTACT_COUNT as u8 {
                    let input = contact(value);
                    assert_eq!(
                        proton.right_to_left(input),
                        fixed.right_to_left(input),
                        "rotor {id:?}, position {p}, input {value}"
                    );
                    assert_eq!(
                        proton.left_to_right(input),
                        fixed.left_to_right(input),
                        "rotor {id:?}, position {p}, input {value}"
                    );
                }
            }
        }
    }

    #[test]
    fn equal_ring_and_core_settings_cancel_electrically() {
        for id in RotorId::ALL {
            for setting in 0..CONTACT_COUNT as u8 {
                let proton = Proton2Rotor::new(
                    polish::body(id),
                    polish::rotor(id),
                    CoreSide::One,
                    core_setting(setting),
                    ring(setting),
                    position(7),
                );
                let fixed = PositionedRotor::new(polish::rotor(id), position(7));

                for value in 0..CONTACT_COUNT as u8 {
                    let input = contact(value);
                    assert_eq!(proton.right_to_left(input), fixed.right_to_left(input));
                    assert_eq!(proton.left_to_right(input), fixed.left_to_right(input));
                }
            }
        }
    }

    #[test]
    fn ring_and_core_settings_have_opposite_electrical_signs() {
        // The Reference Manual gives d = position + ring - core.  Therefore
        // position 7, ring 3, core 5 is electrically the same displacement as
        // a fixed rotor at position 5.
        let proton = Proton2Rotor::new(
            polish::body(RotorId::A),
            polish::rotor(RotorId::A),
            CoreSide::One,
            core_setting(5),
            ring(3),
            position(7),
        );
        let fixed = PositionedRotor::new(polish::rotor(RotorId::A), position(5));

        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            assert_eq!(proton.right_to_left(input), fixed.right_to_left(input));
            assert_eq!(proton.left_to_right(input), fixed.left_to_right(input));
        }
    }

    #[test]
    fn side_two_is_inverse_in_both_signal_directions_at_all_settings() {
        for id in RotorId::ALL {
            for p in 0..CONTACT_COUNT as u8 {
                // Non-basic offsets exercise the coordinate transform at the
                // same time as the mirrored core transform.
                let rotor = Proton2Rotor::new(
                    polish::body(id),
                    polish::rotor(id),
                    CoreSide::Two,
                    core_setting((p + 11) % 30),
                    ring((p + 7) % 30),
                    position(p),
                );

                for value in 0..CONTACT_COUNT as u8 {
                    let input = contact(value);
                    assert_eq!(rotor.left_to_right(rotor.right_to_left(input)), input);
                    assert_eq!(rotor.right_to_left(rotor.left_to_right(input)), input);
                }
            }
        }
    }

    #[test]
    fn core_mixing_keeps_body_and_electrical_identity_separate() {
        let rotor = Proton2Rotor::new(
            polish::body(RotorId::K),
            polish::rotor(RotorId::A),
            CoreSide::One,
            CoreSetting::A,
            RingSetting::A,
            position(0),
        );

        assert_eq!(rotor.body_id().rotor_id(), RotorId::K);
        assert_eq!(rotor.core_id(), RotorId::A);

        // In the overall basic electrical setting, the K body with the A core
        // must behave electrically as core A.  Mechanical pin behaviour belongs
        // to the K body and is deliberately deferred to the stepping phase.
        let fixed_a = PositionedRotor::new(polish::rotor(RotorId::A), position(0));
        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            assert_eq!(rotor.right_to_left(input), fixed_a.right_to_left(input));
        }
    }

    #[test]
    fn set_position_changes_only_dynamic_position() {
        let mut rotor = basic(RotorId::A, 0);
        let body = rotor.body_id();
        let core = rotor.core_id();
        let side = rotor.core_side();
        let core_setting = rotor.core_setting();
        let ring = rotor.ring_setting();

        rotor.set_position(position(12));

        assert_eq!(rotor.position(), position(12));
        assert_eq!(rotor.body_id(), body);
        assert_eq!(rotor.core_id(), core);
        assert_eq!(rotor.core_side(), side);
        assert_eq!(rotor.core_setting(), core_setting);
        assert_eq!(rotor.ring_setting(), ring);
    }
}
