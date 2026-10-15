//! Stationary electrical substitutions for the four PURPLE stepping switches.
//!
//! The historical tables are in SIS *decipher* direction. A switch never
//! advances implicitly during a substitution: the future stepping mechanism
//! is responsible for changing its position between characters.

use crate::data::{cached_sixes_permutations, cached_twenties_permutations};
use crate::{SixesContact, SixesPermutation, SwitchPosition, TwentiesContact,
    TwentiesPermutation, TwentiesSwitchId};

/// The six-contact switch at one of its 25 historical positions.
pub struct SixesSwitch {
    position: SwitchPosition,
    wiring: &'static [SixesPermutation; 25],
}

impl SixesSwitch {
    /// Construct the switch at a validated historical position (1–25).
    pub fn new(position: SwitchPosition) -> Self {
        Self { position, wiring: cached_sixes_permutations() }
    }

    /// Current position in historical one-based notation.
    pub const fn position(&self) -> SwitchPosition {
        self.position
    }

    /// Change position without applying any electrical substitution.
    pub fn set_position(&mut self, position: SwitchPosition) {
        self.position = position;
    }

    /// Apply the published SIS decipher-direction wiring.
    pub fn decipher(&self, input: SixesContact) -> SixesContact {
        let output = self.wiring[self.position.index()].forward(input.index());
        SixesContact::new(output).expect("validated sixes wiring preserves contact domain")
    }

    /// Apply the inverse of the published decipher-direction wiring.
    pub fn encipher(&self, input: SixesContact) -> SixesContact {
        let output = self.wiring[self.position.index()].inverse(input.index());
        SixesContact::new(output).expect("validated sixes wiring preserves contact domain")
    }
}

/// A particular physical twenty-contact switch at one historical position.
pub struct TwentiesSwitch {
    id: TwentiesSwitchId,
    position: SwitchPosition,
    wiring: &'static [TwentiesPermutation; 25],
}

impl TwentiesSwitch {
    /// Construct physical switch #1, #2, or #3, independently of stepping speed.
    pub fn new(id: TwentiesSwitchId, position: SwitchPosition) -> Self {
        let wiring = &cached_twenties_permutations()[id.index()];
        Self { id, position, wiring }
    }

    /// Identity of this physical switch (not its future stepping role).
    pub const fn id(&self) -> TwentiesSwitchId {
        self.id
    }

    /// Current historical one-based position.
    pub const fn position(&self) -> SwitchPosition {
        self.position
    }

    /// Change position without applying any electrical substitution.
    pub fn set_position(&mut self, position: SwitchPosition) {
        self.position = position;
    }

    /// Apply the published SIS decipher-direction wiring.
    pub fn decipher(&self, input: TwentiesContact) -> TwentiesContact {
        let output = self.wiring[self.position.index()].forward(input.index());
        TwentiesContact::new(output).expect("validated twenties wiring preserves contact domain")
    }

    /// Apply the inverse of the published decipher-direction wiring.
    pub fn encipher(&self, input: TwentiesContact) -> TwentiesContact {
        let output = self.wiring[self.position.index()].inverse(input.index());
        TwentiesContact::new(output).expect("validated twenties wiring preserves contact domain")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::{SIXES_WIRING, TWENTIES_1_WIRING, TWENTIES_2_WIRING, TWENTIES_3_WIRING};

    fn pos(n: u8) -> SwitchPosition { SwitchPosition::new(n).unwrap() }

    #[test]
    fn sixes_matches_every_historical_row_and_round_trips() {
        let mut switch = SixesSwitch::new(pos(1));
        for n in 1..=25 {
            switch.set_position(pos(n));
            for input in 0..6 {
                let contact = SixesContact::new(input).unwrap();
                let deciphered = switch.decipher(contact);
                assert_eq!(deciphered.index(), SIXES_WIRING[(n - 1) as usize][input as usize]);
                assert_eq!(switch.encipher(deciphered), contact);
                assert_eq!(switch.decipher(switch.encipher(contact)), contact);
                assert_eq!(switch.position().number(), n, "substitution must not step");
            }
        }
    }

    #[test]
    fn twenties_match_every_historical_row_and_round_trip() {
        for (id, table) in [
            (TwentiesSwitchId::One, &TWENTIES_1_WIRING),
            (TwentiesSwitchId::Two, &TWENTIES_2_WIRING),
            (TwentiesSwitchId::Three, &TWENTIES_3_WIRING),
        ] {
            let mut switch = TwentiesSwitch::new(id, pos(1));
            assert_eq!(switch.id(), id);
            for n in 1..=25 {
                switch.set_position(pos(n));
                for input in 0..20 {
                    let contact = TwentiesContact::new(input).unwrap();
                    let deciphered = switch.decipher(contact);
                    assert_eq!(deciphered.index(), table[(n - 1) as usize][input as usize]);
                    assert_eq!(switch.encipher(deciphered), contact);
                    assert_eq!(switch.decipher(switch.encipher(contact)), contact);
                    assert_eq!(switch.position().number(), n);
                }
            }
        }
    }

    #[test]
    fn documented_sixes_and_identity_twenties_examples() {
        let switch = SixesSwitch::new(pos(1));
        assert_eq!(switch.decipher(SixesContact::new(0).unwrap()).index(), 1);
        let switch = TwentiesSwitch::new(TwentiesSwitchId::One, pos(20));
        for input in 0..20 {
            let c = TwentiesContact::new(input).unwrap();
            assert_eq!(switch.decipher(c), c);
            assert_eq!(switch.encipher(c), c);
        }
    }

    #[test]
    fn position_change_affects_only_chosen_switch() {
        let mut a = TwentiesSwitch::new(TwentiesSwitchId::One, pos(1));
        let b = TwentiesSwitch::new(TwentiesSwitchId::Two, pos(1));
        let input = TwentiesContact::new(0).unwrap();
        assert_eq!(a.decipher(input).index(), TWENTIES_1_WIRING[0][0]);
        assert_eq!(b.decipher(input).index(), TWENTIES_2_WIRING[0][0]);
        a.set_position(pos(2));
        assert_eq!(a.decipher(input).index(), TWENTIES_1_WIRING[1][0]);
        assert_eq!(b.position().number(), 1);
    }
}
