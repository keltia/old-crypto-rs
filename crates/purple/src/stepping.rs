//! PURPLE switch movement, independent of electrical substitution.
//!
//! Positions are historical 1..=25. The initial positions are used for a
//! character, and `step` advances the state *after* processing that character.
//!
//! Source: Freeman, Sullivan & Weierud, *PURPLE Revealed* (2003),
//! Figure 10 (turnover trace), and the accompanying switch-motion description:
//! https://cryptocellar.org/pubs/purple-revealed.pdf

use crate::{PurpleMotion, SwitchPosition, TwentiesSwitchId};

/// Four switch positions: sixes, followed by physical twenties #1, #2, #3.
///
/// The motion assignment is fixed for the lifetime of this stepping state;
/// it assigns speeds to the three *physical* twenties switches.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurpleStepping {
    sixes: SwitchPosition,
    twenties: [SwitchPosition; 3],
    motion: PurpleMotion,
}

impl PurpleStepping {
    /// Construct a stepping state from validated historical positions.
    pub const fn new(
        sixes: SwitchPosition,
        twenties: [SwitchPosition; 3],
        motion: PurpleMotion,
    ) -> Self {
        Self { sixes, twenties, motion }
    }

    /// Current position of the sixes switch.
    pub const fn sixes(&self) -> SwitchPosition { self.sixes }

    /// Current positions in physical order (#1, #2, #3), not speed order.
    pub const fn twenties(&self) -> [SwitchPosition; 3] { self.twenties }

    /// Position of one physical twenties switch.
    pub const fn twenties_position(&self, id: TwentiesSwitchId) -> SwitchPosition {
        self.twenties[id.index()]
    }

    /// The immutable speed assignment (fast, middle, slow).
    pub const fn motion(&self) -> PurpleMotion { self.motion }

    /// Advance the machine after one character, returning the physical twenties
    /// switch which moved. The sixes switch *always* moves.
    ///
    /// Selection is based on the positions *before* this step:
    /// - sixes = 24 and middle = 25: slow moves;
    /// - otherwise, sixes = 25: middle moves;
    /// - otherwise: fast moves.
    ///
    /// Exactly one twenties switch moves, even at the double turnover.
    pub fn step(&mut self) -> TwentiesSwitchId {
        let selected = if self.sixes.number() == 24
            && self.twenties_position(self.motion.middle()).number() == 25
        {
            self.motion.slow()
        } else if self.sixes.number() == 25 {
            self.motion.middle()
        } else {
            self.motion.fast()
        };
        self.twenties[selected.index()] = self.twenties[selected.index()].advanced();
        self.sixes = self.sixes.advanced();
        selected
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TwentiesSwitchId::{One, Two, Three};

    fn p(n: u8) -> SwitchPosition { SwitchPosition::new(n).unwrap() }

    #[test]
    fn sixes_advances_on_every_character_and_wraps() {
        let mut s = PurpleStepping::new(p(1), [p(1); 3], PurpleMotion::new(One, Two, Three).unwrap());
        for i in 1..=25 {
            assert_eq!(s.sixes().number(), i);
            s.step();
        }
        assert_eq!(s.sixes().number(), 1);
    }

    #[test]
    fn figure_ten_historical_turnover_trace() {
        // PURPLE Revealed, Figure 10: #1 fast, #2 middle, #3 slow.
        let mut s = PurpleStepping::new(p(21), [p(1), p(25), p(5)],
                                         PurpleMotion::new(One, Two, Three).unwrap());
        let expected = [
            (21, [1, 25, 5]), (22, [2, 25, 5]), (23, [3, 25, 5]),
            (24, [4, 25, 5]), (25, [4, 25, 6]), (1, [4, 1, 6]),
            (2, [5, 1, 6]),
        ];
        for (i, (six, twenties)) in expected.iter().enumerate() {
            assert_eq!(s.sixes().number(), *six, "row {i}");
            assert_eq!(s.twenties().map(SwitchPosition::number), *twenties, "row {i}");
            if i + 1 != expected.len() { s.step(); }
        }
    }

    #[test]
    fn ordinary_and_middle_turnovers_when_middle_not_at_25() {
        let mut s = PurpleStepping::new(p(24), [p(25), p(4), p(7)],
                                         PurpleMotion::new(One, Two, Three).unwrap());
        assert_eq!(s.step(), One); // sixes was 24, but middle was not 25
        assert_eq!(s.twenties().map(SwitchPosition::number), [1, 4, 7]);
        assert_eq!(s.step(), Two); // sixes was 25
        assert_eq!(s.twenties().map(SwitchPosition::number), [1, 5, 7]);
    }

    #[test]
    fn switch_selection_uses_physical_ids_for_all_six_motions() {
        let ids = [One, Two, Three];
        for &fast in &ids { for &middle in &ids { for &slow in &ids {
            let Ok(motion) = PurpleMotion::new(fast, middle, slow) else { continue };
            let mut positions = [p(7); 3];
            positions[middle.index()] = p(25);
            let mut s = PurpleStepping::new(p(24), positions, motion);
            assert_eq!(s.step(), slow);
            assert_eq!(s.twenties_position(slow), p(8));
            assert_eq!(s.step(), middle);
            assert_eq!(s.twenties_position(middle), p(1));
            assert_eq!(s.step(), fast);
            assert_eq!(s.twenties_position(fast), p(8));
        } } }
    }

    #[test]
    fn exact_full_cycle_for_all_four_switches() {
        let initial = PurpleStepping::new(p(9), [p(1), p(24), p(6)],
                                          PurpleMotion::new(Two, Three, One).unwrap());
        let mut s = initial;
        for i in 1..=15_625 {
            s.step();
            if i != 15_625 { assert_ne!(s, initial, "early repeat at step {i}"); }
        }
        assert_eq!(s, initial);
    }
}
