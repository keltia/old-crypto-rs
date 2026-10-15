//! Assignment of the three physical twenties switches to motion speeds.
//!
//! The speed order is part of a PURPLE key; it does not perform stepping.

use core::fmt;

use crate::TwentiesSwitchId;

/// Invalid speed assignment: a physical twenties switch was selected more than once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MotionError {
    /// The physical switch used by more than one speed.
    pub repeated: TwentiesSwitchId,
}

impl fmt::Display for MotionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "twenties switch {:?} occurs more than once in motion order", self.repeated)
    }
}

impl std::error::Error for MotionError {}

/// Physical twenties switches assigned to fast, middle, and slow motion, in that order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurpleMotion {
    order: [TwentiesSwitchId; 3],
}

impl PurpleMotion {
    /// Assign distinct physical switches to the fast, middle, and slow roles.
    pub const fn new(
        fast: TwentiesSwitchId,
        middle: TwentiesSwitchId,
        slow: TwentiesSwitchId,
    ) -> Result<Self, MotionError> {
        if fast.index() == middle.index() || fast.index() == slow.index() {
            return Err(MotionError { repeated: fast });
        }
        if middle.index() == slow.index() {
            return Err(MotionError { repeated: middle });
        }
        Ok(Self { order: [fast, middle, slow] })
    }

    /// The switch that moves at fast speed.
    pub const fn fast(self) -> TwentiesSwitchId { self.order[0] }
    /// The switch that moves at middle speed.
    pub const fn middle(self) -> TwentiesSwitchId { self.order[1] }
    /// The switch that moves at slow speed.
    pub const fn slow(self) -> TwentiesSwitchId { self.order[2] }
    /// All three physical switch identities, ordered fast, middle, slow.
    pub const fn order(self) -> [TwentiesSwitchId; 3] { self.order }

    /// Returns the speed rank for a physical switch: 0 = fast, 1 = middle, 2 = slow.
    pub const fn speed_index(self, id: TwentiesSwitchId) -> usize {
        if self.order[0].index() == id.index() { 0 }
        else if self.order[1].index() == id.index() { 1 }
        else { 2 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use TwentiesSwitchId::{One, Two, Three};

    #[test]
    fn all_six_assignments_are_valid() {
        let ids = [One, Two, Three];
        let mut seen = 0;
        for &a in &ids {
            for &b in &ids {
                for &c in &ids {
                    let result = PurpleMotion::new(a, b, c);
                    if a != b && a != c && b != c {
                        let motion = result.unwrap();
                        assert_eq!(motion.order(), [a, b, c]);
                        assert_eq!(motion.fast(), a);
                        assert_eq!(motion.middle(), b);
                        assert_eq!(motion.slow(), c);
                        assert_eq!(motion.speed_index(a), 0);
                        assert_eq!(motion.speed_index(b), 1);
                        assert_eq!(motion.speed_index(c), 2);
                        seen += 1;
                    } else {
                        assert!(result.is_err());
                    }
                }
            }
        }
        assert_eq!(seen, 6);
    }

    #[test]
    fn historical_motion_two_three_one() {
        let motion = PurpleMotion::new(Two, Three, One).unwrap();
        assert_eq!(motion.order(), [Two, Three, One]);
    }

    #[test]
    fn duplicate_assignments_report_the_switch() {
        assert_eq!(PurpleMotion::new(One, One, Three), Err(MotionError { repeated: One }));
        assert_eq!(PurpleMotion::new(One, Two, Two), Err(MotionError { repeated: Two }));
        assert_eq!(PurpleMotion::new(Three, Two, Three), Err(MotionError { repeated: Three }));
    }
}
