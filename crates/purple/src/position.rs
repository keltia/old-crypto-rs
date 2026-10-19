//! Switch positions and their historical one-based numbering.

use crate::PositionError;

/// A PURPLE switch position, expressed externally as a historical number 1–25.
///
/// Unlike contacts, switch positions are **one-based** in the public API.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwitchPosition(u8);

impl SwitchPosition {
    /// Number of positions in each switch.
    pub const COUNT: u8 = 25;

    /// Construct from a historical position (1–25 inclusive).
    pub const fn new(number: u8) -> Result<Self, PositionError> {
        if number >= 1 && number <= Self::COUNT {
            Ok(Self(number))
        } else {
            Err(PositionError(number))
        }
    }

    /// Return the historical one-based position number.
    pub const fn number(self) -> u8 {
        self.0
    }

    /// Return the zero-based index for looking up a wiring table row.
    pub const fn index(self) -> usize {
        (self.0 - 1) as usize
    }

    /// Advance one position, wrapping 25 back to 1.
    pub const fn advanced(self) -> Self {
        if self.0 == Self::COUNT { Self(1) } else { Self(self.0 + 1) }
    }
}

impl TryFrom<u8> for SwitchPosition {
    type Error = PositionError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<SwitchPosition> for u8 {
    fn from(value: SwitchPosition) -> Self {
        value.number()
    }
}

/// Physical identity of one of the three twenties switches, independent of speed.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TwentiesSwitchId {
    One,
    Two,
    Three,
}

impl TwentiesSwitchId {
    /// Index of this physical switch in an array ordered #1, #2, #3.
    pub const fn index(self) -> usize {
        match self {
            Self::One => 0,
            Self::Two => 1,
            Self::Three => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_accept_exactly_one_through_twenty_five() {
        for number in 1..=25 {
            let position = SwitchPosition::new(number).unwrap();
            assert_eq!(position.number(), number);
            assert_eq!(position.index(), usize::from(number - 1));
            assert_eq!(SwitchPosition::try_from(number), Ok(position));
            assert_eq!(u8::from(position), number);
        }
        for number in [0, 26, u8::MAX] {
            assert_eq!(SwitchPosition::new(number), Err(PositionError(number)));
        }
    }

    #[test]
    fn wrapping_and_progression() {
        let mut position = SwitchPosition::new(1).unwrap();
        for next in 2..=25 {
            position = position.advanced();
            assert_eq!(position.number(), next);
        }
        assert_eq!(position.advanced().number(), 1);
    }

    #[test]
    fn switch_id_is_not_speed() {
        assert_eq!(TwentiesSwitchId::One.index(), 0);
        assert_eq!(TwentiesSwitchId::Two.index(), 1);
        assert_eq!(TwentiesSwitchId::Three.index(), 2);
    }
}
