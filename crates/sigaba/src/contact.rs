//! Checked SIGABA contact and position coordinate types.
//!
//! The ECM Mark II uses two distinct electrical coordinate systems:
//! - 26 positions (`A` through `Z`) for the cipher/control rotors;
//! - 10 positions (`0` through `9`) for the index rotors.
//!
//! These types deliberately keep the two systems distinct so a 10-contact
//! index value cannot accidentally be passed to a 26-contact rotor.

use core::fmt;

/// Number of contacts on a cipher/control rotor.
pub(crate) const ALPHABET_CONTACTS: u8 = 26;

/// Number of contacts on an index rotor.
pub(crate) const INDEX_CONTACTS: u8 = 10;

/// A checked electrical contact in the 26-contact cipher/control system.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Contact26(u8);

impl Contact26 {
    /// Construct a contact from its zero-based `A=0 .. Z=25` coordinate.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < ALPHABET_CONTACTS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the zero-based coordinate.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Add a signed displacement modulo 26.
    #[must_use]
    pub(crate) fn offset(self, amount: i16) -> Self {
        Self(wrapping_offset(self.0, amount, ALPHABET_CONTACTS))
    }
}

/// A checked electrical contact in the 10-contact index system.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Contact10(u8);

impl Contact10 {
    /// Construct a contact from its zero-based `0..9` coordinate.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < INDEX_CONTACTS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the zero-based coordinate.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Add a signed displacement modulo 10.
    #[must_use]
    pub(crate) fn offset(self, amount: i16) -> Self {
        Self(wrapping_offset(self.0, amount, INDEX_CONTACTS))
    }
}

/// A checked angular position of a 26-contact cipher/control rotor.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Position26(u8);

impl Position26 {
    /// Construct a position from zero-based `A=0 .. Z=25`.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < ALPHABET_CONTACTS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The `A` position.
    pub const A: Self = Self(0);

    /// Return the zero-based coordinate.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Move the visible rotor position by a signed amount modulo 26.
    #[must_use]
    pub(crate) fn offset(self, amount: i16) -> Self {
        Self(wrapping_offset(self.0, amount, ALPHABET_CONTACTS))
    }
}

/// A checked angular position of a 10-contact index rotor.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Position10(u8);

impl Position10 {
    /// Construct a position from zero-based `0..9`.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < INDEX_CONTACTS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Position `0`.
    pub const ZERO: Self = Self(0);

    /// Return the zero-based coordinate.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Move the index-wheel position by a signed amount modulo 10.
    #[must_use]
    pub(crate) fn offset(self, amount: i16) -> Self {
        Self(wrapping_offset(self.0, amount, INDEX_CONTACTS))
    }
}

fn wrapping_offset(value: u8, amount: i16, modulus: u8) -> u8 {
    (i16::from(value) + amount).rem_euclid(i16::from(modulus)) as u8
}

impl fmt::Display for Contact26 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ch = char::from(b'A' + self.0);
        write!(f, "{ch}")
    }
}

impl fmt::Display for Position26 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ch = char::from(b'A' + self.0);
        write!(f, "{ch}")
    }
}

impl fmt::Display for Contact10 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Position10 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact26_accepts_exactly_zero_through_twenty_five() {
        for value in 0..26 {
            assert_eq!(Contact26::new(value).unwrap().get(), value);
        }

        for value in 26..=u8::MAX {
            assert!(Contact26::new(value).is_none());
        }
    }

    #[test]
    fn contact10_accepts_exactly_zero_through_nine() {
        for value in 0..10 {
            assert_eq!(Contact10::new(value).unwrap().get(), value);
        }

        for value in 10..=u8::MAX {
            assert!(Contact10::new(value).is_none());
        }
    }

    #[test]
    fn position_ranges_are_distinct_and_checked() {
        assert!(Position26::new(25).is_some());
        assert!(Position26::new(26).is_none());

        assert!(Position10::new(9).is_some());
        assert!(Position10::new(10).is_none());
    }

    #[test]
    fn contact26_offset_wraps_in_both_directions() {
        let a = Contact26::new(0).unwrap();
        let z = Contact26::new(25).unwrap();

        assert_eq!(a.offset(-1), z);
        assert_eq!(z.offset(1), a);
        assert_eq!(a.offset(26), a);
        assert_eq!(a.offset(-26), a);
        assert_eq!(a.offset(53).get(), 1);
        assert_eq!(a.offset(-53).get(), 25);
    }

    #[test]
    fn contact10_offset_wraps_in_both_directions() {
        let zero = Contact10::new(0).unwrap();
        let nine = Contact10::new(9).unwrap();

        assert_eq!(zero.offset(-1), nine);
        assert_eq!(nine.offset(1), zero);
        assert_eq!(zero.offset(10), zero);
        assert_eq!(zero.offset(-10), zero);
        assert_eq!(zero.offset(21).get(), 1);
        assert_eq!(zero.offset(-21).get(), 9);
    }

    #[test]
    fn positions_use_the_same_modular_coordinate_arithmetic() {
        assert_eq!(Position26::A.offset(-1).get(), 25);
        assert_eq!(Position26::A.offset(27).get(), 1);

        assert_eq!(Position10::ZERO.offset(-1).get(), 9);
        assert_eq!(Position10::ZERO.offset(11).get(), 1);
    }

    #[test]
    fn display_matches_physical_markings() {
        assert_eq!(Contact26::new(0).unwrap().to_string(), "A");
        assert_eq!(Contact26::new(25).unwrap().to_string(), "Z");
        assert_eq!(Position26::new(14).unwrap().to_string(), "O");

        assert_eq!(Contact10::new(0).unwrap().to_string(), "0");
        assert_eq!(Contact10::new(9).unwrap().to_string(), "9");
        assert_eq!(Position10::new(7).unwrap().to_string(), "7");
    }
}
