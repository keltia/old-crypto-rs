//! Checked TSEC/KL-7 contact, position, and wiring coordinate types.
//!
//! The KL-7 uses a 36-contact electrical system:
//! - 36 contacts (0..35) for each rotor and endplate pin;
//! - 26 of these pins correspond to letters A–Z (via the sliding baseplate);
//! - 10 of these pins connect to re-entry loops 0–9.
//!
//! The physical alphabet ring on each rotor contains 36 positions:
//! - 26 letter positions (`A` through `Z`);
//! - 10 blank intermediate positions designated with a '+' (e.g. `B+`, `E+`, `M+`).

use core::fmt;

/// Total number of contacts on a KL-7 rotor.
pub const ROTOR_CONTACTS: u8 = 36;

/// Number of alphabet letters in standard English text.
pub const ALPHABET_LETTERS: u8 = 26;

/// Number of loop-back re-entry connections.
pub const REENTRY_CONTACTS: u8 = 10;

/// Alphabet ring labels for all 36 positions (0-indexed).
///
/// Letters are at positions:
/// 0=A, 1=B, 2=B+, 3=C, 4=D, 5=E, 6=E+, 7=F, 8=G, 9=G+, 10=H, 11=I, 12=J,
/// 13=J+, 14=K, 15=L, 16=M, 17=M+, 18=N, 19=O, 20=O+, 21=P, 22=Q, 23=R,
/// 24=R+, 25=S, 26=T, 27=T+, 28=U, 29=V, 30=W, 31=W+, 32=X, 33=Y, 34=Z, 35=Z+
pub const ALPHABET_RING_LABELS: [&str; 36] = [
    "A", "B", "B+", "C", "D", "E", "E+", "F", "G", "G+", "H", "I", "J", "J+", "K", "L", "M",
    "M+", "N", "O", "O+", "P", "Q", "R", "R+", "S", "T", "T+", "U", "V", "W", "W+", "X", "Y",
    "Z", "Z+",
];

/// A checked electrical contact in the 36-contact KL-7 system.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Contact36(u8);

impl Contact36 {
    /// Construct a contact from its zero-based `0..35` coordinate.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < ROTOR_CONTACTS {
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

    /// Add a signed displacement modulo 36.
    #[must_use]
    pub const fn offset(self, amount: i16) -> Self {
        Self(wrapping_offset(self.0, amount, ROTOR_CONTACTS))
    }
}

/// A checked contact representing one of the 26 alphabet characters (0..25).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Contact26(u8);

impl Contact26 {
    /// Construct an alphabet contact from its zero-based `A=0 .. Z=25` coordinate.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < ALPHABET_LETTERS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Construct from an ASCII uppercase letter.
    #[must_use]
    pub const fn from_ascii_letter(ch: char) -> Option<Self> {
        if ch.is_ascii_uppercase() {
            Some(Self((ch as u8) - b'A'))
        } else if ch.is_ascii_lowercase() {
            Some(Self((ch as u8) - b'a'))
        } else {
            None
        }
    }

    /// Return the zero-based coordinate (0..25).
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Convert to uppercase ASCII character (`'A'..='Z'`).
    #[must_use]
    pub const fn to_ascii_char(self) -> char {
        (b'A' + self.0) as char
    }

    /// Add a signed displacement modulo 26.
    #[must_use]
    pub const fn offset(self, amount: i16) -> Self {
        Self(wrapping_offset(self.0, amount, ALPHABET_LETTERS))
    }
}

/// A checked re-entry wire index (0..9).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ReentryWire(u8);

impl ReentryWire {
    /// Construct a re-entry wire index from `0..9`.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < REENTRY_CONTACTS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the zero-based re-entry index (0..9).
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// A checked rotational position of a 36-contact KL-7 rotor (0..35).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Position36(u8);

impl Position36 {
    /// Construct a position from zero-based `0..35`.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < ROTOR_CONTACTS {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Construct from 1-based index `1..=36`.
    #[must_use]
    pub const fn from_one_based(value: u8) -> Option<Self> {
        if value >= 1 && value <= ROTOR_CONTACTS {
            Some(Self(value - 1))
        } else {
            None
        }
    }

    /// The default index position 0 (`A` / `1`).
    pub const ZERO: Self = Self(0);

    /// Return the zero-based coordinate.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Return 1-based number (1..=36).
    #[must_use]
    pub const fn to_one_based(self) -> u8 {
        self.0 + 1
    }

    /// Return the alphabet ring label (e.g. "A", "B", "B+", etc.).
    #[must_use]
    pub const fn label(self) -> &'static str {
        ALPHABET_RING_LABELS[self.0 as usize]
    }

    /// Parse position from label (e.g. "A", "B+", "1".."36").
    pub fn parse(s: &str) -> Option<Self> {
        let trimmed = s.trim();
        if let Ok(num) = trimmed.parse::<u8>() {
            return Self::from_one_based(num);
        }
        for (idx, &label) in ALPHABET_RING_LABELS.iter().enumerate() {
            if label.eq_ignore_ascii_case(trimmed) {
                return Some(Self(idx as u8));
            }
        }
        None
    }

    /// Move the rotor position by a signed amount modulo 36.
    #[must_use]
    pub const fn offset(self, amount: i16) -> Self {
        Self(wrapping_offset(self.0, amount, ROTOR_CONTACTS))
    }

    /// Advance the rotor position by one step.
    #[must_use]
    pub const fn step(self) -> Self {
        Self((self.0 + 1) % ROTOR_CONTACTS)
    }
}

/// Helper function for Euclidean wrapping modulo arithmetic.
#[must_use]
pub const fn wrapping_offset(base: u8, amount: i16, modulus: u8) -> u8 {
    let m = modulus as i16;
    let r = (base as i16 + amount) % m;
    if r < 0 {
        (r + m) as u8
    } else {
        r as u8
    }
}

impl fmt::Display for Contact36 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Display for Contact26 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ascii_char())
    }
}

impl fmt::Display for Position36 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact36_validity_and_offsets() {
        assert!(Contact36::new(0).is_some());
        assert!(Contact36::new(35).is_some());
        assert!(Contact36::new(36).is_none());

        let c = Contact36::new(5).unwrap();
        assert_eq!(c.offset(31).get(), 0);
        assert_eq!(c.offset(-6).get(), 35);
    }

    #[test]
    fn contact26_char_conversion() {
        let c = Contact26::from_ascii_letter('A').unwrap();
        assert_eq!(c.get(), 0);
        assert_eq!(c.to_ascii_char(), 'A');

        let c_z = Contact26::from_ascii_letter('z').unwrap();
        assert_eq!(c_z.get(), 25);
        assert_eq!(c_z.to_ascii_char(), 'Z');
    }

    #[test]
    fn position36_labels_and_parsing() {
        assert_eq!(Position36::new(0).unwrap().label(), "A");
        assert_eq!(Position36::new(2).unwrap().label(), "B+");
        assert_eq!(Position36::new(17).unwrap().label(), "M+");
        assert_eq!(Position36::new(35).unwrap().label(), "Z+");

        assert_eq!(Position36::parse("A"), Some(Position36::new(0).unwrap()));
        assert_eq!(Position36::parse("B+"), Some(Position36::new(2).unwrap()));
        assert_eq!(Position36::parse("18"), Some(Position36::new(17).unwrap()));
        assert_eq!(Position36::parse("36"), Some(Position36::new(35).unwrap()));
    }
}
