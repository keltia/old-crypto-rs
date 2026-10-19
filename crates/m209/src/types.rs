//! Checked machine-key primitives. These types do not implement the mechanism.
use thiserror::Error;

/// Number of independently advancing pin wheels.
pub const WHEEL_COUNT: usize = 6;
/// Number of lug-bearing bars in the drum.
pub const DRUM_BAR_COUNT: usize = 27;
/// Visible letter markings, in physical wheel order (TM 11-380, §5a).
pub const WHEEL_ALPHABETS: [&str; WHEEL_COUNT] = [
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "ABCDEFGHIJKLMNOPQRSTUVXYZ",
    "ABCDEFGHIJKLMNOPQRSTUVX",
    "ABCDEFGHIJKLMNOPQRSTU",
    "ABCDEFGHIJKLMNOPQRS",
    "ABCDEFGHIJKLMNOPQ",
];
/// Number of pins on each wheel, in physical order.
pub const WHEEL_SIZES: [u8; WHEEL_COUNT] = [26, 25, 23, 21, 19, 17];

/// Error for an invalid M-209 key component.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    #[error("M-209 contact {0} is outside 0..26")]
    InvalidContact(u8),
    #[error("{0:?} is not an uppercase A-Z contact")]
    InvalidLetter(char),
    #[error("M-209 wheel {0} is outside 1..=6")]
    InvalidWheel(u8),
    #[error("position {index} is outside wheel {wheel:?} range")]
    InvalidPosition { wheel: WheelId, index: u8 },
    #[error("letter {letter:?} does not occur on wheel {wheel:?}")]
    InvalidWheelLetter { wheel: WheelId, letter: char },
    #[error("pin bits {bits:#x} exceed wheel {wheel:?} capacity")]
    InvalidPinBits { wheel: WheelId, bits: u32 },
    #[error("M-209 lug {0} is outside 0..=6")]
    InvalidLug(u8),
}

/// An input/output letter contact (A=0 through Z=25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Contact(u8);
impl Contact {
    pub const COUNT: u8 = 26;
    pub const A: Self = Self(0);
    pub const fn new(index: u8) -> Option<Self> {
        if index < Self::COUNT { Some(Self(index)) } else { None }
    }
    pub const fn index(self) -> u8 { self.0 }
    pub const fn letter(self) -> char { (b'A' + self.0) as char }
    pub fn from_letter(letter: char) -> Result<Self, KeyError> {
        if letter.is_ascii_uppercase() { Ok(Self(letter as u8 - b'A')) }
        else { Err(KeyError::InvalidLetter(letter)) }
    }
}
impl TryFrom<u8> for Contact {
    type Error = KeyError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(KeyError::InvalidContact(value))
    }
}

/// A physically numbered wheel (1 through 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WheelId(u8);
impl WheelId {
    pub const fn new(number: u8) -> Option<Self> {
        if number >= 1 && number <= WHEEL_COUNT as u8 { Some(Self(number)) } else { None }
    }
    pub const fn number(self) -> u8 { self.0 }
    pub const fn array_index(self) -> usize { (self.0 - 1) as usize }
    pub const fn size(self) -> u8 { WHEEL_SIZES[self.array_index()] }
    pub const fn alphabet(self) -> &'static str { WHEEL_ALPHABETS[self.array_index()] }
    pub fn position_for_letter(self, letter: char) -> Result<WheelPosition, KeyError> {
        self.alphabet().chars().position(|c| c == letter)
            .map(|i| WheelPosition { wheel: self, index: i as u8 })
            .ok_or(KeyError::InvalidWheelLetter { wheel: self, letter })
    }
}
impl TryFrom<u8> for WheelId {
    type Error = KeyError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(KeyError::InvalidWheel(value))
    }
}

/// A visible wheel-indicator position, indexed within its *own* alphabet.
/// This does not yet encode the offset to the mechanically sensed pin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WheelPosition { wheel: WheelId, index: u8 }
impl WheelPosition {
    pub const fn new(wheel: WheelId, index: u8) -> Option<Self> {
        if index < wheel.size() { Some(Self { wheel, index }) } else { None }
    }
    pub const fn wheel(self) -> WheelId { self.wheel }
    pub const fn index(self) -> u8 { self.index }
    pub fn letter(self) -> char { self.wheel.alphabet().as_bytes()[self.index as usize] as char }
    pub fn advance(self) -> Self {
        Self { wheel: self.wheel, index: (self.index + 1) % self.wheel.size() }
    }
}

/// Per-wheel effective-pin settings: bit i corresponds to the i-th printed letter.
/// Unused higher bits must be zero. Pin sensing is implemented in Step 5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinPattern { wheel: WheelId, bits: u32 }
impl PinPattern {
    pub const fn empty(wheel: WheelId) -> Self { Self { wheel, bits: 0 } }
    pub fn from_bits(wheel: WheelId, bits: u32) -> Result<Self, KeyError> {
        if bits >> wheel.size() != 0 { Err(KeyError::InvalidPinBits { wheel, bits }) }
        else { Ok(Self { wheel, bits }) }
    }
    pub fn from_letters(wheel: WheelId, letters: &str) -> Result<Self, KeyError> {
        let mut bits = 0u32;
        for letter in letters.chars() {
            let index = wheel.position_for_letter(letter)?.index();
            bits |= 1u32 << index;
        }
        Ok(Self { wheel, bits })
    }
    pub const fn wheel(self) -> WheelId { self.wheel }
    pub const fn bits(self) -> u32 { self.bits }
    pub const fn is_effective(self, position: WheelPosition) -> Option<bool> {
        if self.wheel.number() != position.wheel().number() { return None; }
        Some(self.bits & (1u32 << position.index()) != 0)
    }
}

/// Drum-bar lug setting: zero is neutral; 1..=6 identifies a wheel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Lug(u8);
impl Lug {
    pub const NEUTRAL: Self = Self(0);
    pub const fn new(value: u8) -> Option<Self> {
        if value <= WHEEL_COUNT as u8 { Some(Self(value)) } else { None }
    }
    pub const fn value(self) -> u8 { self.0 }
    pub const fn wheel(self) -> Option<WheelId> { WheelId::new(self.0) }
}
impl TryFrom<u8> for Lug {
    type Error = KeyError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(KeyError::InvalidLug(value))
    }
}

/// The two *ordered* lug columns of one drum bar.
/// Historical column restrictions will be validated in Step 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrumBar { left: Lug, right: Lug }
impl DrumBar {
    pub const fn new(left: Lug, right: Lug) -> Self { Self { left, right } }
    pub const fn left(self) -> Lug { self.left }
    pub const fn right(self) -> Lug { self.right }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn contact_bounds_and_roundtrip() {
        for n in 0..26 { let c = Contact::try_from(n).unwrap(); assert_eq!(Contact::from_letter(c.letter()), Ok(c)); }
        assert!(Contact::try_from(26).is_err());
        assert!(Contact::from_letter('a').is_err());
    }
    #[test]
    fn wheel_alphabets_are_exact_and_distinct() {
        for n in 1..=6 {
            let wheel = WheelId::new(n).unwrap();
            let alphabet = wheel.alphabet();
            assert_eq!(alphabet.len(), wheel.size() as usize);
            let mut seen = 0u32;
            for (index, letter) in alphabet.chars().enumerate() {
                let pos = wheel.position_for_letter(letter).unwrap();
                assert_eq!(pos.index(), index as u8);
                assert_eq!(pos.letter(), letter);
                let bit = 1u32 << (letter as u8 - b'A');
                assert_eq!(seen & bit, 0);
                seen |= bit;
            }
        }
        assert!(WheelId::new(0).is_none());
        assert!(WheelId::new(7).is_none());
        assert!(WheelId::new(2).unwrap().position_for_letter('W').is_err());
        assert!(WheelId::new(3).unwrap().position_for_letter('W').is_err());
    }
    #[test]
    fn positions_wrap_at_each_wheel_length() {
        for n in 1..=6 {
            let wheel = WheelId::new(n).unwrap();
            assert!(WheelPosition::new(wheel, wheel.size()).is_none());
            let first = WheelPosition::new(wheel, 0).unwrap();
            let mut p = first;
            for _ in 0..wheel.size() { p = p.advance(); }
            assert_eq!(p, first);
            assert_eq!(WheelPosition::new(wheel, wheel.size() - 1).unwrap().advance(), first);
        }
    }
    #[test]
    fn pin_patterns_validate_range_and_wheel_identity() {
        for n in 1..=6 {
            let wheel = WheelId::new(n).unwrap();
            let all = PinPattern::from_letters(wheel, wheel.alphabet()).unwrap();
            assert_eq!(all.bits(), (1u32 << wheel.size()) - 1);
            assert!(PinPattern::from_bits(wheel, 1u32 << wheel.size()).is_err());
            assert_eq!(PinPattern::empty(wheel).bits(), 0);
            let first = WheelPosition::new(wheel, 0).unwrap();
            assert_eq!(all.is_effective(first), Some(true));
        }
        let a = WheelId::new(1).unwrap();
        let b = WheelId::new(2).unwrap();
        assert_eq!(PinPattern::empty(a).is_effective(WheelPosition::new(b, 0).unwrap()), None);
        assert!(PinPattern::from_letters(b, "W").is_err());
    }
    #[test]
    fn lug_bounds_and_ordered_bar() {
        assert!(Lug::try_from(7).is_err());
        assert_eq!(Lug::NEUTRAL.wheel(), None);
        for n in 1..=6 { assert_eq!(Lug::try_from(n).unwrap().wheel().unwrap().number(), n); }
        let bar = DrumBar::new(Lug::new(3).unwrap(), Lug::NEUTRAL);
        assert_eq!(bar.left().value(), 3);
        assert_eq!(bar.right(), Lug::NEUTRAL);
    }
}
