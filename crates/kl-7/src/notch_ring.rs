//! Exchangeable outer plastic notch rings for TSEC/KL-7 rotors.
//!
//! The KL-7 stepping unit uses 11 exchangeable outer notch rings (numbered 1 through 11).
//! Each ring has a unique 36-position pattern of cams (raised teeth) and notches (gaps).
//! When mounted on a rotor, the cams actuate the two-level sensing switches ($S_a$),
//! which drive the irregular rotor stepping solenoids.

use super::contact::{Position36, ROTOR_CONTACTS};
use core::fmt;

/// Identification of one of the 11 standard KL-7 notch rings.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NotchRingId {
    Ring1 = 1,
    Ring2 = 2,
    Ring3 = 3,
    Ring4 = 4,
    Ring5 = 5,
    Ring6 = 6,
    Ring7 = 7,
    Ring8 = 8,
    Ring9 = 9,
    Ring10 = 10,
    Ring11 = 11,
}

impl NotchRingId {
    /// Return the 1-based numeric ring ID (1..=11).
    #[must_use]
    pub const fn to_number(self) -> u8 {
        self as u8
    }

    /// Construct from 1-based number (1..=11).
    #[must_use]
    pub const fn from_number(num: u8) -> Option<Self> {
        match num {
            1 => Some(Self::Ring1),
            2 => Some(Self::Ring2),
            3 => Some(Self::Ring3),
            4 => Some(Self::Ring4),
            5 => Some(Self::Ring5),
            6 => Some(Self::Ring6),
            7 => Some(Self::Ring7),
            8 => Some(Self::Ring8),
            9 => Some(Self::Ring9),
            10 => Some(Self::Ring10),
            11 => Some(Self::Ring11),
            _ => None,
        }
    }
}

impl fmt::Display for NotchRingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_number())
    }
}

/// Standard 36-element cam patterns for rings 1 through 11.
///
/// `true` (1) represents a cam (active switch state).
/// `false` (0) represents a notch (inactive switch state).
pub const NOTCH_RING_PATTERNS: [[bool; 36]; 11] = [
    // Ring 1
    [
        true, false, false, false, true, false, false, false, false, true, false, false, false,
        true, true, false, true, false, true, false, false, false, true, true, false, false, true,
        true, false, false, true, true, false, false, false, true,
    ],
    // Ring 2
    [
        false, false, true, true, false, true, false, true, false, false, false, true, false, true,
        true, false, false, false, true, false, false, true, true, false, false, true, false, true,
        false, false, false, true, false, false, true, true,
    ],
    // Ring 3
    [
        true, true, false, false, false, false, true, true, false, true, false, false, false,
        false, true, false, false, false, true, false, false, false, false, true, false, true,
        false, true, false, true, false, true, false, false, true, false,
    ],
    // Ring 4
    [
        true, false, true, false, false, false, true, false, false, true, false, false, false,
        true, true, false, false, true, false, true, false, false, false, false, true, true, true,
        false, false, true, true, true, false, true, false, false,
    ],
    // Ring 5
    [
        true, false, true, false, false, true, true, false, false, false, true, false, false, true,
        false, false, false, true, true, false, false, true, false, true, false, true, false, true,
        true, false, false, false, false, true, true, false,
    ],
    // Ring 6
    [
        false, false, false, false, false, true, true, true, false, false, true, true, false,
        false, false, true, false, true, false, false, false, true, true, false, true, true, false,
        true, true, false, false, true, false, false, false, true,
    ],
    // Ring 7
    [
        true, true, false, false, true, false, false, true, true, false, false, true, true, false,
        false, false, false, true, false, false, false, true, false, true, false, false, false,
        true, true, false, true, true, false, true, false, false,
    ],
    // Ring 8
    [
        false, false, true, true, true, false, false, true, false, false, false, true, false, true,
        false, true, true, false, false, true, true, true, false, false, true, false, true, false,
        false, false, false, true, true, false, true, true,
    ],
    // Ring 9
    [
        true, true, true, false, true, false, true, true, false, false, false, false, true, false,
        false, true, true, false, false, true, false, true, false, false, true, false, false, true,
        true, false, true, true, true, false, false, false,
    ],
    // Ring 10
    [
        false, true, false, false, false, false, false, true, false, true, true, false, false,
        true, true, true, false, true, false, false, false, true, false, false, false, true, false,
        false, true, true, false, false, true, true, true, false,
    ],
    // Ring 11
    [
        true, true, false, false, true, false, false, false, false, true, true, false, false,
        false, true, false, true, true, false, false, false, true, false, false, true, true, false,
        false, false, false, true, false, true, false, false, false,
    ],
];

/// Physical sensing sensor offset relative to window position in the stepping unit.
pub const SENSOR_ANGULAR_OFFSET: u8 = 10;

/// A configured outer notch ring pattern.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NotchRing {
    id: NotchRingId,
    pattern: [bool; 36],
}

impl NotchRing {
    /// Construct a standard notch ring from its ID (1..11).
    #[must_use]
    pub const fn from_id(id: NotchRingId) -> Self {
        let pattern = NOTCH_RING_PATTERNS[(id.to_number() - 1) as usize];
        Self { id, pattern }
    }

    /// Construct a custom notch ring with user-defined cam pattern.
    #[must_use]
    pub const fn custom(id: NotchRingId, pattern: [bool; 36]) -> Self {
        Self { id, pattern }
    }

    /// Return the ring's identification.
    #[must_use]
    pub const fn id(&self) -> NotchRingId {
        self.id
    }

    /// Return the raw 36-element pattern of cams (`true`) and notches (`false`).
    #[must_use]
    pub const fn pattern(&self) -> &[bool; 36] {
        &self.pattern
    }

    /// Sense the notch ring cam status at a given rotor state.
    ///
    /// - `rotor_win_pos`: Current rotational window position of the rotor (0..35).
    /// - `alpha_ring_set`: Alphabet ring offset on the rotor core (0..35).
    /// - `notch_ring_set`: Notch ring offset relative to alphabet ring (0..35).
    #[must_use]
    pub fn is_cam_active(
        &self,
        rotor_win_pos: Position36,
        alpha_ring_set: Position36,
        notch_ring_set: Position36,
    ) -> bool {
        let index = (rotor_win_pos.get() as u16
            + alpha_ring_set.get() as u16
            + notch_ring_set.get() as u16
            + SENSOR_ANGULAR_OFFSET as u16)
            % (ROTOR_CONTACTS as u16);
        self.pattern[index as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_ids_round_trip() {
        for num in 1..=11 {
            let id = NotchRingId::from_number(num).unwrap();
            assert_eq!(id.to_number(), num);
        }
        assert!(NotchRingId::from_number(0).is_none());
        assert!(NotchRingId::from_number(12).is_none());
    }

    #[test]
    fn ring_patterns_exact_length_and_counts() {
        for (idx, pattern) in NOTCH_RING_PATTERNS.iter().enumerate() {
            assert_eq!(pattern.len(), 36);
            let cams = pattern.iter().filter(|&&b| b).count();
            assert!((10..=20).contains(&cams), "Ring {} cams={}", idx + 1, cams);
        }
    }

    #[test]
    fn sensing_active_cams() {
        let ring1 = NotchRing::from_id(NotchRingId::Ring1);
        // index = (0 + 0 + 0 + 10) % 36 = 10 -> Ring 1 pattern[10] is false
        assert!(!ring1.is_cam_active(Position36::ZERO, Position36::ZERO, Position36::ZERO));

        // index = (4 + 0 + 0 + 10) % 36 = 14 -> Ring 1 pattern[14] is true
        assert!(ring1.is_cam_active(Position36::new(4).unwrap(), Position36::ZERO, Position36::ZERO));
    }
}
