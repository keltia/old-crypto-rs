//! Mechanical data attached to a Fialka wheel body.
//!
//! The removable PROTON-2 wiring core and the mechanical wheel body are
//! deliberately separate objects.  Advance-blocking pins belong to the body,
//! not to the removable electrical core.

use super::{Contact, RotorId};

/// Set of advance-blocking pins around one 30-position wheel body.
///
/// Bit `0` corresponds to the physical `А` / source-table position 1, and bit
/// `29` to `Й` / position 30.  This type stores only the physical pin pattern;
/// the later stepping layer is responsible for applying ring setting, current
/// wheel position, slot direction, and the drive-cog offset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct BlockingPins(u32);

impl BlockingPins {
    const VALID_MASK: u32 = (1_u32 << 30) - 1;

    /// Build a physical pin set from source-table positions numbered 1..=30.
    ///
    /// Returns `None` for an out-of-range or repeated source position.  The
    /// duplicate check makes transcription errors visible even though a bitset
    /// would otherwise silently collapse them.
    #[must_use]
    pub(crate) fn from_one_based(positions: &[u8]) -> Option<Self> {
        let mut bits = 0_u32;

        for &position in positions {
            if !(1..=30).contains(&position) {
                return None;
            }

            let bit = 1_u32 << (position - 1);
            if bits & bit != 0 {
                return None;
            }
            bits |= bit;
        }

        Some(Self(bits))
    }

    /// Whether a blocking pin exists at this physical body coordinate.
    #[must_use]
    pub(crate) const fn contains(self, position: Contact) -> bool {
        self.0 & (1_u32 << position.get()) != 0
    }

    /// Number of physical advance-blocking pins on the wheel body.
    #[must_use]
    pub(crate) const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Whether this body has no blocking pins.
    #[must_use]
    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Raw low-30-bit representation, useful for exact fixture comparisons.
    #[must_use]
    pub(crate) const fn bits(self) -> u32 {
        self.0 & Self::VALID_MASK
    }
}

/// Identity of a mechanical Fialka wheel body.
///
/// This is deliberately distinct from [`super::RotorCore::id`]: PROTON-2
/// keying permits the removable electrical core from one wheel to be fitted
/// inside another wheel body.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RotorBodyId(RotorId);

impl RotorBodyId {
    #[must_use]
    pub(crate) const fn new(id: RotorId) -> Self {
        Self(id)
    }

    #[must_use]
    pub(crate) const fn rotor_id(self) -> RotorId {
        self.0
    }
}

impl From<RotorId> for RotorBodyId {
    fn from(id: RotorId) -> Self {
        Self::new(id)
    }
}

/// Mechanical body of one Fialka wheel in its source/base ring coordinates.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RotorBody {
    id: RotorBodyId,
    blocking_pins: BlockingPins,
}

impl RotorBody {
    #[must_use]
    pub(crate) const fn new(id: RotorBodyId, blocking_pins: BlockingPins) -> Self {
        Self { id, blocking_pins }
    }

    #[must_use]
    pub(crate) const fn id(self) -> RotorBodyId {
        self.id
    }

    #[must_use]
    pub(crate) const fn blocking_pins(self) -> BlockingPins {
        self.blocking_pins
    }

    /// Query the physical pin coordinate before any ring/position transform.
    #[must_use]
    pub(crate) const fn has_blocking_pin(self, position: Contact) -> bool {
        self.blocking_pins.contains(position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_based_constructor_rejects_invalid_and_duplicate_positions() {
        assert!(BlockingPins::from_one_based(&[1, 2, 30]).is_some());
        assert!(BlockingPins::from_one_based(&[]).is_some());
        assert!(BlockingPins::from_one_based(&[0]).is_none());
        assert!(BlockingPins::from_one_based(&[31]).is_none());
        assert!(BlockingPins::from_one_based(&[2, 2]).is_none());
    }

    #[test]
    fn bitset_coordinates_are_zero_based_contacts() {
        let pins = BlockingPins::from_one_based(&[1, 2, 30]).unwrap();

        assert!(pins.contains(Contact::new(0).unwrap()));
        assert!(pins.contains(Contact::new(1).unwrap()));
        assert!(pins.contains(Contact::new(29).unwrap()));
        assert!(!pins.contains(Contact::new(2).unwrap()));
        assert_eq!(pins.len(), 3);
        assert!(!pins.is_empty());
    }
}
