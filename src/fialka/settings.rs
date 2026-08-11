//! Static PROTON-2 rotor settings.
//!
//! The adjustable Fialka wheels have two independent 30-position adjustments:
//! the index/ring setting and the insertion setting of the removable wiring
//! core.  They deliberately have distinct Rust types so that they cannot be
//! accidentally interchanged at call sites.

use super::Contact;

/// Position of the movable index ring (`А == 0`, ..., `Й == 29`).
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RingSetting(Contact);

impl RingSetting {
    /// Basic PROTON-2 ring setting (`А`).
    pub const A: Self = Self(Contact::ZERO);

    /// Construct a checked zero-based ring setting.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        match Contact::new(value) {
            Some(contact) => Some(Self(contact)),
            None => None,
        }
    }

    /// Return the zero-based setting.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0.get()
    }
}

impl TryFrom<u8> for RingSetting {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(value)
    }
}

impl From<RingSetting> for u8 {
    fn from(setting: RingSetting) -> Self {
        setting.get()
    }
}

/// Angular insertion setting of a removable PROTON-2 wiring core.
///
/// `А == 0` means that the white index line on the core is aligned with `А`
/// on the index ring.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoreSetting(Contact);

impl CoreSetting {
    /// Basic PROTON-2 core setting (`А`).
    pub const A: Self = Self(Contact::ZERO);

    /// Construct a checked zero-based core setting.
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        match Contact::new(value) {
            Some(contact) => Some(Self(contact)),
            None => None,
        }
    }

    /// Return the zero-based setting.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0.get()
    }
}

impl TryFrom<u8> for CoreSetting {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(value)
    }
}

impl From<CoreSetting> for u8 {
    fn from(setting: CoreSetting) -> Self {
        setting.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::CONTACT_COUNT;

    #[test]
    fn ring_setting_accepts_exact_contact_range() {
        for value in 0..CONTACT_COUNT as u8 {
            assert_eq!(RingSetting::new(value).map(RingSetting::get), Some(value));
        }
        assert_eq!(RingSetting::new(CONTACT_COUNT as u8), None);
    }

    #[test]
    fn core_setting_accepts_exact_contact_range() {
        for value in 0..CONTACT_COUNT as u8 {
            assert_eq!(CoreSetting::new(value).map(CoreSetting::get), Some(value));
        }
        assert_eq!(CoreSetting::new(CONTACT_COUNT as u8), None);
    }

    #[test]
    fn the_two_settings_are_distinct_types_with_same_basic_coordinate() {
        assert_eq!(RingSetting::A.get(), 0);
        assert_eq!(CoreSetting::A.get(), 0);
    }
}
