//! Fialka's machine-native 30-contact coordinate system.

/// Number of electrical contacts in the normal Fialka signal path.
pub(crate) const CONTACT_COUNT: usize = 30;

/// One electrical contact in the Fialka's 30-position coordinate system.
///
/// `Contact` deliberately has no character/alphabet semantics.  Keyboard and
/// print alphabets are separate layers over the cipher machine.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct Contact(u8);

impl Contact {
    /// Contact zero, corresponding to the `А` coordinate.
    pub(crate) const ZERO: Self = Self(0);

    /// Smallest valid contact number.
    pub(crate) const MIN: u8 = 0;

    /// Largest valid contact number.
    pub(crate) const MAX: u8 = CONTACT_COUNT as u8 - 1;

    /// Construct a checked contact number.
    #[must_use]
    pub(crate) const fn new(value: u8) -> Option<Self> {
        if value < CONTACT_COUNT as u8 {
            Some(Self(value))
        } else {
            None
        }
    }

    /// Return the zero-based electrical contact number.
    #[must_use]
    pub(crate) const fn get(self) -> u8 {
        self.0
    }

    /// Move around the 30-contact circle by a signed displacement.
    ///
    /// This is coordinate arithmetic, not input validation: construction is
    /// checked by [`Contact::new`], while offsets intentionally wrap around.
    #[must_use]
    pub(crate) fn offset(self, displacement: i16) -> Self {
        let value = (i16::from(self.0) + displacement).rem_euclid(CONTACT_COUNT as i16);
        Self(value as u8)
    }
}

impl TryFrom<u8> for Contact {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(value)
    }
}

impl From<Contact> for u8 {
    fn from(contact: Contact) -> Self {
        contact.get()
    }
}

impl From<Contact> for usize {
    fn from(contact: Contact) -> Self {
        usize::from(contact.get())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_exact_contact_range() {
        for value in Contact::MIN..=Contact::MAX {
            assert_eq!(Contact::new(value).map(Contact::get), Some(value));
        }

        assert_eq!(Contact::new(Contact::MAX + 1), None);
        assert_eq!(Contact::new(u8::MAX), None);
    }

    #[test]
    fn try_from_is_checked() {
        assert_eq!(Contact::try_from(0), Ok(Contact(0)));
        assert_eq!(Contact::try_from(29), Ok(Contact(29)));
        assert_eq!(Contact::try_from(30), Err(30));
    }

    #[test]
    fn offsets_wrap_both_directions() {
        assert_eq!(Contact(0).offset(-1), Contact(29));
        assert_eq!(Contact(29).offset(1), Contact(0));
        assert_eq!(Contact(3).offset(30), Contact(3));
        assert_eq!(Contact(3).offset(-30), Contact(3));
        assert_eq!(Contact(3).offset(61), Contact(4));
        assert_eq!(Contact(3).offset(-61), Contact(2));
    }

    #[test]
    fn offset_and_inverse_offset_cancel_exhaustively() {
        for value in 0..CONTACT_COUNT as u8 {
            let contact = Contact::new(value).unwrap();

            for displacement in -90..=90 {
                assert_eq!(
                    contact.offset(displacement).offset(-displacement),
                    contact
                );
            }
        }
    }
}
