//! Zero-based electrical contacts within the separate PURPLE switch banks.

use core::fmt;

/// Error returned when a numeric contact is outside its bank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContactError {
    /// The rejected zero-based contact number.
    pub value: u8,
    /// Number of contacts in the requested bank.
    pub count: u8,
}

impl fmt::Display for ContactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "contact {} is outside 0..{}", self.value, self.count)
    }
}

impl std::error::Error for ContactError {}

macro_rules! contact_type {
    ($name:ident, $count:expr, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(u8);

        impl $name {
            /// Number of electrical contacts in this bank.
            pub const COUNT: u8 = $count;

            /// Construct from a zero-based contact number.
            pub const fn new(value: u8) -> Result<Self, ContactError> {
                if value < Self::COUNT {
                    Ok(Self(value))
                } else {
                    Err(ContactError { value, count: Self::COUNT })
                }
            }

            /// Return the zero-based contact number.
            pub const fn index(self) -> u8 {
                self.0
            }
        }

        impl TryFrom<u8> for $name {
            type Error = ContactError;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for u8 {
            fn from(value: $name) -> Self {
                value.index()
            }
        }
    };
}

contact_type!(SixesContact, 6, "A zero-based contact (0–5) in the sixes bank.");
contact_type!(TwentiesContact, 20, "A zero-based contact (0–19) in the twenties bank.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixes_boundaries() {
        for value in 0..SixesContact::COUNT {
            let contact = SixesContact::new(value).unwrap();
            assert_eq!(contact.index(), value);
            assert_eq!(u8::from(contact), value);
            assert_eq!(SixesContact::try_from(value), Ok(contact));
        }
        for value in [6, 20, u8::MAX] {
            assert_eq!(SixesContact::new(value), Err(ContactError { value, count: 6 }));
        }
    }

    #[test]
    fn twenties_boundaries() {
        for value in 0..TwentiesContact::COUNT {
            let contact = TwentiesContact::new(value).unwrap();
            assert_eq!(contact.index(), value);
            assert_eq!(u8::from(contact), value);
            assert_eq!(TwentiesContact::try_from(value), Ok(contact));
        }
        for value in [20, 25, u8::MAX] {
            assert_eq!(TwentiesContact::new(value), Err(ContactError { value, count: 20 }));
        }
    }

    #[test]
    fn error_is_descriptive() {
        assert_eq!(SixesContact::new(6).unwrap_err().to_string(), "contact 6 is outside 0..6");
    }
}
