//! SIGABA rotor identities and cached built-in wiring dataset.
//!
//! There is an important provenance distinction between the two datasets in
//! this module:
//!
//! * The five 10-contact index-rotor wirings are documented as the actual
//!   wirings from surviving SIGABA index rotors.
//! * The ten 26-contact large-rotor wirings commonly used by modern SIGABA
//!   simulators are the Pekelney reference set.  They were deliberately made
//!   up for the simulator because the surviving machine available to Pekelney
//!   had straight-through cipher/control rotors.
//!
//! Therefore the large-rotor set is useful for interoperability and for
//! validating SIGABA mechanics, but must not be described as historical US
//! wartime wiring.
//!
//! Sources:
//! - W. O. Chan, *Cryptanalysis of SIGABA* (2007), Appendix A and §7.1.
//! - M. Stamp & W. O. Chan, *SIGABA: Cryptanalysis of the Full Keyspace*.
//! - Richard Pekelney's ECM Mark II work, as summarized by Chan.
//!
//! Chan explicitly states that only the index rotor wirings in the simulator
//! are actual rotor wirings; Pekelney created the large-rotor wirings. The
//! built-in definitions live in `config/rotors/pekelney-reference.yaml`, which
//! is embedded, parsed and validated once on first use.

use core::fmt;
use std::sync::OnceLock;

use super::rotor_set::{RotorSet, RotorSetError};

#[cfg(test)]
use super::permutation::Permutation;

const REFERENCE_ROTOR_YAML: &str =
    include_str!("../config/rotors/pekelney-reference.yaml");

/// Number of interchangeable large cipher/control rotors in the reference set.
pub(crate) const LARGE_ROTOR_COUNT: usize = 10;

/// Number of SIGABA index rotors.
pub(crate) const INDEX_ROTOR_COUNT: usize = 5;

/// Identity of one of the ten interchangeable 26-contact rotors.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct LargeRotorId(u8);

impl LargeRotorId {
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < 10 {
            Some(Self(value))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const ALL: [Self; LARGE_ROTOR_COUNT] = [
        Self(0), Self(1), Self(2), Self(3), Self(4),
        Self(5), Self(6), Self(7), Self(8), Self(9),
    ];
}

/// Identity of one of the five 10-contact index rotors.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IndexRotorId(u8);

impl IndexRotorId {
    #[must_use]
    pub const fn new(value: u8) -> Option<Self> {
        if value < 5 {
            Some(Self(value))
        } else {
            None
        }
    }

    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const ALL: [Self; INDEX_ROTOR_COUNT] =
        [Self(0), Self(1), Self(2), Self(3), Self(4)];
}

/// Identifies the provenance of a 26-contact rotor set.
///
/// At present the only public, complete ten-rotor set suitable for simulator
/// interoperability is Pekelney's non-historical reference set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LargeRotorSet {
    /// Reference wiring created by Richard Pekelney for his ECM Mark II
    /// simulator.  This is not claimed to reproduce a wartime US rotor set.
    PekelneyReference,
}

impl fmt::Display for LargeRotorSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PekelneyReference => f.write_str("Pekelney reference"),
        }
    }
}

/// Build one 26-contact rotor from a documented simulator reference set.
#[cfg(test)]
pub(crate) fn large_rotor(
    set: LargeRotorSet,
    id: LargeRotorId,
) -> Result<Permutation<26>, RotorSetError> {
    let rotor_set = match set {
        LargeRotorSet::PekelneyReference => reference_rotor_set()?,
    };

    Ok(rotor_set.large_rotor(id))
}

/// Build one of the five historically documented 10-contact index rotors.
#[cfg(test)]
pub(crate) fn index_rotor(
    id: IndexRotorId,
) -> Result<Permutation<10>, RotorSetError> {
    Ok(reference_rotor_set()?.index_rotor(id))
}

pub(crate) fn reference_rotor_set() -> Result<&'static RotorSet, RotorSetError> {
    static REFERENCE: OnceLock<Result<RotorSet, RotorSetError>> = OnceLock::new();
    match REFERENCE.get_or_init(|| RotorSet::from_yaml(REFERENCE_ROTOR_YAML)) {
        Ok(set) => Ok(set),
        Err(error) => Err(error.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn large_rotor_ids_are_exactly_zero_through_nine() {
        for id in 0..10 {
            assert_eq!(LargeRotorId::new(id).unwrap().get(), id);
        }
        assert!(LargeRotorId::new(10).is_none());
        assert!(LargeRotorId::new(u8::MAX).is_none());
    }

    #[test]
    fn index_rotor_ids_are_exactly_zero_through_four() {
        for id in 0..5 {
            assert_eq!(IndexRotorId::new(id).unwrap().get(), id);
        }
        assert!(IndexRotorId::new(5).is_none());
        assert!(IndexRotorId::new(u8::MAX).is_none());
    }

    #[test]
    fn every_pekelney_large_wiring_is_a_valid_permutation() {
        for id in LargeRotorId::ALL {
            let rotor = large_rotor(LargeRotorSet::PekelneyReference, id)
                .unwrap_or_else(|error| panic!("large rotor {}: {error}", id.get()));

            for input in 0..26_u8 {
                assert_eq!(rotor.inverse(rotor.forward(input)), input);
            }
        }
    }

    #[test]
    fn every_historical_index_wiring_is_a_valid_permutation() {
        for id in IndexRotorId::ALL {
            let rotor = index_rotor(id)
                .unwrap_or_else(|error| panic!("index rotor {}: {error}", id.get() + 1));

            for input in 0..10_u8 {
                assert_eq!(rotor.inverse(rotor.forward(input)), input);
            }
        }
    }

    #[test]
    fn chan_appendix_a_large_rotor_examples_are_exact() {
        let rotor0 =
            large_rotor(LargeRotorSet::PekelneyReference, LargeRotorId::new(0).unwrap()).unwrap();
        let rotor9 =
            large_rotor(LargeRotorSet::PekelneyReference, LargeRotorId::new(9).unwrap()).unwrap();

        // Rotor 0: YCHLQSUGBDIXNZKERPVJTAWFOM
        assert_eq!(rotor0.forward(0), b'Y' - b'A');
        assert_eq!(rotor0.forward(1), b'C' - b'A');
        assert_eq!(rotor0.forward(25), b'M' - b'A');

        // Rotor 9: EZJQXMOGYTCSFRIUPVNADLHWBK
        assert_eq!(rotor9.forward(0), b'E' - b'A');
        assert_eq!(rotor9.forward(9), b'T' - b'A');
        assert_eq!(rotor9.forward(25), b'K' - b'A');
    }

    #[test]
    fn chan_appendix_a_index_rotors_are_exact() {
        const EXPECTED: [[u8; 10]; 5] = [
            [7, 5, 9, 1, 4, 8, 2, 6, 3, 0],
            [3, 8, 1, 0, 5, 9, 2, 7, 6, 4],
            [4, 0, 8, 6, 1, 5, 3, 2, 9, 7],
            [3, 9, 8, 0, 5, 2, 6, 1, 7, 4],
            [6, 4, 9, 7, 1, 3, 5, 2, 8, 0],
        ];

        for (index, id) in IndexRotorId::ALL.into_iter().enumerate() {
            let rotor = index_rotor(id).unwrap();
            assert_eq!(rotor.mapping(), &EXPECTED[index]);
        }
    }

    #[test]
    fn historical_index_data_matches_independent_published_table() {
        // The same five permutations are published in the independent ECM Mark
        // II technical description:
        //
        // 1: 7 5 9 1 4 8 2 6 3 0
        // 2: 3 8 1 0 5 9 2 7 6 4
        // 3: 4 0 8 6 1 5 3 2 9 7
        // 4: 3 9 8 0 5 2 6 1 7 4
        // 5: 6 4 9 7 1 3 5 2 8 0
        assert_eq!(
            index_rotor(IndexRotorId::new(0).unwrap()).unwrap().mapping(),
            &[7, 5, 9, 1, 4, 8, 2, 6, 3, 0]
        );
        assert_eq!(
            index_rotor(IndexRotorId::new(4).unwrap()).unwrap().mapping(),
            &[6, 4, 9, 7, 1, 3, 5, 2, 8, 0]
        );
    }

    #[test]
    fn large_reference_set_is_named_as_nonhistorical_provenance() {
        assert_eq!(
            LargeRotorSet::PekelneyReference.to_string(),
            "Pekelney reference"
        );
    }
}
