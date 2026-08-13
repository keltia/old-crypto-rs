//! Runtime-loaded and validated SIGABA rotor wiring datasets.

use core::fmt;
use std::sync::Arc;

use serde::Deserialize;

use super::{
    alphabet_rotor::Orientation,
    contact::{Contact26, Position26},
    data::{INDEX_ROTOR_COUNT, IndexRotorId, LARGE_ROTOR_COUNT, LargeRotorId},
    permutation::{Permutation, PermutationError},
};

const SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Category of rotor within a SIGABA wiring dataset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RotorKind {
    /// One of the ten interchangeable 26-contact cipher/control rotors.
    Large,
    /// One of the five stationary 10-contact index rotors.
    Index,
}

impl fmt::Display for RotorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Large => f.write_str("large"),
            Self::Index => f.write_str("index"),
        }
    }
}

/// Error returned while parsing or validating a rotor wiring dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RotorSetError {
    /// The document is not valid rotor-set YAML.
    InvalidYaml(String),
    /// The document uses a schema version this crate does not understand.
    UnsupportedSchemaVersion { found: u32, supported: u32 },
    /// The dataset name is empty or contains only whitespace.
    EmptyName,
    /// A rotor bank does not contain the required number of definitions.
    WrongRotorCount {
        kind: RotorKind,
        expected: usize,
        actual: usize,
    },
    /// A rotor identity is outside the range accepted for its bank.
    RotorIdOutOfRange {
        kind: RotorKind,
        id: i64,
        maximum: usize,
    },
    /// A rotor identity appears more than once in one bank.
    DuplicateRotorId {
        kind: RotorKind,
        id: usize,
        first_definition: usize,
        second_definition: usize,
    },
    /// A wiring contains the wrong number of contacts.
    WrongWiringLength {
        kind: RotorKind,
        id: usize,
        expected: usize,
        actual: usize,
    },
    /// A wiring contains a symbol outside its contact alphabet.
    InvalidWiringSymbol {
        kind: RotorKind,
        id: usize,
        position: usize,
        symbol: char,
    },
    /// A wiring maps two inputs to the same output contact.
    DuplicateWiringContact {
        kind: RotorKind,
        id: usize,
        symbol: char,
        first_position: usize,
        second_position: usize,
    },
}

impl fmt::Display for RotorSetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidYaml(error) => write!(f, "invalid rotor-set YAML: {error}"),
            Self::UnsupportedSchemaVersion { found, supported } => write!(
                f,
                "unsupported rotor-set schema version {found}; expected {supported}"
            ),
            Self::EmptyName => f.write_str("rotor-set name must not be empty"),
            Self::WrongRotorCount {
                kind,
                expected,
                actual,
            } => write!(
                f,
                "{kind}-rotor set contains {actual} definitions; expected {expected}"
            ),
            Self::RotorIdOutOfRange { kind, id, maximum } => {
                write!(f, "{kind}-rotor id {id} is outside 0..{maximum}")
            }
            Self::DuplicateRotorId {
                kind,
                id,
                first_definition,
                second_definition,
            } => write!(
                f,
                "{kind}-rotor id {id} is duplicated in definitions {} and {}",
                first_definition + 1,
                second_definition + 1
            ),
            Self::WrongWiringLength {
                kind,
                id,
                expected,
                actual,
            } => write!(
                f,
                "{kind}-rotor {id} wiring contains {actual} contacts; expected {expected}"
            ),
            Self::InvalidWiringSymbol {
                kind,
                id,
                position,
                symbol,
            } => write!(
                f,
                "{kind}-rotor {id} wiring has invalid symbol {symbol:?} at position {}",
                position + 1
            ),
            Self::DuplicateWiringContact {
                kind,
                id,
                symbol,
                first_position,
                second_position,
            } => write!(
                f,
                "{kind}-rotor {id} wiring repeats contact {symbol:?} at positions {} and {}",
                first_position + 1,
                second_position + 1
            ),
        }
    }
}

impl std::error::Error for RotorSetError {}

/// A complete, validated SIGABA rotor wiring dataset.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RotorSet {
    inner: Arc<RotorSetData>,
}

#[derive(Debug, Eq, PartialEq)]
struct RotorSetData {
    name: String,
    description: Option<String>,
    large: [Permutation<26>; LARGE_ROTOR_COUNT],
    index: [Permutation<10>; INDEX_ROTOR_COUNT],
    transforms: [RotorTransforms; LARGE_ROTOR_COUNT],
}

/// Position-dependent transforms for one rotor in one orientation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MountedRotorTransforms {
    forward: [[u8; 26]; 26],
    reverse: [[u8; 26]; 26],
}

impl MountedRotorTransforms {
    fn new(wiring: Permutation<26>, orientation: Orientation) -> Self {
        let mut forward = [[0_u8; 26]; 26];
        let mut reverse = [[0_u8; 26]; 26];

        for position in 0..26_u8 {
            for input in 0..26_u8 {
                let (forward_output, reverse_output) = match orientation {
                    Orientation::Normal => {
                        let shifted = wrapping_offset(input, i16::from(position));
                        (
                            wrapping_offset(wiring.forward(shifted), -i16::from(position)),
                            wrapping_offset(wiring.inverse(shifted), -i16::from(position)),
                        )
                    }
                    Orientation::Reversed => {
                        let reflected = wrapping_offset(position, -i16::from(input));
                        (
                            wrapping_offset(position, -i16::from(wiring.inverse(reflected))),
                            wrapping_offset(position, -i16::from(wiring.forward(reflected))),
                        )
                    }
                };

                forward[usize::from(position)][usize::from(input)] = forward_output;
                reverse[usize::from(position)][usize::from(input)] = reverse_output;
            }
        }

        Self { forward, reverse }
    }

    #[must_use]
    pub(crate) fn forward(&self, position: Position26, input: Contact26) -> Contact26 {
        contact(self.forward[usize::from(position.get())][usize::from(input.get())])
    }

    #[must_use]
    pub(crate) fn reverse(&self, position: Position26, input: Contact26) -> Contact26 {
        contact(self.reverse[usize::from(position.get())][usize::from(input.get())])
    }
}

/// Precomputed transforms for both ways of mounting one physical rotor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RotorTransforms {
    normal: MountedRotorTransforms,
    reversed: MountedRotorTransforms,
}

impl RotorTransforms {
    fn new(wiring: Permutation<26>) -> Self {
        Self {
            normal: MountedRotorTransforms::new(wiring, Orientation::Normal),
            reversed: MountedRotorTransforms::new(wiring, Orientation::Reversed),
        }
    }

    const fn mounted(&self, orientation: Orientation) -> &MountedRotorTransforms {
        match orientation {
            Orientation::Normal => &self.normal,
            Orientation::Reversed => &self.reversed,
        }
    }
}

impl RotorSet {
    /// Return the built-in Pekelney/Dunn reference rotor set.
    ///
    /// # Panics
    ///
    /// Panics if the crate's built-in rotor constants fail their permutation
    /// validation. The complete dataset is covered by exhaustive tests.
    #[must_use]
    pub fn pekelney_reference() -> Self {
        super::data::reference_rotor_set()
            .expect("the built-in reference rotor set is validated by tests")
            .clone()
    }

    /// Parse and validate a complete rotor set from YAML.
    ///
    /// # Errors
    ///
    /// Returns [`RotorSetError`] if the YAML does not match the supported
    /// schema or any rotor definition is incomplete or non-bijective.
    pub fn from_yaml(source: &str) -> Result<Self, RotorSetError> {
        let raw: RawRotorSet = serde_yml::from_str(source)
            .map_err(|error| RotorSetError::InvalidYaml(error.to_string()))?;

        if raw.schema_version != SUPPORTED_SCHEMA_VERSION {
            return Err(RotorSetError::UnsupportedSchemaVersion {
                found: raw.schema_version,
                supported: SUPPORTED_SCHEMA_VERSION,
            });
        }
        if raw.name.trim().is_empty() {
            return Err(RotorSetError::EmptyName);
        }

        let large = parse_bank(
            RotorKind::Large,
            raw.large_rotors,
            LARGE_ROTOR_COUNT,
            |symbol| symbol.is_ascii_uppercase().then(|| symbol as u8 - b'A'),
        )?;
        let index = parse_bank(
            RotorKind::Index,
            raw.index_rotors,
            INDEX_ROTOR_COUNT,
            |symbol| symbol.is_ascii_digit().then(|| symbol as u8 - b'0'),
        )?;

        Ok(Self::from_permutations(
            raw.name,
            raw.description,
            &large,
            &index,
        ))
    }

    /// Dataset name from the YAML document.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Optional human-readable dataset description.
    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.inner.description.as_deref()
    }

    /// Validated numeric wiring for one large rotor.
    #[must_use]
    pub fn large_wiring(&self, id: LargeRotorId) -> &[u8; 26] {
        self.inner.large[usize::from(id.get())].mapping()
    }

    /// Validated numeric wiring for one index rotor.
    #[must_use]
    pub fn index_wiring(&self, id: IndexRotorId) -> &[u8; 10] {
        self.inner.index[usize::from(id.get())].mapping()
    }

    pub(crate) fn from_permutations(
        name: String,
        description: Option<String>,
        large: &[Permutation<26>; LARGE_ROTOR_COUNT],
        index: &[Permutation<10>; INDEX_ROTOR_COUNT],
    ) -> Self {
        let large = *large;
        let transforms = large.map(RotorTransforms::new);
        Self {
            inner: Arc::new(RotorSetData {
                name,
                description,
                large,
                index: *index,
                transforms,
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn large_rotor(&self, id: LargeRotorId) -> Permutation<26> {
        self.inner.large[usize::from(id.get())]
    }

    pub(crate) fn index_rotor(&self, id: IndexRotorId) -> Permutation<10> {
        self.inner.index[usize::from(id.get())]
    }

    pub(crate) fn mounted(
        &self,
        id: LargeRotorId,
        orientation: Orientation,
    ) -> &MountedRotorTransforms {
        self.inner.transforms[usize::from(id.get())].mounted(orientation)
    }
}

impl From<super::data::LargeRotorSet> for RotorSet {
    fn from(set: super::data::LargeRotorSet) -> Self {
        match set {
            super::data::LargeRotorSet::PekelneyReference => {
                Self::pekelney_reference()
            }
        }
    }
}

fn wrapping_offset(value: u8, amount: i16) -> u8 {
    u8::try_from((i16::from(value) + amount).rem_euclid(26))
        .expect("a value reduced modulo 26 always fits in u8")
}

fn contact(value: u8) -> Contact26 {
    Contact26::new(value).expect("validated 26-contact permutation returned an in-range contact")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRotorSet {
    schema_version: u32,
    name: String,
    description: Option<String>,
    large_rotors: Vec<RawRotor>,
    index_rotors: Vec<RawRotor>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRotor {
    id: i64,
    wiring: String,
}

fn parse_bank<const CONTACTS: usize, const ROTORS: usize>(
    kind: RotorKind,
    definitions: Vec<RawRotor>,
    expected: usize,
    normalize: impl Fn(char) -> Option<u8>,
) -> Result<[Permutation<CONTACTS>; ROTORS], RotorSetError> {
    if definitions.len() != expected {
        return Err(RotorSetError::WrongRotorCount {
            kind,
            expected,
            actual: definitions.len(),
        });
    }

    let mut parsed = [None; ROTORS];
    let mut definition_by_id = [usize::MAX; ROTORS];

    for (definition_index, definition) in definitions.into_iter().enumerate() {
        let Ok(id) = usize::try_from(definition.id) else {
            return Err(RotorSetError::RotorIdOutOfRange {
                kind,
                id: definition.id,
                maximum: ROTORS,
            });
        };
        if id >= ROTORS {
            return Err(RotorSetError::RotorIdOutOfRange {
                kind,
                id: definition.id,
                maximum: ROTORS,
            });
        }
        if definition_by_id[id] != usize::MAX {
            return Err(RotorSetError::DuplicateRotorId {
                kind,
                id,
                first_definition: definition_by_id[id],
                second_definition: definition_index,
            });
        }

        let symbols: Vec<char> = definition.wiring.chars().collect();
        if symbols.len() != CONTACTS {
            return Err(RotorSetError::WrongWiringLength {
                kind,
                id,
                expected: CONTACTS,
                actual: symbols.len(),
            });
        }

        let mut wiring = [0_u8; CONTACTS];
        for (position, symbol) in symbols.into_iter().enumerate() {
            wiring[position] = normalize(symbol).ok_or(RotorSetError::InvalidWiringSymbol {
                kind,
                id,
                position,
                symbol,
            })?;
        }

        parsed[id] =
            Some(Permutation::new(wiring).map_err(|error| permutation_error(kind, id, error))?);
        definition_by_id[id] = definition_index;
    }

    Ok(parsed.map(|rotor| {
        rotor.expect("exact rotor count plus unique in-range IDs implies full coverage")
    }))
}

fn permutation_error(kind: RotorKind, id: usize, error: PermutationError) -> RotorSetError {
    match error {
        PermutationError::Duplicate {
            value,
            first_index,
            second_index,
        } => RotorSetError::DuplicateWiringContact {
            kind,
            id,
            symbol: match kind {
                RotorKind::Large => char::from(b'A' + value),
                RotorKind::Index => char::from(b'0' + value),
            },
            first_position: first_index,
            second_position: second_index,
        },
        PermutationError::OutOfRange { index, value, .. } => RotorSetError::InvalidWiringSymbol {
            kind,
            id,
            position: index,
            symbol: char::from(value),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE: &str = include_str!("../config/rotors/pekelney-reference.yaml");

    #[test]
    fn reference_yaml_parses_with_metadata_and_exact_wirings() {
        let set = RotorSet::from_yaml(REFERENCE).unwrap();

        assert_eq!(set.name(), "pekelney_reference");
        assert_eq!(
            set.description(),
            Some("Pekelney/Dunn simulator reference wiring")
        );
        assert_eq!(
            set.large_wiring(LargeRotorId::new(0).unwrap()),
            &b"YCHLQSUGBDIXNZKERPVJTAWFOM".map(|letter| letter - b'A')
        );
        assert_eq!(
            set.index_wiring(IndexRotorId::new(4).unwrap()),
            &[6, 4, 9, 7, 1, 3, 5, 2, 8, 0]
        );
    }

    #[test]
    fn cloning_a_rotor_set_shares_its_immutable_tables() {
        let set = RotorSet::from_yaml(REFERENCE).unwrap();
        let cloned = set.clone();

        assert!(Arc::ptr_eq(&set.inner, &cloned.inner));
    }

    #[test]
    fn parsed_wirings_have_owned_precomputed_mounted_transforms() {
        let yaml = REFERENCE.replace(
            "YCHLQSUGBDIXNZKERPVJTAWFOM",
            "CYHLQSUGBDIXNZKERPVJTAWFOM",
        );
        let set = RotorSet::from_yaml(&yaml).unwrap();
        let id = LargeRotorId::new(0).unwrap();
        let transforms = set.mounted(id, Orientation::Normal);

        assert_eq!(
            transforms.forward(Position26::A, contact(0)).get(),
            b'C' - b'A'
        );
        assert_eq!(
            transforms.forward(Position26::A, contact(1)).get(),
            b'Y' - b'A'
        );
        assert_eq!(
            transforms.reverse(Position26::A, contact(b'C' - b'A')).get(),
            0
        );
    }

    #[test]
    fn unsupported_schema_version_is_rejected() {
        let yaml = REFERENCE.replace("schema_version: 1", "schema_version: 2");
        assert_eq!(
            RotorSet::from_yaml(&yaml),
            Err(RotorSetError::UnsupportedSchemaVersion {
                found: 2,
                supported: 1,
            })
        );
    }

    #[test]
    fn empty_name_is_rejected() {
        let yaml = REFERENCE.replace("name: pekelney_reference", "name: '   '");
        assert_eq!(RotorSet::from_yaml(&yaml), Err(RotorSetError::EmptyName));
    }

    #[test]
    fn wrong_rotor_count_is_rejected() {
        let yaml = REFERENCE.replace("  - id: 9\n    wiring: EZJQXMOGYTCSFRIUPVNADLHWBK\n", "");
        assert_eq!(
            RotorSet::from_yaml(&yaml),
            Err(RotorSetError::WrongRotorCount {
                kind: RotorKind::Large,
                expected: 10,
                actual: 9,
            })
        );
    }

    #[test]
    fn out_of_range_and_duplicate_ids_are_rejected() {
        let out_of_range = REFERENCE.replacen("  - id: 0", "  - id: 10", 1);
        assert_eq!(
            RotorSet::from_yaml(&out_of_range),
            Err(RotorSetError::RotorIdOutOfRange {
                kind: RotorKind::Large,
                id: 10,
                maximum: 10,
            })
        );

        let duplicate = REFERENCE.replacen("  - id: 1", "  - id: 0", 1);
        assert_eq!(
            RotorSet::from_yaml(&duplicate),
            Err(RotorSetError::DuplicateRotorId {
                kind: RotorKind::Large,
                id: 0,
                first_definition: 0,
                second_definition: 1,
            })
        );
    }

    #[test]
    fn wiring_length_symbols_and_permutation_are_validated() {
        let short = REFERENCE.replace("YCHLQSUGBDIXNZKERPVJTAWFOM", "YCHLQSUGBDIXNZKERPVJTAWFO");
        assert!(matches!(
            RotorSet::from_yaml(&short),
            Err(RotorSetError::WrongWiringLength {
                kind: RotorKind::Large,
                id: 0,
                expected: 26,
                actual: 25,
            })
        ));

        let invalid = REFERENCE.replace("YCHLQSUGBDIXNZKERPVJTAWFOM", "yCHLQSUGBDIXNZKERPVJTAWFOM");
        assert!(matches!(
            RotorSet::from_yaml(&invalid),
            Err(RotorSetError::InvalidWiringSymbol {
                kind: RotorKind::Large,
                id: 0,
                position: 0,
                symbol: 'y',
            })
        ));

        let duplicate =
            REFERENCE.replace("YCHLQSUGBDIXNZKERPVJTAWFOM", "CCHLQSUGBDIXNZKERPVJTAWFOM");
        assert!(matches!(
            RotorSet::from_yaml(&duplicate),
            Err(RotorSetError::DuplicateWiringContact {
                kind: RotorKind::Large,
                id: 0,
                symbol: 'C',
                first_position: 0,
                second_position: 1,
            })
        ));
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let yaml = REFERENCE.replace(
            "name: pekelney_reference",
            "name: pekelney_reference\nunexpected: true",
        );
        let error = RotorSet::from_yaml(&yaml).unwrap_err();
        assert!(matches!(error, RotorSetError::InvalidYaml(_)));
        assert!(error.to_string().contains("unknown field"), "{error}");
    }

    #[test]
    fn index_wiring_must_remain_a_quoted_string() {
        let yaml = REFERENCE.replace("wiring: \"7591482630\"", "wiring: 7591482630");
        assert!(matches!(
            RotorSet::from_yaml(&yaml),
            Err(RotorSetError::InvalidYaml(_))
        ));
    }
}
