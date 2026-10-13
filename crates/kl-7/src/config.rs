//! Configuration for the TSEC/KL-7 cipher machine.

use super::{
    actuator::ACTUATOR_SWITCH_COUNT,
    contact::Position36,
    data::RotorId,
    notch_ring::{NotchRing, NotchRingId},
    rotor::Rotor,
    stepping::DRUM_ROTOR_COUNT,
};
use core::fmt;
use serde::{Deserialize, Serialize};

/// Error returned when validating a KL-7 configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// Duplicate rotor core assigned to multiple slots in the drum.
    DuplicateRotorCore(RotorId),
    /// Duplicate notch ring assigned to multiple movable slots.
    DuplicateNotchRing(NotchRingId),
    /// Invalid rotor slot index.
    InvalidRotorSlot(usize),
    /// Invalid rotor name or identifier.
    InvalidRotorName(String),
    /// Invalid notch ring identifier.
    InvalidNotchRingNumber(u8),
    /// Invalid position label or number.
    InvalidPosition(String),
    /// YAML format or parsing error.
    Yaml(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateRotorCore(id) => {
                write!(f, "rotor core {id} assigned to multiple drum slots")
            }
            Self::DuplicateNotchRing(id) => {
                write!(f, "notch ring {id} assigned to multiple movable slots")
            }
            Self::InvalidRotorSlot(slot) => write!(f, "invalid rotor slot index: {slot}"),
            Self::InvalidRotorName(name) => write!(f, "invalid rotor name: '{name}'"),
            Self::InvalidNotchRingNumber(num) => write!(f, "invalid notch ring number: {num}"),
            Self::InvalidPosition(pos) => write!(f, "invalid position: '{pos}'"),
            Self::Yaml(err) => write!(f, "YAML error: {err}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// DTO for serializing/deserializing daily key sheet configurations via YAML.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeySheetDto {
    #[serde(default)]
    pub date: Option<String>,
    pub rotors: [String; DRUM_ROTOR_COUNT],
    pub alpha_ring_sets: [String; DRUM_ROTOR_COUNT],
    pub notch_rings: [u8; ACTUATOR_SWITCH_COUNT],
    pub notch_ring_sets: [String; ACTUATOR_SWITCH_COUNT],
    pub initial_positions: [String; DRUM_ROTOR_COUNT],
    #[serde(default)]
    pub mode: Option<String>,
}

/// Operating procedure mode for KL-7 encryption.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OperationMode {
    /// POLLUX procedure: message key is set and sent in plain indicator.
    #[default]
    Pollux,
    /// ADONIS procedure: message key is encrypted via the basic alignment.
    Adonis,
}

/// Fully validated immutable configuration for the TSEC/KL-7 machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Kl7Config {
    rotors: [RotorId; DRUM_ROTOR_COUNT],
    alpha_ring_sets: [Position36; DRUM_ROTOR_COUNT],
    notch_rings: [NotchRingId; ACTUATOR_SWITCH_COUNT],
    notch_ring_sets: [Position36; ACTUATOR_SWITCH_COUNT],
    initial_positions: [Position36; DRUM_ROTOR_COUNT],
    mode: OperationMode,
}

impl Kl7Config {
    /// Create a new validated KL-7 configuration with standard reference rotors.
    pub fn new(
        rotors: [RotorId; DRUM_ROTOR_COUNT],
        alpha_ring_sets: [Position36; DRUM_ROTOR_COUNT],
        notch_rings: [NotchRingId; ACTUATOR_SWITCH_COUNT],
        notch_ring_sets: [Position36; ACTUATOR_SWITCH_COUNT],
        initial_positions: [Position36; DRUM_ROTOR_COUNT],
        mode: OperationMode,
    ) -> Result<Self, ConfigError> {
        // Validate unique rotor cores
        let mut rotor_seen = [false; 13];
        for &r in &rotors {
            let idx = r.index();
            if rotor_seen[idx] {
                return Err(ConfigError::DuplicateRotorCore(r));
            }
            rotor_seen[idx] = true;
        }

        // Validate unique notch rings
        let mut ring_seen = [false; 12];
        for &ring in &notch_rings {
            let num = ring.to_number() as usize;
            if ring_seen[num] {
                return Err(ConfigError::DuplicateNotchRing(ring));
            }
            ring_seen[num] = true;
        }

        Ok(Self {
            rotors,
            alpha_ring_sets,
            notch_rings,
            notch_ring_sets,
            initial_positions,
            mode,
        })
    }

    /// Parse a configuration from a YAML string using `noyalib`.
    pub fn from_yaml(yaml_str: &str) -> Result<Self, ConfigError> {
        let dto: KeySheetDto =
            noyalib::from_str(yaml_str).map_err(|e| ConfigError::Yaml(e.to_string()))?;
        Self::from_dto(dto)
    }

    /// Convert this configuration into a YAML string using `noyalib`.
    pub fn to_yaml(&self) -> Result<String, ConfigError> {
        let dto = self.to_dto();
        noyalib::to_string(&dto).map_err(|e| ConfigError::Yaml(e.to_string()))
    }

    /// Construct from DTO.
    pub fn from_dto(dto: KeySheetDto) -> Result<Self, ConfigError> {
        let mut rotors = [RotorId::A; DRUM_ROTOR_COUNT];
        for (i, r_str) in dto.rotors.iter().enumerate() {
            let ch = r_str.chars().next().ok_or_else(|| {
                ConfigError::InvalidRotorName(r_str.clone())
            })?;
            rotors[i] = RotorId::from_char(ch).ok_or_else(|| {
                ConfigError::InvalidRotorName(r_str.clone())
            })?;
        }

        let mut alpha_ring_sets = [Position36::ZERO; DRUM_ROTOR_COUNT];
        for (i, p_str) in dto.alpha_ring_sets.iter().enumerate() {
            alpha_ring_sets[i] = Position36::parse(p_str)
                .ok_or_else(|| ConfigError::InvalidPosition(p_str.clone()))?;
        }

        let mut notch_rings = [NotchRingId::Ring1; ACTUATOR_SWITCH_COUNT];
        for (i, &num) in dto.notch_rings.iter().enumerate() {
            notch_rings[i] = NotchRingId::from_number(num)
                .ok_or(ConfigError::InvalidNotchRingNumber(num))?;
        }

        let mut notch_ring_sets = [Position36::ZERO; ACTUATOR_SWITCH_COUNT];
        for (i, p_str) in dto.notch_ring_sets.iter().enumerate() {
            notch_ring_sets[i] = Position36::parse(p_str)
                .ok_or_else(|| ConfigError::InvalidPosition(p_str.clone()))?;
        }

        let mut initial_positions = [Position36::ZERO; DRUM_ROTOR_COUNT];
        for (i, p_str) in dto.initial_positions.iter().enumerate() {
            initial_positions[i] = Position36::parse(p_str)
                .ok_or_else(|| ConfigError::InvalidPosition(p_str.clone()))?;
        }

        let mode = match dto.mode.as_deref() {
            Some("Adonis") | Some("ADONIS") | Some("adonis") => OperationMode::Adonis,
            _ => OperationMode::Pollux,
        };

        Self::new(
            rotors,
            alpha_ring_sets,
            notch_rings,
            notch_ring_sets,
            initial_positions,
            mode,
        )
    }

    /// Convert to DTO.
    #[must_use]
    pub fn to_dto(&self) -> KeySheetDto {
        let mut rotors = [const { String::new() }; DRUM_ROTOR_COUNT];
        let mut alpha_ring_sets = [const { String::new() }; DRUM_ROTOR_COUNT];
        let mut initial_positions = [const { String::new() }; DRUM_ROTOR_COUNT];
        let mut notch_rings = [0u8; ACTUATOR_SWITCH_COUNT];
        let mut notch_ring_sets = [const { String::new() }; ACTUATOR_SWITCH_COUNT];

        for i in 0..DRUM_ROTOR_COUNT {
            rotors[i] = self.rotors[i].to_string();
            alpha_ring_sets[i] = self.alpha_ring_sets[i].to_one_based().to_string();
            initial_positions[i] = self.initial_positions[i].to_string();
        }

        for i in 0..ACTUATOR_SWITCH_COUNT {
            notch_rings[i] = self.notch_rings[i].to_number();
            notch_ring_sets[i] = self.notch_ring_sets[i].to_string();
        }

        let mode = match self.mode {
            OperationMode::Pollux => Some("Pollux".to_string()),
            OperationMode::Adonis => Some("Adonis".to_string()),
        };

        KeySheetDto {
            date: None,
            rotors,
            alpha_ring_sets,
            notch_rings,
            notch_ring_sets,
            initial_positions,
            mode,
        }
    }

    /// Return the reference USS Beagle historical test configuration.
    #[must_use]
    pub fn uss_beagle() -> Self {
        Self {
            rotors: [
                RotorId::E,
                RotorId::H,
                RotorId::F,
                RotorId::L, // Stationary Rotor 4
                RotorId::I,
                RotorId::A,
                RotorId::G,
                RotorId::B,
            ],
            alpha_ring_sets: [
                Position36::new(3).unwrap(),  // 4 (1-based)
                Position36::new(27).unwrap(), // 28
                Position36::new(3).unwrap(),  // 4
                Position36::new(15).unwrap(), // 16 (Stationary Wide Ring)
                Position36::new(8).unwrap(),  // 9
                Position36::new(31).unwrap(), // 32
                Position36::new(7).unwrap(),  // 8
                Position36::new(10).unwrap(), // 11
            ],
            notch_rings: [
                NotchRingId::Ring5,
                NotchRingId::Ring10,
                NotchRingId::Ring6,
                NotchRingId::Ring7,
                NotchRingId::Ring1,
                NotchRingId::Ring8,
                NotchRingId::Ring3,
            ],
            notch_ring_sets: [
                Position36::new(3).unwrap(),  // 'C'
                Position36::new(17).unwrap(), // 'M+' (position 18, index 17) -> wait, let's verify
                Position36::new(5).unwrap(),  // 'E' (position 6, index 5)
                Position36::new(1).unwrap(),  // 'B' (position 2, index 1)
                Position36::new(6).unwrap(),  // 'E+' (position 7, index 6)
                Position36::new(33).unwrap(), // 'Y' (position 34, index 33)
                Position36::new(14).unwrap(), // 'K' (position 15, index 14)
            ],
            initial_positions: [
                Position36::new(32).unwrap(), // 'X'
                Position36::new(5).unwrap(),  // 'E'
                Position36::new(8).unwrap(),  // 'G'
                Position36::new(15).unwrap(), // Rotor 4 fixed
                Position36::new(1).unwrap(),  // 'B'
                Position36::new(29).unwrap(), // 'V'
                Position36::new(5).unwrap(),  // 'E'
                Position36::new(22).unwrap(), // 'Q'
            ],
            mode: OperationMode::Pollux,
        }
    }

    /// Return the rotor core assigned to drum slot 0..7.
    #[must_use]
    pub const fn rotor(&self, slot: usize) -> RotorId {
        self.rotors[slot]
    }

    /// Return all 8 rotor cores.
    #[must_use]
    pub const fn rotors(&self) -> &[RotorId; DRUM_ROTOR_COUNT] {
        &self.rotors
    }

    /// Return alphabet ring setting for drum slot 0..7.
    #[must_use]
    pub const fn alpha_ring_set(&self, slot: usize) -> Position36 {
        self.alpha_ring_sets[slot]
    }

    /// Return all 8 alphabet ring settings.
    #[must_use]
    pub const fn alpha_ring_sets(&self) -> &[Position36; DRUM_ROTOR_COUNT] {
        &self.alpha_ring_sets
    }

    /// Return notch ring assigned to movable slot 0..6.
    #[must_use]
    pub const fn notch_ring(&self, idx: usize) -> NotchRingId {
        self.notch_rings[idx]
    }

    /// Return all 7 notch rings.
    #[must_use]
    pub const fn notch_rings(&self) -> &[NotchRingId; ACTUATOR_SWITCH_COUNT] {
        &self.notch_rings
    }

    /// Return notch ring offset setting for movable slot 0..6.
    #[must_use]
    pub const fn notch_ring_set(&self, idx: usize) -> Position36 {
        self.notch_ring_sets[idx]
    }

    /// Return all 7 notch ring offset settings.
    #[must_use]
    pub const fn notch_ring_sets(&self) -> &[Position36; ACTUATOR_SWITCH_COUNT] {
        &self.notch_ring_sets
    }

    /// Return initial window position for drum slot 0..7.
    #[must_use]
    pub const fn initial_position(&self, slot: usize) -> Position36 {
        self.initial_positions[slot]
    }

    /// Return all 8 initial window positions.
    #[must_use]
    pub const fn initial_positions(&self) -> &[Position36; DRUM_ROTOR_COUNT] {
        &self.initial_positions
    }

    /// Return the operation mode.
    #[must_use]
    pub const fn mode(&self) -> OperationMode {
        self.mode
    }

    /// Build the runtime machine core `Kl7Core` from this configuration.
    #[must_use]
    pub fn build_core(&self) -> super::machine::Kl7Core {
        let rotors = [
            Rotor::from_reference(self.rotors[0], self.initial_positions[0], self.alpha_ring_sets[0]),
            Rotor::from_reference(self.rotors[1], self.initial_positions[1], self.alpha_ring_sets[1]),
            Rotor::from_reference(self.rotors[2], self.initial_positions[2], self.alpha_ring_sets[2]),
            Rotor::from_reference(self.rotors[3], self.initial_positions[3], self.alpha_ring_sets[3]),
            Rotor::from_reference(self.rotors[4], self.initial_positions[4], self.alpha_ring_sets[4]),
            Rotor::from_reference(self.rotors[5], self.initial_positions[5], self.alpha_ring_sets[5]),
            Rotor::from_reference(self.rotors[6], self.initial_positions[6], self.alpha_ring_sets[6]),
            Rotor::from_reference(self.rotors[7], self.initial_positions[7], self.alpha_ring_sets[7]),
        ];

        let rings = [
            NotchRing::from_id(self.notch_rings[0]),
            NotchRing::from_id(self.notch_rings[1]),
            NotchRing::from_id(self.notch_rings[2]),
            NotchRing::from_id(self.notch_rings[3]),
            NotchRing::from_id(self.notch_rings[4]),
            NotchRing::from_id(self.notch_rings[5]),
            NotchRing::from_id(self.notch_rings[6]),
        ];

        super::machine::Kl7Core::new(rotors, rings, self.notch_ring_sets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uss_beagle_yaml_round_trip() {
        let config = Kl7Config::uss_beagle();
        let yaml_str = config.to_yaml().unwrap();
        let parsed = Kl7Config::from_yaml(&yaml_str).unwrap();
        assert_eq!(parsed, config);
    }

    #[test]
    fn duplicate_rotor_rejected() {
        let rotors = [
            RotorId::A,
            RotorId::B,
            RotorId::C,
            RotorId::D,
            RotorId::E,
            RotorId::F,
            RotorId::G,
            RotorId::A, // duplicate A
        ];
        let alpha = [Position36::ZERO; 8];
        let rings = [
            NotchRingId::Ring1,
            NotchRingId::Ring2,
            NotchRingId::Ring3,
            NotchRingId::Ring4,
            NotchRingId::Ring5,
            NotchRingId::Ring6,
            NotchRingId::Ring7,
        ];
        let ring_sets = [Position36::ZERO; 7];
        let init_pos = [Position36::ZERO; 8];

        let res = Kl7Config::new(rotors, alpha, rings, ring_sets, init_pos, OperationMode::Pollux);
        assert!(matches!(res, Err(ConfigError::DuplicateRotorCore(RotorId::A))));
    }
}
