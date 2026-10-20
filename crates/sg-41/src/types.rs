//! Checked wheel identities, visible window positions and pin-table settings.
//!
//! These are data types, not an implementation of the mechanical SG-41 cipher.
//! In particular, the Table 5 row order is *not* assumed to be the physical
//! stepping-pin or print-head sensing order.

use super::error::WheelError;

pub const WHEEL_COUNT: usize = 6;

pub const WHEEL_LENGTHS: [u8; WHEEL_COUNT] = [25, 25, 23, 23, 24, 24];

/// Alphabetic window markings, in the order transcribed from Table 1.
/// Wheels 5 and 6 have numeric markings and are represented separately.
const LETTER_MARKINGS: [&str; 4] = [
    "ABCDEFGHIKLMNOPQRSTUVWXYZ",
    "ABCDEFGHIKLMNOPQRSTUVWXYZ",
    "ABCDEFGHIKLMNOPQRSTUVWX",
    "ABCDEFGHIKLMNOPQRSTUVWX",
];

/// The nonuniform numeric window markings on wheel 6.
pub const SIXTH_WHEEL_MARKINGS: [u8; 24] = [
    0, 2, 5, 7, 10, 12, 15, 17, 20, 22, 25, 27,
    30, 32, 35, 37, 40, 42, 45, 47, 50, 52, 55, 57,
];

/// Wheel numbers follow the physical SG-41 order, 1 through 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WheelId(u8);

impl WheelId {
    pub const fn new(number: u8) -> Option<Self> {
        if number >= 1 && number <= WHEEL_COUNT as u8 {
            Some(Self(number))
        } else {
            None
        }
    }

    pub const fn number(self) -> u8 {
        self.0
    }

    pub const fn array_index(self) -> usize {
        (self.0 - 1) as usize
    }

    pub const fn length(self) -> u8 {
        WHEEL_LENGTHS[self.array_index()]
    }

    /// Convert a physical window index into a displayed label.
    pub fn label(self, index: u8) -> Result<WindowLabel, WheelError> {
        if index >= self.length() {
            return Err(WheelError::InvalidIndex {
                wheel: self.0,
                index,
                max: self.length() - 1,
            });
        }

        match self.0 {
            1..=4 => Ok(WindowLabel::Letter(
                LETTER_MARKINGS[self.array_index()].as_bytes()[index as usize] as char,
            )),
            5 => Ok(WindowLabel::Number(index + 1)),
            6 => Ok(WindowLabel::Number(SIXTH_WHEEL_MARKINGS[index as usize])),
            _ => unreachable!("WheelId constructor validates the number"),
        }
    }

    /// Interpret a displayed label; this does not apply any sensing offset.
    pub fn position(self, label: WindowLabel) -> Result<WheelPosition, WheelError> {
        let index = match (self.0, label) {
            (1..=4, WindowLabel::Letter(letter)) => {
                LETTER_MARKINGS[self.array_index()]
                    .chars()
                    .position(|candidate| candidate == letter)
                    .ok_or(WheelError::InvalidLabel { wheel: self.0, label: letter })? as u8
            }
            (5, WindowLabel::Number(marking)) if (1..=24).contains(&marking) => marking - 1,
            (6, WindowLabel::Number(marking)) => SIXTH_WHEEL_MARKINGS
                .iter()
                .position(|&candidate| candidate == marking)
                .ok_or(WheelError::InvalidMarking { wheel: self.0, marking })? as u8,
            (_, WindowLabel::Letter(letter)) => {
                return Err(WheelError::InvalidLabel { wheel: self.0, label: letter });
            }
            (_, WindowLabel::Number(marking)) => {
                return Err(WheelError::InvalidMarking { wheel: self.0, marking });
            }
        };

        Ok(WheelPosition { wheel: self, index })
    }
}

impl TryFrom<u8> for WheelId {
    type Error = WheelError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value).ok_or(WheelError::InvalidWheel(value))
    }
}

/// A physical window marking. Numbers display with two digits (e.g. `01`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WindowLabel {
    Letter(char),
    Number(u8),
}

impl std::fmt::Display for WindowLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Letter(letter) => write!(f, "{letter}"),
            Self::Number(number) => write!(f, "{number:02}"),
        }
    }
}

/// A checked zero-based visible wheel position (not a sensed-pin index).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WheelPosition {
    wheel: WheelId,
    index: u8,
}

impl WheelPosition {
    pub const fn new(wheel: WheelId, index: u8) -> Option<Self> {
        if index < wheel.length() {
            Some(Self { wheel, index })
        } else {
            None
        }
    }

    pub const fn wheel(self) -> WheelId {
        self.wheel
    }

    pub const fn index(self) -> u8 {
        self.index
    }

    pub fn label(self) -> WindowLabel {
        // Invariant: checked at construction.
        self.wheel.label(self.index).expect("validated wheel position")
    }

    /// Move one position in the *chosen positive index direction*.
    /// Its correspondence to physical crank stepping remains to be verified.
    pub const fn next_index(self) -> Self {
        Self {
            wheel: self.wheel,
            index: (self.index + 1) % self.wheel.length(),
        }
    }
}

/// Which mechanical pin sensor is involved. The offsets are documented but
/// the wheel-direction/index sign will be established against Table 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinSensor {
    Stepping,
    Displacement,
}

impl PinSensor {
    /// Nominal offset from the displayed window in the technical description.
    pub const fn documented_offset(self) -> i8 {
        match self {
            Self::Stepping => -5,
            Self::Displacement => 8,
        }
    }
}

/// A validated pin pattern indexed in the source's Table 5 row order.
/// The physical pin-sensing mapping is deliberately left to a later step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinPattern {
    wheel: WheelId,
    bits: u32,
}

impl PinPattern {
    pub fn from_table_bits(wheel: WheelId, text: &str) -> Result<Self, WheelError> {
        if text.chars().count() != wheel.length() as usize {
            return Err(WheelError::PinCount {
                wheel: wheel.number(),
                expected: wheel.length() as usize,
                actual: text.chars().count(),
            });
        }

        let mut bits = 0u32;

        for (row, value) in text.chars().enumerate() {
            match value {
                '0' => {}
                '1' => bits |= 1u32 << row,
                _ => return Err(WheelError::InvalidPinBit {
                    wheel: wheel.number(),
                    row,
                    value,
                }),
            }
        }

        Ok(Self { wheel, bits })
    }

    pub const fn wheel(self) -> WheelId {
        self.wheel
    }

    pub const fn bits(self) -> u32 {
        self.bits
    }

    /// Read a *Table 5 row*, not a mechanically sensed position.
    pub const fn table_row(self, row: u8) -> Option<bool> {
        if row < self.wheel.length() {
            Some(self.bits & (1u32 << row) != 0)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REFERENCE_BITS: [&str; 6] = [
        "0001101011000100010001101",
        "0110100100001011100101100",
        "11001001000100100100010",
        "01001000111010001110010",
        "001001001010000101011010",
        "011001100110001011010100",
    ];

    #[test]
    fn wheel_geometry_and_markings_roundtrip() {
        assert!(WheelId::new(0).is_none());
        assert!(WheelId::new(7).is_none());

        for n in 1..=6 {
            let wheel = WheelId::new(n).unwrap();

            for index in 0..wheel.length() {
                let label = wheel.label(index).unwrap();
                let position = wheel.position(label).unwrap();

                assert_eq!(position.index(), index);
                assert_eq!(position.label(), label);
                assert_eq!(wheel.position(label).unwrap().wheel(), wheel);
            }

            assert!(wheel.label(wheel.length()).is_err());
            assert!(WheelPosition::new(wheel, wheel.length()).is_none());

            let first = WheelPosition::new(wheel, 0).unwrap();
            let mut position = first;

            for _ in 0..wheel.length() {
                position = position.next_index();
            }

            assert_eq!(position, first);
        }
    }

    #[test]
    fn reference_initial_windows_and_invalid_markings() {
        let labels = [
            WindowLabel::Letter('A'),
            WindowLabel::Letter('B'),
            WindowLabel::Letter('C'),
            WindowLabel::Letter('D'),
            WindowLabel::Number(1),
            WindowLabel::Number(0),
        ];

        for (index, &label) in labels.iter().enumerate() {
            let wheel = WheelId::new(index as u8 + 1).unwrap();
            assert_eq!(wheel.position(label).unwrap().label(), label);
        }

        assert!(WheelId::new(1).unwrap().position(WindowLabel::Letter('J')).is_err());
        assert!(WheelId::new(3).unwrap().position(WindowLabel::Letter('Y')).is_err());
        assert!(WheelId::new(5).unwrap().position(WindowLabel::Number(0)).is_err());
        assert!(WheelId::new(6).unwrap().position(WindowLabel::Number(1)).is_err());
        assert_eq!(WindowLabel::Number(1).to_string(), "01");
        assert_eq!(WindowLabel::Number(0).to_string(), "00");
    }

    #[test]
    fn reference_pin_tables_validate_all_144_settings() {
        let mut count = 0;

        for (index, bit_string) in REFERENCE_BITS.iter().enumerate() {
            let wheel = WheelId::new(index as u8 + 1).unwrap();
            let pattern = PinPattern::from_table_bits(wheel, bit_string).unwrap();

            assert_eq!(pattern.wheel(), wheel);

            for (row, ch) in bit_string.chars().enumerate() {
                assert_eq!(pattern.table_row(row as u8), Some(ch == '1'));
                count += 1;
            }

            assert_eq!(pattern.table_row(wheel.length()), None);
            assert!(PinPattern::from_table_bits(wheel, "0").is_err());

            let mut invalid = bit_string.to_string();
            invalid.replace_range(0..1, "x");
            assert!(PinPattern::from_table_bits(wheel, &invalid).is_err());
        }

        assert_eq!(count, 144);
    }

    #[test]
    fn sensor_offsets_remain_distinct() {
        assert_eq!(PinSensor::Stepping.documented_offset(), -5);
        assert_eq!(PinSensor::Displacement.documented_offset(), 8);
    }
}
