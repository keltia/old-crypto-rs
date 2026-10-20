//! Six-wheel window state and pin sensing for the SG-41.
//!
//! Table 5 pin rows are indexed in the same increasing order as the window
//! markings. Table 6 confirms that positive index movement is the mechanical
//! advance direction, and the stepping sensor reads five rows behind the
//! displayed window. The cage sensor reads eight rows ahead.
//!
//! Stepping decisions and their timing live in `stepping.rs`.

use super::error::WheelError;
use super::types::{PinPattern, PinSensor, WHEEL_COUNT, WheelId, WheelPosition, WindowLabel};

/// One latched reading of all six mechanical pin sensors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinSnapshot([bool; WHEEL_COUNT]);

impl PinSnapshot {
    /// Construct a pin latch from six physical wheel states (1 through 6).
    pub const fn from_bits(bits: [bool; WHEEL_COUNT]) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> [bool; WHEEL_COUNT] {
        self.0
    }

    pub const fn get(self, wheel: WheelId) -> bool {
        self.0[wheel.array_index()]
    }
}

/// Configuration and current window indices of the six fixed SG-41 wheels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WheelBank {
    positions: [WheelPosition; WHEEL_COUNT],
    pins: [PinPattern; WHEEL_COUNT],
}

impl WheelBank {
    /// Require all entries to be in physical wheel order (1 through 6).
    pub fn new(
        positions: [WheelPosition; WHEEL_COUNT],
        pins: [PinPattern; WHEEL_COUNT],
    ) -> Result<Self, WheelError> {
        for index in 0..WHEEL_COUNT {
            let expected = WheelId::new(index as u8 + 1).expect("valid fixed wheel id");

            for actual in [positions[index].wheel(), pins[index].wheel()] {
                if actual != expected {
                    return Err(WheelError::WheelMismatch {
                        pattern_wheel: expected.number(),
                        position_wheel: actual.number(),
                    });
                }
            }
        }

        Ok(Self { positions, pins })
    }

    pub const fn positions(&self) -> [WheelPosition; WHEEL_COUNT] {
        self.positions
    }

    pub fn windows(&self) -> [WindowLabel; WHEEL_COUNT] {
        std::array::from_fn(|index| self.positions[index].label())
    }

    pub const fn position(&self, wheel: WheelId) -> WheelPosition {
        self.positions[wheel.array_index()]
    }

    /// Advance a selected wheel by one position, with modular wraparound.
    /// The caller, not the bank, controls the stepping schedule.
    pub fn advance(&mut self, wheel: WheelId) {
        let index = wheel.array_index();
        self.positions[index] = self.positions[index].next_index();
    }

    /// Advance exactly the selected wheels, once each, from the same mask.
    /// This does not inspect any pins or cascade stepping decisions.
    pub fn advance_mask(&mut self, mask: [bool; WHEEL_COUNT]) {
        for (index, selected) in mask.into_iter().enumerate() {
            if selected {
                self.positions[index] = self.positions[index].next_index();
            }
        }
    }

    /// Read the Table 5 pin row under a sensor at the current wheel windows.
    ///
    /// Table 6 confirms the signed offsets in increasing window-index order:
    /// stepping at -5, displacement at +8. No machine state is changed.
    pub fn sense(&self, sensor: PinSensor) -> PinSnapshot {
        let offset = i16::from(sensor.documented_offset());

        PinSnapshot(std::array::from_fn(|index| {
            let position = self.positions[index];
            let length = i16::from(position.wheel().length());
            let row = (i16::from(position.index()) + offset).rem_euclid(length) as u8;

            self.pins[index]
                .table_row(row)
                .expect("sensor row is reduced modulo the wheel length")
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PINS: [&str; WHEEL_COUNT] = [
        "0001101011000100010001101",
        "0110100100001011100101100",
        "11001001000100100100010",
        "01001000111010001110010",
        "001001001010000101011010",
        "011001100110001011010100",
    ];

    /// Table 6 window tuples before each character, in physical wheel order.
    const TRACE: [[&str; WHEEL_COUNT]; 32] = [
        ["A", "B", "C", "D", "01", "00"],
        ["C", "E", "G", "F", "04", "07"],
        ["D", "G", "H", "H", "05", "12"],
        ["E", "H", "K", "I", "06", "15"],
        ["G", "L", "O", "M", "08", "20"],
        ["H", "M", "P", "N", "09", "25"],
        ["K", "P", "S", "P", "12", "30"],
        ["L", "R", "T", "Q", "14", "32"],
        ["M", "S", "U", "R", "16", "37"],
        ["O", "V", "A", "U", "18", "45"],
        ["P", "X", "C", "V", "19", "47"],
        ["R", "A", "F", "A", "22", "52"],
        ["T", "C", "I", "E", "01", "57"],
        ["U", "E", "L", "F", "02", "02"],
        ["V", "F", "M", "G", "03", "07"],
        ["W", "G", "N", "H", "05", "10"],
        ["X", "H", "P", "K", "06", "12"],
        ["Y", "K", "R", "L", "08", "15"],
        ["A", "M", "U", "O", "10", "22"],
        ["B", "N", "V", "Q", "12", "25"],
        ["D", "R", "A", "T", "15", "32"],
        ["E", "S", "B", "U", "16", "35"],
        ["G", "V", "F", "X", "18", "42"],
        ["H", "W", "H", "B", "20", "45"],
        ["I", "X", "K", "C", "21", "47"],
        ["L", "B", "N", "F", "23", "55"],
        ["N", "E", "R", "I", "01", "02"],
        ["O", "F", "S", "L", "02", "07"],
        ["P", "H", "T", "M", "03", "12"],
        ["Q", "K", "V", "N", "04", "15"],
        ["S", "M", "A", "Q", "07", "22"],
        ["T", "N", "B", "R", "09", "25"],
    ];

    fn wheel(index: usize) -> WheelId {
        WheelId::new(index as u8 + 1).unwrap()
    }

    fn window(index: usize, label: &str) -> WheelPosition {
        let marking = if index < 4 {
            WindowLabel::Letter(label.chars().next().unwrap())
        } else {
            WindowLabel::Number(label.parse().unwrap())
        };

        wheel(index).position(marking).unwrap()
    }

    fn bank_at(labels: [&str; WHEEL_COUNT]) -> WheelBank {
        let positions = std::array::from_fn(|index| window(index, labels[index]));
        let pins = std::array::from_fn(|index| {
            PinPattern::from_table_bits(wheel(index), PINS[index]).unwrap()
        });

        WheelBank::new(positions, pins).unwrap()
    }

    #[test]
    fn verifies_pin_sensing_at_initial_windows() {
        let mut bank = bank_at(TRACE[0]);

        assert_eq!(bank.sense(PinSensor::Stepping).bits(), [false, true, false, true, true, true]);
        assert_eq!(bank.sense(PinSensor::Displacement).bits(), [true, false, false, false, true, false]);
        assert_eq!(bank.windows().map(|label| label.to_string()), TRACE[0]);

        let initial = bank.positions();
        bank.advance_mask([false; WHEEL_COUNT]);
        assert_eq!(bank.positions(), initial);

        bank.advance(wheel(0));
        assert_eq!(bank.position(wheel(0)).index(), 1);
        assert_eq!(bank.position(wheel(1)).index(), initial[1].index());
    }

    #[test]
    fn rejects_out_of_order_wheels() {
        let positions = std::array::from_fn(|index| window(index, TRACE[0][index]));
        let pins = std::array::from_fn(|index| {
            PinPattern::from_table_bits(wheel(index), PINS[index]).unwrap()
        });

        let mut swapped = pins;
        swapped.swap(0, 1);
        assert!(matches!(
            WheelBank::new(positions, swapped),
            Err(WheelError::WheelMismatch { .. })
        ));
    }

    #[test]
    fn table_six_validates_stepping_sensor_orientation_for_every_transition() {
        // Test-only reference execution of Table 4's four phases. The
        // production stepping decision layer is intentionally deferred.
        let mut bank = bank_at(TRACE[0]);

        for (character, expected) in TRACE.iter().enumerate() {
            assert_eq!(
                bank.windows().map(|label| label.to_string()),
                expected.map(str::to_owned),
                "incorrect pre-character windows at {}",
                character + 1,
            );

            if character + 1 == TRACE.len() {
                break;
            }

            let trace = crate::stepping::step_crank(&mut bank);
            assert_eq!(trace.final_positions, bank.positions());
        }
    }
}
