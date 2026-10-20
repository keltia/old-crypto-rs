//! Validated SG-41 key settings, independent of the running wheel state.

use super::core::Sg41Core;
use super::error::ConfigError;
use super::types::{PinPattern, WHEEL_COUNT, WheelId, WheelPosition, WindowLabel};
use super::wheel_bank::WheelBank;

/// The six fixed wheel settings in physical wheel order (1 through 6).
///
/// A configuration is immutable: building a core creates a fresh wheel bank
/// every time, without advancing or modifying these initial settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sg41Config {
    positions: [WheelPosition; WHEEL_COUNT],
    pins: [PinPattern; WHEEL_COUNT],
}

impl Sg41Config {
    /// Accept individually validated positions and pin patterns, checking
    /// that both arrays follow the machine's fixed physical wheel order.
    pub fn new(
        positions: [WheelPosition; WHEEL_COUNT],
        pins: [PinPattern; WHEEL_COUNT],
    ) -> Result<Self, ConfigError> {
        WheelBank::new(positions, pins)?;

        Ok(Self { positions, pins })
    }

    /// Construct a configuration from the six visible wheel markings and six
    /// Table 5 pin strings (in physical wheel order).
    ///
    /// Letter markings are uppercase; wheels 5 and 6 require their actual
    /// numeric markings. Pin strings contain exactly 23, 24, or 25 binary
    /// digits as appropriate to each physical wheel.
    pub fn from_key_settings(
        windows: [WindowLabel; WHEEL_COUNT],
        table_pins: [&str; WHEEL_COUNT],
    ) -> Result<Self, ConfigError> {
        let first = WheelId::new(1).expect("fixed wheel number");
        let mut positions = [first.position(windows[0])?; WHEEL_COUNT];
        let mut pins = [PinPattern::from_table_bits(first, table_pins[0])?; WHEEL_COUNT];

        for index in 1..WHEEL_COUNT {
            let wheel = WheelId::new(index as u8 + 1).expect("fixed wheel number");
            positions[index] = wheel.position(windows[index])?;
            pins[index] = PinPattern::from_table_bits(wheel, table_pins[index])?;
        }

        Self::new(positions, pins)
    }

    pub const fn positions(&self) -> [WheelPosition; WHEEL_COUNT] {
        self.positions
    }

    pub const fn pins(&self) -> [PinPattern; WHEEL_COUNT] {
        self.pins
    }

    pub fn windows(&self) -> [WindowLabel; WHEEL_COUNT] {
        std::array::from_fn(|index| self.positions[index].label())
    }

    /// Create a fresh, independent stateful SG-41 cipher engine.
    pub fn build_core(&self) -> Sg41Core {
        let bank = WheelBank::new(self.positions, self.pins)
            .expect("Sg41Config was validated on construction");

        Sg41Core::new(bank)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WheelError;

    const REFERENCE_PINS: [&str; WHEEL_COUNT] = [
        "0001101011000100010001101",
        "0110100100001011100101100",
        "11001001000100100100010",
        "01001000111010001110010",
        "001001001010000101011010",
        "011001100110001011010100",
    ];

    const REFERENCE_WINDOWS: [WindowLabel; WHEEL_COUNT] = [
        WindowLabel::Letter('A'),
        WindowLabel::Letter('B'),
        WindowLabel::Letter('C'),
        WindowLabel::Letter('D'),
        WindowLabel::Number(1),
        WindowLabel::Number(0),
    ];

    fn reference_config() -> Sg41Config {
        Sg41Config::from_key_settings(REFERENCE_WINDOWS, REFERENCE_PINS).unwrap()
    }

    #[test]
    fn reference_configuration_enciphers_historical_vector() {
        let config = reference_config();
        assert_eq!(config.windows(), REFERENCE_WINDOWS);

        let mut core = config.build_core();
        let result: String = "SCHLUESSELGERAETVIEREINSWANDERER"
            .chars()
            .map(|letter| core.encipher_char(letter).unwrap().output)
            .collect();

        assert_eq!(result, "IHEPLRETQSDSNDCWHPIVVGLYMHOWSJQS");
        assert_eq!(config.windows(), REFERENCE_WINDOWS);

        let mut another = config.build_core();
        assert_eq!(another.encipher_char('S').unwrap().output, 'I');
    }

    #[test]
    fn configuration_is_reciprocal() {
        let config = reference_config();
        let mut core = config.build_core();
        let plain = "SCHLUESSELGERAETVIEREINSWANDERER";
        let cipher: String = plain.chars()
            .map(|ch| core.encipher_char(ch).unwrap().output)
            .collect();

        let mut decoder = config.build_core();
        let recovered: String = cipher.chars()
            .map(|ch| decoder.decipher_char(ch).unwrap().output)
            .collect();

        assert_eq!(recovered, plain);
    }

    #[test]
    fn rejects_invalid_windows_and_pin_settings() {
        let mut invalid_windows = REFERENCE_WINDOWS;
        invalid_windows[0] = WindowLabel::Letter('J');
        assert!(matches!(
            Sg41Config::from_key_settings(invalid_windows, REFERENCE_PINS),
            Err(ConfigError::Wheel(WheelError::InvalidLabel { wheel: 1, .. }))
        ));

        invalid_windows = REFERENCE_WINDOWS;
        invalid_windows[5] = WindowLabel::Number(1);
        assert!(matches!(
            Sg41Config::from_key_settings(invalid_windows, REFERENCE_PINS),
            Err(ConfigError::Wheel(WheelError::InvalidMarking { wheel: 6, .. }))
        ));

        let mut invalid_pins = REFERENCE_PINS;
        invalid_pins[2] = "001";
        assert!(matches!(
            Sg41Config::from_key_settings(REFERENCE_WINDOWS, invalid_pins),
            Err(ConfigError::Wheel(WheelError::PinCount { wheel: 3, .. }))
        ));

        invalid_pins = REFERENCE_PINS;
        invalid_pins[4] = "x01001001010000101011010";
        assert!(matches!(
            Sg41Config::from_key_settings(REFERENCE_WINDOWS, invalid_pins),
            Err(ConfigError::Wheel(WheelError::InvalidPinBit { wheel: 5, .. }))
        ));
    }

    #[test]
    fn rejects_mismatched_typed_wheels() {
        let config = reference_config();
        let mut pins = config.pins();
        pins.swap(0, 1);

        assert!(matches!(
            Sg41Config::new(config.positions(), pins),
            Err(ConfigError::Wheel(WheelError::WheelMismatch { .. }))
        ));
    }
}
