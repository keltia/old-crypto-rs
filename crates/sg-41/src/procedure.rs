//! Historical SG-41 daily keys, sender station settings and message windows.
//!
//! These operations construct validated key settings; they do not advance wheels.

use super::error::ProcedureError;
use super::message::MessageIndicator;
use super::types::{WHEEL_COUNT, WheelId, WindowLabel};
use super::Sg41Config;

/// The 26 labeled rows of a monthly pin table, in alphabetic A-Z order.
///
/// Each labeled row contains 25 pin settings. The daily key selects one
/// row for each wheel, taking only as many bits as that wheel has pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonthlyPinTable {
    rows: [String; 26],
}

impl MonthlyPinTable {
    pub fn new(rows: [String; 26]) -> Result<Self, ProcedureError> {
        for (index, bits) in rows.iter().enumerate() {
            let row = (b'A' + index as u8) as char;
            if bits.len() != 25 || !bits.bytes().all(|byte| matches!(byte, b'0' | b'1')) {
                return Err(ProcedureError::InvalidMonthlyRow { row });
            }
        }

        Ok(Self { rows })
    }

    pub fn select(&self, daily: &DailyKey) -> [&str; WHEEL_COUNT] {
        std::array::from_fn(|index| {
            let row = usize::from(daily.letters[index] - b'A');
            let wheel = WheelId::new(index as u8 + 1).expect("six fixed wheels");
            &self.rows[row][..wheel.length() as usize]
        })
    }
}

/// The six letters of a daily key, selecting one monthly-table row per wheel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DailyKey {
    letters: [u8; WHEEL_COUNT],
}

impl DailyKey {
    pub fn new(letters: [u8; WHEEL_COUNT]) -> Result<Self, ProcedureError> {
        for (index, &letter) in letters.iter().enumerate() {
            if !letter.is_ascii_uppercase() {
                return Err(ProcedureError::InvalidDailyLetter { index, letter });
            }
        }

        Ok(Self { letters })
    }

    pub const fn letters(self) -> [u8; WHEEL_COUNT] {
        self.letters
    }
}

/// The sender's two station numbers, displayed by wheels five and six.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StationNumbers {
    wheel_five: u8,
    wheel_six: u8,
}

impl StationNumbers {
    pub fn new(wheel_five: u8, wheel_six: u8) -> Result<Self, ProcedureError> {
        WheelId::new(5).expect("fixed wheel").position(WindowLabel::Number(wheel_five))?;
        WheelId::new(6).expect("fixed wheel").position(WindowLabel::Number(wheel_six))?;

        Ok(Self { wheel_five, wheel_six })
    }

    pub const fn numbers(self) -> (u8, u8) {
        (self.wheel_five, self.wheel_six)
    }
}

/// Identifies the calendar quarter for which a station assignment is valid.
/// Does not invent an assignment or infer station numbers from a date.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quarter {
    year: u16,
    number: u8,
}

impl Quarter {
    pub fn new(year: u16, number: u8) -> Result<Self, ProcedureError> {
        if !(1..=4).contains(&number) {
            return Err(ProcedureError::InvalidQuarter(number));
        }

        Ok(Self { year, number })
    }

    pub fn for_month(year: u16, month: u8) -> Result<Self, ProcedureError> {
        if !(1..=12).contains(&month) {
            return Err(ProcedureError::InvalidMonth(month));
        }

        Self::new(year, (month - 1) / 3 + 1)
    }

    pub const fn year(self) -> u16 {
        self.year
    }

    pub const fn number(self) -> u8 {
        self.number
    }
}

/// A known sender station assignment. No global station-number registry is implied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StationAssignment {
    pub quarter: Quarter,
    pub numbers: StationNumbers,
}

impl StationAssignment {
    pub fn for_date(self, year: u16, month: u8) -> Result<StationNumbers, ProcedureError> {
        if self.quarter != Quarter::for_month(year, month)? {
            return Err(ProcedureError::StationQuarterMismatch);
        }

        Ok(self.numbers)
    }
}

/// Construct all six windows in historical physical order, then use the
/// monthly table and daily key to select the six wheel pin patterns.
///
/// For reception, `sender` must be the *originating station*, not the receiver.
pub fn historical_config(
    monthly: &MonthlyPinTable,
    daily: &DailyKey,
    indicator: &MessageIndicator,
    sender: StationNumbers,
) -> Result<Sg41Config, ProcedureError> {
    let indicator = indicator.letters();
    let (fifth, sixth) = sender.numbers();
    let windows = [
        WindowLabel::Letter(char::from(indicator[0])),
        WindowLabel::Letter(char::from(indicator[1])),
        WindowLabel::Letter(char::from(indicator[2])),
        WindowLabel::Letter(char::from(indicator[3])),
        WindowLabel::Number(fifth),
        WindowLabel::Number(sixth),
    ];

    Ok(Sg41Config::from_key_settings(windows, monthly.select(daily))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> MonthlyPinTable {
        MonthlyPinTable::new(std::array::from_fn(|_| "0".repeat(25))).unwrap()
    }

    #[test]
    fn historical_windows_use_sender_numbers() {
        let config = historical_config(
            &table(),
            &DailyKey::new(*b"ACHUKW").unwrap(),
            &MessageIndicator::new(*b"KNVP").unwrap(),
            StationNumbers::new(18, 37).unwrap(),
        ).unwrap();

        assert_eq!(config.windows(), [
            WindowLabel::Letter('K'), WindowLabel::Letter('N'),
            WindowLabel::Letter('V'), WindowLabel::Letter('P'),
            WindowLabel::Number(18), WindowLabel::Number(37),
        ]);
    }

    #[test]
    fn station_markings_are_validated_against_actual_wheels() {
        assert!(StationNumbers::new(18, 37).is_ok());
        assert!(StationNumbers::new(0, 37).is_err());
        assert!(StationNumbers::new(18, 38).is_err());
    }

    #[test]
    fn quarters_change_in_january_april_july_october() {
        let assignment = StationAssignment {
            quarter: Quarter::for_month(1945, 3).unwrap(),
            numbers: StationNumbers::new(18, 37).unwrap(),
        };
        assert_eq!(assignment.for_date(1945, 3).unwrap().numbers(), (18, 37));
        assert!(assignment.for_date(1945, 4).is_err());
        assert!(Quarter::for_month(1945, 13).is_err());
    }

    #[test]
    fn daily_key_selects_one_row_per_wheel() {
        let mut rows = std::array::from_fn(|_| "0".repeat(25));
        rows[0].replace_range(0..1, "1");
        rows[2].replace_range(0..1, "1");
        let monthly = MonthlyPinTable::new(rows).unwrap();
        let pins = monthly.select(&DailyKey::new(*b"ACHUKW").unwrap());
        assert!(pins[0].starts_with('1'));
        assert!(pins[1].starts_with('1'));
        assert!(pins[2].starts_with('0'));
    }
}
