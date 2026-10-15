//! Standard reference wiring tables and rotor definitions for TSEC/KL-7.
//!
//! Provides the Dirk Rijmenants reference dataset:
//! - 13 standard rotor cores (A through M);
//! - Standard sliding baseplate / cipher unit endplate mapping.

use super::{
    contact::{Contact26, Contact36, ReentryWire},
    permutation::Permutation,
};
use core::fmt;

/// Identification of one of the 13 KL-7 rotor cores.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RotorId {
    A = 0,
    B = 1,
    C = 2,
    D = 3,
    E = 4,
    F = 5,
    G = 6,
    H = 7,
    I = 8,
    J = 9,
    K = 10,
    L = 11,
    M = 12,
}

impl RotorId {
    /// Return the 0-based rotor index (0..12).
    #[must_use]
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Return the single letter name ('A'..='M').
    #[must_use]
    pub const fn to_char(self) -> char {
        (b'A' + self as u8) as char
    }

    /// Construct from character ('A'..='M' or 'a'..='m').
    pub fn from_char(ch: char) -> Option<Self> {
        match ch.to_ascii_uppercase() {
            'A' => Some(Self::A),
            'B' => Some(Self::B),
            'C' => Some(Self::C),
            'D' => Some(Self::D),
            'E' => Some(Self::E),
            'F' => Some(Self::F),
            'G' => Some(Self::G),
            'H' => Some(Self::H),
            'I' => Some(Self::I),
            'J' => Some(Self::J),
            'K' => Some(Self::K),
            'L' => Some(Self::L),
            'M' => Some(Self::M),
            _ => None,
        }
    }
}

impl fmt::Display for RotorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_char())
    }
}

/// Standard 0-indexed permutation mapping for Rotor Core A.
pub const ROTOR_A_MAP: [u8; 36] = [
    28, 26, 13, 7, 34, 3, 27, 10, 4, 12, 19, 2, 24, 32, 17, 14, 6, 11, 33, 15, 16, 0, 8, 29, 23,
    22, 1, 31, 9, 18, 5, 25, 35, 21, 30, 20,
];

/// Standard 0-indexed permutation mapping for Rotor Core B.
pub const ROTOR_B_MAP: [u8; 36] = [
    22, 18, 25, 15, 1, 12, 13, 34, 20, 3, 16, 30, 24, 2, 17, 26, 11, 33, 35, 9, 29, 5, 6, 14, 27,
    0, 10, 32, 28, 19, 31, 23, 4, 21, 7, 8,
];

/// Standard 0-indexed permutation mapping for Rotor Core C.
pub const ROTOR_C_MAP: [u8; 36] = [
    18, 25, 27, 35, 5, 24, 30, 17, 26, 9, 4, 0, 31, 8, 10, 32, 22, 16, 28, 11, 12, 1, 15, 14, 34,
    7, 23, 21, 29, 2, 33, 13, 6, 19, 20, 3,
];

/// Standard 0-indexed permutation mapping for Rotor Core D.
pub const ROTOR_D_MAP: [u8; 36] = [
    14, 25, 35, 12, 0, 30, 24, 32, 2, 31, 20, 22, 16, 28, 6, 21, 19, 23, 11, 9, 13, 29, 18, 27, 3,
    34, 4, 7, 5, 8, 15, 26, 1, 10, 33, 17,
];

/// Standard 0-indexed permutation mapping for Rotor Core E.
pub const ROTOR_E_MAP: [u8; 36] = [
    12, 3, 1, 15, 16, 29, 20, 4, 32, 6, 28, 7, 8, 35, 34, 22, 33, 24, 19, 21, 27, 14, 0, 18, 23,
    26, 9, 10, 5, 11, 31, 25, 13, 2, 17, 30,
];

/// Standard 0-indexed permutation mapping for Rotor Core F.
pub const ROTOR_F_MAP: [u8; 36] = [
    25, 33, 26, 13, 1, 0, 30, 35, 10, 8, 34, 17, 14, 11, 3, 6, 28, 7, 22, 18, 2, 29, 19, 16, 27,
    20, 21, 4, 24, 32, 15, 12, 23, 5, 9, 31,
];

/// Standard 0-indexed permutation mapping for Rotor Core G.
pub const ROTOR_G_MAP: [u8; 36] = [
    19, 18, 8, 31, 35, 1, 5, 32, 11, 27, 3, 9, 2, 23, 28, 15, 21, 17, 29, 16, 6, 33, 14, 22, 30,
    24, 26, 0, 20, 25, 7, 4, 12, 34, 10, 13,
];

/// Standard 0-indexed permutation mapping for Rotor Core H.
pub const ROTOR_H_MAP: [u8; 36] = [
    27, 18, 22, 4, 16, 35, 26, 13, 15, 19, 20, 6, 11, 21, 10, 34, 12, 14, 0, 31, 7, 17, 32, 3, 8,
    28, 25, 23, 24, 33, 9, 5, 2, 29, 1, 30,
];

/// Standard 0-indexed permutation mapping for Rotor Core I.
pub const ROTOR_I_MAP: [u8; 36] = [
    24, 5, 34, 11, 20, 21, 18, 31, 19, 22, 29, 17, 0, 15, 30, 10, 23, 12, 32, 6, 35, 8, 33, 1, 9,
    7, 25, 28, 14, 16, 3, 27, 13, 2, 26, 4,
];

/// Standard 0-indexed permutation mapping for Rotor Core J.
pub const ROTOR_J_MAP: [u8; 36] = [
    7, 30, 0, 27, 19, 5, 31, 4, 32, 20, 29, 11, 3, 13, 14, 33, 6, 34, 15, 17, 28, 21, 24, 25, 35,
    10, 22, 18, 2, 1, 12, 26, 23, 9, 16, 8,
];

/// Standard 0-indexed permutation mapping for Rotor Core K.
pub const ROTOR_K_MAP: [u8; 36] = [
    14, 12, 35, 22, 5, 20, 31, 17, 30, 19, 0, 23, 9, 34, 18, 27, 6, 7, 25, 11, 28, 21, 24, 29, 4,
    8, 1, 26, 15, 3, 16, 2, 33, 13, 10, 32,
];

/// Standard 0-indexed permutation mapping for Rotor Core L.
pub const ROTOR_L_MAP: [u8; 36] = [
    7, 17, 14, 32, 6, 25, 19, 15, 33, 22, 35, 26, 11, 23, 18, 12, 1, 2, 13, 28, 0, 5, 31, 9, 24,
    29, 8, 4, 27, 16, 21, 30, 3, 10, 20, 34,
];

/// Standard 0-indexed permutation mapping for Rotor Core M (introduced 1975).
pub const ROTOR_M_MAP: [u8; 36] = [
    35, 5, 28, 27, 23, 25, 20, 21, 19, 34, 14, 18, 22, 29, 0, 7, 11, 6, 12, 26, 30, 31, 8, 32, 9,
    15, 13, 17, 33, 1, 2, 16, 24, 10, 3, 4,
];

/// The 13 standard reference permutations.
pub const REFERENCE_ROTOR_MAPS: [[u8; 36]; 13] = [
    ROTOR_A_MAP,
    ROTOR_B_MAP,
    ROTOR_C_MAP,
    ROTOR_D_MAP,
    ROTOR_E_MAP,
    ROTOR_F_MAP,
    ROTOR_G_MAP,
    ROTOR_H_MAP,
    ROTOR_I_MAP,
    ROTOR_J_MAP,
    ROTOR_K_MAP,
    ROTOR_L_MAP,
    ROTOR_M_MAP,
];

/// Standard baseplate pin connection list:
/// Pin indices 0..35 connect to either a letter ('A'..='Z') or a re-entry loop wire (0..9).
///
/// Order of 36 base contacts from pin 0 to pin 35:
/// Q, P, 0, N, F, C, 3, Y, O, M, 9, G, R, 8, U, I, 7, B, H, 2, V, T, W, 6, X, S, 4, J, L, Z, 5, D, K, E, A, 1
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BasePlateTerminal {
    Letter(Contact26),
    Reentry(ReentryWire),
}

/// Standard Baseplate mapping table for pins 0..35.
pub const BASE_PLATE_TERMINALS: [BasePlateTerminal; 36] = [
    BasePlateTerminal::Letter(Contact26::new(16).unwrap()), // 0: Q
    BasePlateTerminal::Letter(Contact26::new(15).unwrap()), // 1: P
    BasePlateTerminal::Reentry(ReentryWire::new(0).unwrap()), // 2: 0
    BasePlateTerminal::Letter(Contact26::new(13).unwrap()), // 3: N
    BasePlateTerminal::Letter(Contact26::new(5).unwrap()),  // 4: F
    BasePlateTerminal::Letter(Contact26::new(2).unwrap()),  // 5: C
    BasePlateTerminal::Reentry(ReentryWire::new(3).unwrap()), // 6: 3
    BasePlateTerminal::Letter(Contact26::new(24).unwrap()), // 7: Y
    BasePlateTerminal::Letter(Contact26::new(14).unwrap()), // 8: O
    BasePlateTerminal::Letter(Contact26::new(12).unwrap()), // 9: M
    BasePlateTerminal::Reentry(ReentryWire::new(9).unwrap()), // 10: 9
    BasePlateTerminal::Letter(Contact26::new(6).unwrap()),  // 11: G
    BasePlateTerminal::Letter(Contact26::new(17).unwrap()), // 12: R
    BasePlateTerminal::Reentry(ReentryWire::new(8).unwrap()), // 13: 8
    BasePlateTerminal::Letter(Contact26::new(20).unwrap()), // 14: U
    BasePlateTerminal::Letter(Contact26::new(8).unwrap()),  // 15: I
    BasePlateTerminal::Reentry(ReentryWire::new(7).unwrap()), // 16: 7
    BasePlateTerminal::Letter(Contact26::new(1).unwrap()),  // 17: B
    BasePlateTerminal::Letter(Contact26::new(7).unwrap()),  // 18: H
    BasePlateTerminal::Reentry(ReentryWire::new(2).unwrap()), // 19: 2
    BasePlateTerminal::Letter(Contact26::new(21).unwrap()), // 20: V
    BasePlateTerminal::Letter(Contact26::new(19).unwrap()), // 21: T
    BasePlateTerminal::Letter(Contact26::new(22).unwrap()), // 22: W
    BasePlateTerminal::Reentry(ReentryWire::new(6).unwrap()), // 23: 6
    BasePlateTerminal::Letter(Contact26::new(23).unwrap()), // 24: X
    BasePlateTerminal::Letter(Contact26::new(18).unwrap()), // 25: S
    BasePlateTerminal::Reentry(ReentryWire::new(4).unwrap()), // 26: 4
    BasePlateTerminal::Letter(Contact26::new(9).unwrap()),  // 27: J
    BasePlateTerminal::Letter(Contact26::new(11).unwrap()), // 28: L
    BasePlateTerminal::Letter(Contact26::new(25).unwrap()), // 29: Z
    BasePlateTerminal::Reentry(ReentryWire::new(5).unwrap()), // 30: 5
    BasePlateTerminal::Letter(Contact26::new(3).unwrap()),  // 31: D
    BasePlateTerminal::Letter(Contact26::new(10).unwrap()), // 32: K
    BasePlateTerminal::Letter(Contact26::new(4).unwrap()),  // 33: E
    BasePlateTerminal::Letter(Contact26::new(0).unwrap()),  // 34: A
    BasePlateTerminal::Reentry(ReentryWire::new(1).unwrap()), // 35: 1
];

/// Get the endplate pin index for a letter contact (A=0..Z=25).
#[must_use]
pub fn letter_to_pin(letter: Contact26) -> Contact36 {
    for (pin, terminal) in BASE_PLATE_TERMINALS.iter().enumerate() {
        if let BasePlateTerminal::Letter(l) = terminal
            && *l == letter
        {
            return Contact36::new(pin as u8).unwrap();
        }
    }
    unreachable!("All 26 letters are present on the baseplate");
}

/// Get the endplate pin index for a re-entry loop wire (0..9).
#[must_use]
pub fn reentry_to_pin(wire: ReentryWire) -> Contact36 {
    for (pin, terminal) in BASE_PLATE_TERMINALS.iter().enumerate() {
        if let BasePlateTerminal::Reentry(w) = terminal
            && *w == wire
        {
            return Contact36::new(pin as u8).unwrap();
        }
    }
    unreachable!("All 10 reentry wires are present on the baseplate");
}

/// Get the baseplate terminal at a given endplate pin index (0..35).
#[must_use]
pub const fn pin_to_terminal(pin: Contact36) -> BasePlateTerminal {
    BASE_PLATE_TERMINALS[pin.get() as usize]
}

/// Return the validated reference permutation for a standard rotor.
#[must_use]
pub fn reference_rotor_permutation(id: RotorId) -> Permutation<36> {
    Permutation::new(REFERENCE_ROTOR_MAPS[id.index()]).expect("reference rotor mapping is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_13_reference_rotors_are_valid_permutations() {
        for (idx, &map) in REFERENCE_ROTOR_MAPS.iter().enumerate() {
            let perm = Permutation::new(map);
            assert!(perm.is_ok(), "Rotor index {} is invalid", idx);
        }
    }

    #[test]
    fn baseplate_contains_26_unique_letters_and_10_unique_reentry_wires() {
        let mut letters_seen = [false; 26];
        let mut reentry_seen = [false; 10];

        for &terminal in &BASE_PLATE_TERMINALS {
            match terminal {
                BasePlateTerminal::Letter(l) => {
                    assert!(!letters_seen[l.get() as usize]);
                    letters_seen[l.get() as usize] = true;
                }
                BasePlateTerminal::Reentry(w) => {
                    assert!(!reentry_seen[w.get() as usize]);
                    reentry_seen[w.get() as usize] = true;
                }
            }
        }

        assert!(letters_seen.iter().all(|&b| b));
        assert!(reentry_seen.iter().all(|&b| b));
    }

    #[test]
    fn letter_and_pin_round_trip() {
        for l in 0..26 {
            let letter = Contact26::new(l).unwrap();
            let pin = letter_to_pin(letter);
            assert_eq!(pin_to_terminal(pin), BasePlateTerminal::Letter(letter));
        }

        for w in 0..10 {
            let wire = ReentryWire::new(w).unwrap();
            let pin = reentry_to_pin(wire);
            assert_eq!(pin_to_terminal(pin), BasePlateTerminal::Reentry(wire));
        }
    }
}
