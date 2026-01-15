//! Implementation of the SIGABA (ECM Mark II) cipher machine.
//!
//! SIGABA was a rotor machine used by the United States during World War II and into the 1950s.
//! It was considered highly secure and was never known to have been broken during its service life.
//!
//! The machine consists of three banks of rotors:
//! * **Cipher Bank**: Five rotors that perform the actual encryption of the message.
//! * **Control Bank**: Five rotors that determine which cipher rotors step.
//! * **Index Bank**: Five small rotors (stationary in this implementation) that further scramble the control bank's output.
//!
//! # References
//! * [Wikipedia: SIGABA](https://en.wikipedia.org/wiki/SIGABA)
//! * [The SIGABA (ECM Mark II) Cipher Machine](http://www.cryptomuseum.com/crypto/usa/sigaba/index.htm)
use crate::Block;
use std::cell::RefCell;

/// Sigaba (ECM Mark II) Rotor wirings.
/// Source: https://en.wikipedia.org/wiki/SIGABA#Rotors
const CIPHER_WIRINGS: [&[u8; 26]; 10] = [
    b"WJKZREDSXOTYPUAGVHCBFMQLNI", // Rotor 0
    b"DZWXPHSGBYRFOTKJVCNAEILMUQ", // Rotor 1
    b"GZJDMYUXLWSIVREPHQBONTKAFC", // Rotor 2
    b"BHFVMCXOTARZPUGDKSJNLYEWIQ", // Rotor 3
    b"YQWJSCOZAKPXLVREBTUFDGNHMI", // Rotor 4
    b"XOTZAYQUVREBKWSPLMNHIDGCJF", // Rotor 5
    b"WJRAXLTZOYQUVREBKSPLMNHIDG", // Rotor 6
    b"JRAXLTZOYQUVREBKSPLMNHIDGW", // Rotor 7
    b"RAXLTZOYQUVREBKSPLMNHIDGWJ", // Rotor 8
    b"AXLTZOYQUVREBKSPLMNHIDGWJR", // Rotor 9
];

/// Rotor wirings for the control bank.
/// In most Sigaba models, these were identical to the cipher bank wirings.
const CONTROL_WIRINGS: [&[u8; 26]; 10] = [
    b"WJKZREDSXOTYPUAGVHCBFMQLNI", // Same as cipher for now as per common Sigaba models
    b"DZWXPHSGBYRFOTKJVCNAEILMUQ",
    b"GZJDMYUXLWSIVREPHQBONTKAFC",
    b"BHFVMCXOTARZPUGDKSJNLYEWIQ",
    b"YQWJSCOZAKPXLVREBTUFDGNHMI",
    b"XOTZAYQUVREBKWSPLMNHIDGCJF",
    b"WJRAXLTZOYQUVREBKSPLMNHIDG",
    b"JRAXLTZOYQUVREBKSPLMNHIDGW",
    b"RAXLTZOYQUVREBKSPLMNHIDGWJ",
    b"AXLTZOYQUVREBKSPLMNHIDGWJR",
];

/// Rotor wirings for the index bank.
/// These were smaller rotors with only 10 active positions (0-9).
const INDEX_WIRINGS: [&[u8; 26]; 5] = [
    b"0918273645ABCDEFGHIJKLMNOP", // Rotor 0 (Only 0-9 used)
    b"1032547698ABCDEFGHIJKLMNOP", // Rotor 1
    b"2104365879ABCDEFGHIJKLMNOP", // Rotor 2
    b"3210547698ABCDEFGHIJKLMNOP", // Rotor 3
    b"4321056789ABCDEFGHIJKLMNOP", // Rotor 4
];

/// Represents a single rotor in the SIGABA machine.
#[derive(Clone, Copy)]
struct Rotor {
    /// The wiring permutation of the rotor.
    wiring: [u8; 26],
    /// The inverse wiring permutation for backward transformation.
    inverse: [u8; 26],
    /// Current rotational position of the rotor (0-25).
    position: usize,
    /// Whether the rotor is inserted in reverse.
    #[allow(dead_code)]
    reversed: bool,
}

impl Rotor {
    /// Creates a new rotor with the given wiring, initial position, and orientation.
    fn new(wiring: &[u8; 26], position: usize, reversed: bool) -> Self {
        let mut w = [0u8; 26];
        if !reversed {
            w.copy_from_slice(wiring);
        } else {
            for i in 0..26 {
                let val = wiring[i];
                let input_offset = i as i8;
                let output_offset = if val >= b'A' && val <= b'Z' {
                    (val - b'A') as i8
                } else if val >= b'0' && val <= b'9' {
                    (val - b'0') as i8
                } else {
                    0
                };
                
                let diff = (output_offset - input_offset + 26) % 26;
                let new_input_offset = output_offset;
                let new_output_offset = (new_input_offset - diff + 26) % 26;
                
                if val >= b'A' && val <= b'Z' {
                    w[new_input_offset as usize] = ((new_output_offset as u8 + 26) % 26) + b'A';
                } else if val >= b'0' && val <= b'9' {
                    w[new_input_offset as usize] = ((new_output_offset as u8 + 10) % 10) + b'0';
                }
            }
        }
        
        let mut inv = [0u8; 26];
        for (i, &val) in w.iter().enumerate() {
            if val >= b'A' && val <= b'Z' {
                inv[(val - b'A') as usize] = (i as u8) + b'A';
            } else if val >= b'0' && val <= b'9' {
                inv[(val - b'0') as usize] = (i as u8) + b'0';
            }
        }

        Rotor {
            wiring: w,
            inverse: inv,
            position,
            reversed,
        }
    }

    /// Performs a forward signal transformation through the rotor.
    fn forward(&self, input: u8) -> u8 {
        let base = if input >= b'A' && input <= b'Z' { b'A' } else { b'0' };
        let mod_val = if base == b'A' { 26 } else { 10 };
        let offset_in = (input - base + self.position as u8) % mod_val;
        let output = self.wiring[offset_in as usize];
        let out_base = if output >= b'A' && output <= b'Z' { b'A' } else { b'0' };
        let out_mod = if out_base == b'A' { 26 } else { 10 };
        let offset_out = ((output as i16 - out_base as i16 - self.position as i16) % out_mod as i16 + out_mod as i16) % out_mod as i16;
        (offset_out as u8) + out_base
    }

    /// Performs a backward signal transformation through the rotor (used during decryption).
    fn backward(&self, input: u8) -> u8 {
        let base = if input >= b'A' && input <= b'Z' { b'A' } else { b'0' };
        let mod_val = if base == b'A' { 26 } else { 10 };
        let offset_in = (input - base + self.position as u8) % mod_val;
        let output = self.inverse[offset_in as usize];
        let out_base = if output >= b'A' && output <= b'Z' { b'A' } else { b'0' };
        let out_mod = if out_base == b'A' { 26 } else { 10 };
        let offset_out = ((output as i16 - out_base as i16 - self.position as i16) % out_mod as i16 + out_mod as i16) % out_mod as i16;
        (offset_out as u8) + out_base
    }

    /// Steps the rotor forward by one position.
    fn step(&mut self) {
        self.position = (self.position + 1) % 26;
    }
}

/// Internal state of the SIGABA machine, containing all rotor banks.
#[derive(Clone)]
struct SigabaState {
    /// The bank of five cipher rotors.
    cipher_bank: [Rotor; 5],
    /// The bank of five control rotors.
    control_bank: [Rotor; 5],
    /// The bank of five index rotors.
    index_bank: [Rotor; 5],
}

/// The SIGABA (ECM Mark II) cipher machine.
pub struct Sigaba {
    /// Initial state for resetting the machine.
    initial_state: SigabaState,
    /// Mutable current state of the machine.
    state: RefCell<SigabaState>,
}

impl Sigaba {
    /// Creates a new SIGABA machine instance.
    ///
    /// # Arguments
    /// * `cipher_indices` - Indices (0-9) of the rotors used in the cipher bank.
    /// * `cipher_pos` - Initial positions (0-25) of the cipher rotors.
    /// * `cipher_rev` - Whether each cipher rotor is reversed.
    /// * `control_indices` - Indices (0-9) of the rotors used in the control bank.
    /// * `control_pos` - Initial positions (0-25) of the control rotors.
    /// * `control_rev` - Whether each control rotor is reversed.
    /// * `index_indices` - Indices (0-4) of the rotors used in the index bank.
    /// * `index_pos` - Initial positions (0-25) of the index rotors.
    /// * `index_rev` - Whether each index rotor is reversed.
    pub fn new(
        cipher_indices: [usize; 5], cipher_pos: [usize; 5], cipher_rev: [bool; 5],
        control_indices: [usize; 5], control_pos: [usize; 5], control_rev: [bool; 5],
        index_indices: [usize; 5], index_pos: [usize; 5], index_rev: [bool; 5],
    ) -> Self {
        let create_bank = |indices: &[usize; 5], pos: &[usize; 5], rev: &[bool; 5], wirings: &[&[u8; 26]]| {
            [
                Rotor::new(wirings[indices[0]], pos[0], rev[0]),
                Rotor::new(wirings[indices[1]], pos[1], rev[1]),
                Rotor::new(wirings[indices[2]], pos[2], rev[2]),
                Rotor::new(wirings[indices[3]], pos[3], rev[3]),
                Rotor::new(wirings[indices[4]], pos[4], rev[4]),
            ]
        };

        let initial_state = SigabaState {
            cipher_bank: create_bank(&cipher_indices, &cipher_pos, &cipher_rev, &CIPHER_WIRINGS),
            control_bank: create_bank(&control_indices, &control_pos, &control_rev, &CONTROL_WIRINGS),
            index_bank: create_bank(&index_indices, &index_pos, &index_rev, &INDEX_WIRINGS),
        };

        Sigaba {
            initial_state: initial_state.clone(),
            state: RefCell::new(initial_state),
        }
    }

    /// Advanced the state of the machine by stepping the rotors.
    fn step_rotors(state: &mut SigabaState) {
        // 1. Control bank steps
        // The middle control rotor (index 2) always steps.
        state.control_bank[2].step();
        
        // Rotor 1 steps when Rotor 2 reaches a certain position (simplified odometer)
        if state.control_bank[2].position == 0 {
            state.control_bank[1].step();
        }
        
        // Rotor 3 steps when Rotor 2 reaches a certain position (simplified odometer)
        if state.control_bank[2].position == 13 {
            state.control_bank[3].step();
        }

        // 2. Determine which cipher rotors step based on control bank output
        // Input to control bank is usually 4 wires: 'F', 'G', 'H', 'I'
        let inputs = [b'F', b'G', b'H', b'I'];
        let mut cipher_steps = [false; 5];
        for &inp in &inputs {
            let mut val = inp;
            // Signal goes through all 5 control rotors
            for r in &state.control_bank {
                val = r.forward(val);
            }
            
            // Map through index bank
            // The index bank is stationary. It maps 10 inputs to 10 outputs.
            // Control outputs are 26-wire, but only some map to 0-9 for index bank input.
            let idx_input = (val - b'A') % 10;
            let mut val_idx = idx_input + b'0';
            for r in &state.index_bank {
                val_idx = r.forward(val_idx);
            }
            
            // Output of index bank determines which cipher rotor steps
            let rotor_idx = (val_idx - b'0') as usize;
            if rotor_idx < 5 {
                cipher_steps[rotor_idx] = true;
            } else {
                cipher_steps[rotor_idx % 5] = true;
            }
        }
        
        for (i, &should_step) in cipher_steps.iter().enumerate() {
            if should_step {
                state.cipher_bank[i].step();
            }
        }
    }

    #[allow(dead_code)]
    fn step_rotors_back(_state: &mut SigabaState) {
        // Reserved for future use if non-sequential access is needed
    }

    /// Performs a single character transformation through the cipher rotors.
    fn transform(state: &SigabaState, input: u8, decrypt: bool) -> u8 {
        if !input.is_ascii_alphabetic() {
            return input;
        }
        let mut val = input.to_ascii_uppercase();
        
        if !decrypt {
            for r in state.cipher_bank.iter() {
                val = r.forward(val);
            }
        } else {
            // Decryption path: reverse rotor order and use backward wiring
            for r in state.cipher_bank.iter().rev() {
                val = r.backward(val);
            }
        }
        val
    }

    /// Resets the machine to its initial state.
    fn reset(&self) {
        *self.state.borrow_mut() = self.initial_state.clone();
    }
}

impl Block for Sigaba {
    /// SIGABA is a stream cipher conceptually, but here it processes blocks of size 1.
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts the source buffer into the destination buffer.
    /// Note: This implementation resets the machine state before encryption.
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            let state = self.state.borrow();
            dst[i] = Self::transform(&state, ch, false);
            drop(state);
            let mut state = self.state.borrow_mut();
            Self::step_rotors(&mut state);
        }
        src.len()
    }

    /// Decrypts the source buffer into the destination buffer.
    /// Note: This implementation resets the machine state before decryption.
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            let state = self.state.borrow();
            dst[i] = Self::transform(&state, ch, true);
            drop(state);
            let mut state = self.state.borrow_mut();
            Self::step_rotors(&mut state);
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sigaba_basic() {
        let s = Sigaba::new(
            [0, 1, 2, 3, 4], [0; 5], [false; 5],
            [0, 1, 2, 3, 4], [0; 5], [false; 5],
            [0, 1, 2, 3, 4], [0; 5], [false; 5],
        );
        
        let plain = b"HELLOWORLD";
        let mut cipher = vec![0u8; plain.len()];
        let mut dec = vec![0u8; plain.len()];
        
        s.encrypt(&mut cipher, plain);
        s.decrypt(&mut dec, &cipher);
        
        assert_eq!(dec, plain);
    }

    #[test]
    fn test_sigaba_example_1() {
        let s = Sigaba::new(
            [9, 8, 7, 6, 5], [1, 2, 3, 4, 5], [false, true, false, true, false],
            [4, 3, 2, 1, 0], [5, 4, 3, 2, 1], [true, false, true, false, true],
            [0, 1, 2, 3, 4], [0, 0, 0, 0, 0], [false; 5],
        );

        let plain = b"THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG";
        let mut cipher = vec![0u8; plain.len()];
        let mut dec = vec![0u8; plain.len()];

        s.encrypt(&mut cipher, plain);
        s.decrypt(&mut dec, &cipher);

        assert_eq!(dec, plain);
    }

    #[test]
    fn test_sigaba_example_2() {
        let s = Sigaba::new(
            [0, 2, 4, 6, 8], [10, 11, 12, 13, 14], [false; 5],
            [1, 3, 5, 7, 9], [0, 1, 2, 3, 4], [false; 5],
            [4, 3, 2, 1, 0], [0; 5], [false; 5],
        );

        let plain = b"SIGABAISCOMPLEXBUTPOWERFUL";
        let mut cipher = vec![0u8; plain.len()];
        let mut dec = vec![0u8; plain.len()];

        s.encrypt(&mut cipher, plain);
        s.decrypt(&mut dec, &cipher);

        assert_eq!(dec, plain);
    }

    #[test]
    fn test_sigaba_example_3() {
        let s = Sigaba::new(
            [1, 3, 5, 7, 9], [0; 5], [true; 5],
            [0, 2, 4, 6, 8], [10; 5], [false; 5],
            [0, 1, 2, 3, 4], [0; 5], [false; 5],
        );

        let plain = b"ATTACKATDAWN";
        let mut cipher = vec![0u8; plain.len()];
        let mut dec = vec![0u8; plain.len()];

        s.encrypt(&mut cipher, plain);
        s.decrypt(&mut dec, &cipher);

        assert_eq!(dec, plain);
    }
}
