//! Implementation of the Wheatstone cipher machine.
//!
//! The Wheatstone cipher (also known as the Playfair Double) is a mechanical cipher
//! device invented by Charles Wheatstone in the 1860s. It uses two rotating alphabetic
//! wheels - one for plaintext (with 27 positions including a special character) and
//! one for ciphertext (with 26 positions) - along with a pointer mechanism to
//! encrypt and decrypt messages.
//!
//! # Example
//!
//! ```no_run
//! use old_crypto_rs::{Block, wheatstone::Wheatstone};
//!
//! let cipher = Wheatstone::new(b'M', "CIPHER", "MACHINE").unwrap();
//! let plaintext = b"HELLO";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```

use crate::Block;
use crate::helpers;
use std::cell::RefCell;

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LEN_PL: usize = ALPHABET.len() + 1;
const LEN_CT: usize = ALPHABET.len();

/// Wheatstone cipher machine implementation.
///
/// This struct represents a Wheatstone cipher with two keyed alphabets:
/// - A plaintext wheel (27 characters, including '+' as a separator)
/// - A ciphertext wheel (26 characters, standard alphabet)
///
/// The cipher maintains internal state to track the current positions
/// of both wheels during encryption and decryption operations.
pub struct Wheatstone {
    /// Original plaintext key (stored for reference)
    #[allow(dead_code)]
    pkey: String,
    /// Original ciphertext key (stored for reference)
    #[allow(dead_code)]
    ckey: String,
    /// Plaintext wheel alphabet (27 characters)
    aplw: Vec<u8>,
    /// Ciphertext wheel alphabet (26 characters)
    actw: Vec<u8>,
    /// Starting character position on the ciphertext wheel
    start: u8,
    /// Internal mutable state for wheel positions
    state: RefCell<WheatstoneState>,
}

/// Internal state for tracking wheel positions during encryption/decryption.
///
/// The Wheatstone cipher needs to maintain state between character operations
/// as each encryption/decryption affects the position of the wheels for the
/// next character.
struct WheatstoneState {
    /// Current position on the plaintext wheel (0-26)
    curpos: usize,
    /// Current position on the ciphertext wheel (0-25)
    ctpos: usize,
}

impl Wheatstone {
    /// Creates a new Wheatstone cipher with the provided configuration.
    ///
    /// # Arguments
    ///
    /// * `start` - The starting character on the ciphertext wheel (typically 'A'-'Z')
    /// * `pkey` - The plaintext key used to shuffle the plaintext alphabet
    /// * `ckey` - The ciphertext key used to shuffle the ciphertext alphabet
    ///
    /// # Returns
    ///
    /// Returns `Ok(Wheatstone)` if the cipher is successfully created, or
    /// `Err(String)` if either key is empty.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use old_crypto_rs::wheatstone::Wheatstone;
    ///
    /// let cipher = Wheatstone::new(b'M', "CIPHER", "MACHINE").unwrap();
    /// ```
    /// 
    pub fn new(start: u8, pkey: &str, ckey: &str) -> Result<Self, String> {
        if pkey.is_empty() || ckey.is_empty() {
            return Err("keys can not be empty".to_string());
        }

        // Transform with key
        let pkey_shuffled = format!("+{}", helpers::shuffle(pkey, ALPHABET));
        let ckey_shuffled = helpers::shuffle(ckey, ALPHABET);

        let aplw = pkey_shuffled.as_bytes().to_vec();
        let actw = ckey_shuffled.as_bytes().to_vec();

        let ctpos = actw.iter().position(|&x| x == start).unwrap_or(0);

        Ok(Wheatstone {
            pkey: pkey_shuffled,
            ckey: ckey_shuffled,
            aplw,
            actw,
            start,
            state: RefCell::new(WheatstoneState {
                curpos: 0,
                ctpos,
            }),
        })
    }

    /// Encodes a single character using the Wheatstone cipher mechanism.
    ///
    /// This method finds the character on the plaintext wheel, calculates
    /// the offset from the current position, advances both wheels by this
    /// offset, and returns the character at the new ciphertext wheel position.
    ///
    /// # Arguments
    ///
    /// * `ch` - The plaintext character to encode (as a byte)
    ///
    /// # Returns
    ///
    /// The encoded ciphertext character (as a byte)
    /// 
    fn encode(&self, ch: u8) -> u8 {
        let mut state = self.state.borrow_mut();
        let a = self.aplw.iter().position(|&x| x == ch).unwrap_or(0);
        let off = if a <= state.curpos {
            (a + LEN_PL) - state.curpos
        } else {
            a - state.curpos
        };
        state.curpos = a;
        state.ctpos = (state.ctpos + off) % LEN_CT;
        self.actw[state.ctpos]
    }

    /// Decodes a single character using the Wheatstone cipher mechanism.
    ///
    /// This method finds the character on the ciphertext wheel, calculates
    /// the offset from the current position, advances both wheels by this
    /// offset, and returns the character at the new plaintext wheel position.
    ///
    /// # Arguments
    ///
    /// * `ch` - The ciphertext character to decode (as a byte)
    ///
    /// # Returns
    ///
    /// The decoded plaintext character (as a byte)
    /// 
    fn decode(&self, ch: u8) -> u8 {
        let mut state = self.state.borrow_mut();
        let a = self.actw.iter().position(|&x| x == ch).unwrap_or(0);
        let off = if a <= state.ctpos {
            (a + LEN_CT) - state.ctpos
        } else {
            a - state.ctpos
        };
        state.ctpos = a;
        state.curpos = (state.curpos + off) % LEN_PL;
        self.aplw[state.curpos]
    }

    /// Resets the cipher state to the initial configuration.
    ///
    /// This method resets both wheel positions to their starting values:
    /// - Plaintext wheel position to 0
    /// - Ciphertext wheel position to the location of the start character
    ///
    /// This is called automatically before each encrypt/decrypt operation
    /// to ensure consistent results.
    /// 
    fn reset(&self) {
        let mut state = self.state.borrow_mut();
        state.curpos = 0;
        state.ctpos = self.actw.iter().position(|&x| x == self.start).unwrap_or(0);
    }
}

impl Block for Wheatstone {
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts plaintext using the Wheatstone cipher.
    ///
    /// This method encrypts the entire source buffer character by character,
    /// writing the ciphertext to the destination buffer. The cipher state is
    /// automatically reset before encryption to ensure consistent results.
    ///
    /// # Arguments
    ///
    /// * `dst` - Mutable slice where the ciphertext will be written (must be at least as long as `src`)
    /// * `src` - Slice containing the plaintext to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes encrypted (equal to `src.len()`)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use old_crypto_rs::{Block, wheatstone::Wheatstone};
    ///
    /// let cipher = Wheatstone::new(b'M', "CIPHER", "MACHINE").unwrap();
    /// let plaintext = b"HELLO";
    /// let mut ciphertext = vec![0u8; plaintext.len()];
    /// let len = cipher.encrypt(&mut ciphertext, plaintext);
    /// assert_eq!(len, plaintext.len());
    /// ```
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.encode(ch);
        }
        src.len()
    }

    /// Decrypts ciphertext using the Wheatstone cipher.
    ///
    /// This method decrypts the entire source buffer character by character,
    /// writing the plaintext to the destination buffer. The cipher state is
    /// automatically reset before decryption to ensure consistent results.
    ///
    /// # Arguments
    ///
    /// * `dst` - Mutable slice where the plaintext will be written (must be at least as long as `src`)
    /// * `src` - Slice containing the ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// The number of bytes decrypted (equal to `src.len()`)
    ///
    /// # Example
    ///
    /// ```no_run
    /// use old_crypto_rs::{Block, wheatstone::Wheatstone};
    ///
    /// let cipher = Wheatstone::new(b'M', "CIPHER", "MACHINE").unwrap();
    /// let ciphertext = b"BYVLQ";
    /// let mut plaintext = vec![0u8; ciphertext.len()];
    /// let len = cipher.decrypt(&mut plaintext, ciphertext);
    /// assert_eq!(len, ciphertext.len());
    /// ```
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.decode(ch);
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_TXT: &str = "CHARLES+WHEATSTONE+HAD+A+REMARKABLY+FERTILE+MIND";
    const CIPHER_TXT: &str = "BYVLQKWAMNLCYXIOUBFLHTXGHFPBJHZZLUEZFHIVBVRTFVRQ";
    const KEY1: &str = "CIPHER";
    const KEY2: &str = "MACHINE";
    const LPLAIN_TXT: &str = "IFYOUCANREADTHISYOUEITHERDOWNLOADEDMYOWNIMPLEMENTATIONOFCHAOCIPHERORYOUWROTEONEOFYOUROWNINEITHERCASELETMEKNOWANDACCEPTMYCONGRATULATIONSX";
    const LCIPHER_TXT: &str = "PIPTIADNMEWJYKGHGVEOIZUVWEPWVKCIMWBOKXHCLDAOGCRGPMWDNJKJVJDLDQYZEBMOXBKVAVSOABVDBJWBQFQPTWFEMPQRZNTXBHVWGLHIJLGFMMLBZHXYCDUTUOCYNYQJYABYX";

    #[test]
    fn test_new_cipher() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        assert_eq!(c.aplw.len(), 27);
        assert_eq!(c.actw.len(), 26);
    }

    #[test]
    fn test_encode() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        assert_eq!(c.state.borrow().curpos, 0);
        assert_eq!(c.state.borrow().ctpos, 0);

        // Round 1
        assert_eq!(c.encode(b'C'), b'B');
        assert_eq!(c.state.borrow().curpos, 1);
        assert_eq!(c.state.borrow().ctpos, 1);

        // Round 2
        assert_eq!(c.encode(b'H'), b'Y');
        assert_eq!(c.state.borrow().curpos, 15);
        assert_eq!(c.state.borrow().ctpos, 15);

        // Round 3
        assert_eq!(c.encode(b'A'), b'V');
        assert_eq!(c.state.borrow().curpos, 2);
        assert_eq!(c.state.borrow().ctpos, 3);

        // Round 4
        assert_eq!(c.encode(b'R'), b'L');
        assert_eq!(c.state.borrow().curpos, 23);
        assert_eq!(c.state.borrow().ctpos, 24);
    }

    #[test]
    fn test_decode() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        assert_eq!(c.state.borrow().curpos, 0);
        assert_eq!(c.state.borrow().ctpos, 0);

        assert_eq!(c.decode(b'B'), b'C');
        assert_eq!(c.state.borrow().curpos, 1);
        assert_eq!(c.state.borrow().ctpos, 1);

        assert_eq!(c.decode(b'Y'), b'H');
        assert_eq!(c.state.borrow().curpos, 15);
        assert_eq!(c.state.borrow().ctpos, 15);

        assert_eq!(c.decode(b'V'), b'A');
        assert_eq!(c.state.borrow().curpos, 2);
        assert_eq!(c.state.borrow().ctpos, 3);

        assert_eq!(c.decode(b'L'), b'R');
        assert_eq!(c.state.borrow().curpos, 23);
        assert_eq!(c.state.borrow().ctpos, 24);
    }

    #[test]
    fn test_wheatstone_encrypt() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let src = PLAIN_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(dst, CIPHER_TXT.as_bytes());
    }

    #[test]
    fn test_wheatstone_encrypt_start_a() {
        let c = Wheatstone::new(b'A', KEY1, KEY2).unwrap();
        let src = PLAIN_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(String::from_utf8_lossy(&dst), "DZWORUXCALOHZYNPVDGOIMYJIGQDKIEEOVBEGINWDWSMGWSR");
    }

    #[test]
    fn test_wheatstone_encrypt_long() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let plain = helpers::fix_double(LPLAIN_TXT, 'Q');
        let src = plain.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(dst, LCIPHER_TXT.as_bytes());
    }

    #[test]
    fn test_wheatstone_decrypt() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let src = CIPHER_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.decrypt(&mut dst, src);
        assert_eq!(dst, PLAIN_TXT.as_bytes());
    }

    #[test]
    fn test_wheatstone_decrypt_long() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let plain = helpers::fix_double(LPLAIN_TXT, 'Q');
        let src = LCIPHER_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.decrypt(&mut dst, src);
        assert_eq!(dst, plain.as_bytes());
    }
}
