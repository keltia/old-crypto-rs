//! Chaocipher implementation.
//!
//! The Chaocipher is a cipher method invented by John Francis Byrne in 1918 and described in his
//! 1953 autobiographical Silent Years. He believed Chaocipher was simple, yet unbreakable.
//!
//! The algorithm uses two alphabets (called the left and right alphabets, or cipher and plaintext
//! alphabets) which are permuted after each character is processed. The permutation involves
//! rotating both alphabets and performing specific shifts at fixed positions (zenith and nadir).
//!
//! # Example
//!
//! ```
//! use old_crypto_rs::{Block, chaocipher::Chaocipher};
//!
//! let pkey = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
//! let ckey = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";
//! let cipher = Chaocipher::new(pkey, ckey).unwrap();
//!
//! let plaintext = b"HELLO";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```
//!
use crate::Block;
use std::cell::RefCell;

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ZENITH: usize = 0;
const NADIR: usize = 13;

/// A Chaocipher instance with two permutation alphabets.
///
/// The `Chaocipher` struct maintains two 26-character alphabet keys (plaintext and cipher keys)
/// and an internal state that is updated after each character encryption/decryption.
/// The state is kept in a `RefCell` to allow interior mutability during const operations.
///
pub struct Chaocipher {
    /// The plaintext alphabet key (right alphabet)
    pkey: String,
    /// The cipher alphabet key (left alphabet)
    ckey: String,
    /// Internal mutable state containing the working alphabets
    state: RefCell<ChaocipherState>,
}

/// Internal state of the Chaocipher algorithm.
///
/// Contains the two working alphabets that are permuted after each character operation.
///
struct ChaocipherState {
    /// The plaintext working alphabet (right alphabet)
    pw: Vec<u8>,
    /// The cipher working alphabet (left alphabet)
    cw: Vec<u8>,
}

impl Chaocipher {
    /// Creates a new Chaocipher instance with the provided keys.
    ///
    /// Both keys must be exactly 26 characters long (matching the standard English alphabet).
    ///
    /// # Arguments
    ///
    /// * `pkey` - The plaintext alphabet key (right alphabet)
    /// * `ckey` - The cipher alphabet key (left alphabet)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Chaocipher)` if the keys are valid, or `Err(String)` if either key
    /// has an incorrect length.
    ///
    /// # Example
    ///
    /// ```
    /// use old_crypto_rs::chaocipher::Chaocipher;
    ///
    /// let cipher = Chaocipher::new(
    ///     "PTLNBQDEOYSFAVZKGJRIHWXUMC",
    ///     "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
    /// ).unwrap();
    /// ```
    ///
    pub fn new(pkey: &str, ckey: &str) -> Result<Self, String> {
        if pkey.len() != ALPHABET.len() || ckey.len() != ALPHABET.len() {
            return Err("bad alphabet length".to_string());
        }

        Ok(Chaocipher {
            pkey: pkey.to_string(),
            ckey: ckey.to_string(),
            state: RefCell::new(ChaocipherState {
                pw: pkey.as_bytes().to_vec(),
                cw: ckey.as_bytes().to_vec(),
            }),
        })
    }

    /// Performs a left circular shift on an alphabet by n positions.
    ///
    /// # Arguments
    ///
    /// * `a` - The alphabet slice to shift
    /// * `n` - The number of positions to shift (will be taken modulo the alphabet length)
    ///
    fn lshift_n(a: &mut [u8], n: usize) {
        if a.is_empty() { return; }
        let n = n % a.len();
        a.rotate_left(n);
    }

    /// Advances the internal state by permuting both alphabets.
    ///
    /// This is the core permutation step of the Chaocipher algorithm. After finding a character
    /// at position `idx`, both alphabets are rotated and specific positions (between zenith and
    /// nadir) are shifted to create the permutation.
    ///
    /// The cipher alphabet is shifted left by `idx` positions, then a character is extracted
    /// and rotated within a specific range. The plaintext alphabet is shifted by `idx + 1`
    /// positions with a similar extraction and rotation.
    ///
    /// # Arguments
    ///
    /// * `state` - The current cipher state to be modified
    /// * `idx` - The position of the character that was just processed
    ///
    fn advance(state: &mut ChaocipherState, idx: usize) {
        // First we shift the left alphabet (cw)
        Self::lshift_n(&mut state.cw, idx);
        let l = state.cw[ZENITH + 1];
        state.cw[ZENITH + 1..NADIR + 1].rotate_left(1);
        state.cw[NADIR] = l;

        // Then we shift the right alphabet (pw)
        Self::lshift_n(&mut state.pw, idx + 1);
        let l = state.pw[ZENITH + 2];
        state.pw[ZENITH + 2..NADIR + 1].rotate_left(1);
        state.pw[NADIR] = l;
    }

    /// Encodes or decodes a single character.
    ///
    /// This method handles both encryption and decryption by finding the character in one
    /// alphabet and returning the corresponding character from the other alphabet at the
    /// same position. The state is then advanced for the next character.
    ///
    /// # Arguments
    ///
    /// * `is_encrypt` - If true, encrypts; if false, decrypts
    /// * `ch` - The character to process
    ///
    /// # Returns
    ///
    /// The encrypted or decrypted character
    ///
    fn encode_both(&self, is_encrypt: bool, ch: u8) -> u8 {
        let mut state = self.state.borrow_mut();
        let idx = if is_encrypt {
            state.pw.iter().position(|&x| x == ch).unwrap_or(0)
        } else {
            state.cw.iter().position(|&x| x == ch).unwrap_or(0)
        };

        let pt = if is_encrypt {
            state.cw[idx]
        } else {
            state.pw[idx]
        };

        Self::advance(&mut state, idx);
        pt
    }

    /// Resets the cipher state to the initial key configuration.
    ///
    /// This method restores both working alphabets to their original key values,
    /// allowing the cipher to be reused for multiple messages.
    ///
    fn reset(&self) {
        let mut state = self.state.borrow_mut();
        state.pw = self.pkey.as_bytes().to_vec();
        state.cw = self.ckey.as_bytes().to_vec();
    }
}

impl Block for Chaocipher {
    /// Returns the block size of the cipher.
    ///
    /// Chaocipher operates on single characters, so the block size is always 1.
    ///
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts the source data into the destination buffer.
    ///
    /// The cipher state is reset before encryption begins, ensuring that each encryption
    /// operation starts from the initial key configuration.
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer for encrypted data (must be at least as long as `src`)
    /// * `src` - The source plaintext data to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes encrypted (equal to the length of `src`)
    ///
    /// # Example
    ///
    /// ```
    /// use old_crypto_rs::{Block, chaocipher::Chaocipher};
    ///
    /// let cipher = Chaocipher::new(
    ///     "PTLNBQDEOYSFAVZKGJRIHWXUMC",
    ///     "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
    /// ).unwrap();
    ///
    /// let plaintext = b"HELLO";
    /// let mut ciphertext = vec![0u8; plaintext.len()];
    /// cipher.encrypt(&mut ciphertext, plaintext);
    /// ```
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.encode_both(true, ch);
        }
        src.len()
    }

    /// Decrypts the source data into the destination buffer.
    ///
    /// The cipher state is reset before decryption begins, ensuring that each decryption
    /// operation starts from the initial key configuration.
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer for decrypted data (must be at least as long as `src`)
    /// * `src` - The source ciphertext data to decrypt
    ///
    /// # Returns
    ///
    /// The number of bytes decrypted (equal to the length of `src`)
    ///
    /// # Example
    ///
    /// ```
    /// use old_crypto_rs::{Block, chaocipher::Chaocipher};
    ///
    /// let cipher = Chaocipher::new(
    ///     "PTLNBQDEOYSFAVZKGJRIHWXUMC",
    ///     "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
    /// ).unwrap();
    ///
    /// let ciphertext = b"OAHQH";
    /// let mut plaintext = vec![0u8; ciphertext.len()];
    /// cipher.decrypt(&mut plaintext, ciphertext);
    /// ```
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.encode_both(false, ch);
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    const PLAIN_TXT: &str = "WELLDONEISBETTERTHANWELLSAID";
    const CIPHER_TXT: &str = "OAHQHCNYNXTSZJRRHJBYHQKSOUJY";
    const LPLAIN_TXT: &str = "IFYOUCANREADTHISYOUEITHERDOWNLOADEDMYOWNIMPLEMENTATIONOFCHAOCIPHERORYOUWROTEONEOFYOUROWNINEITHERCASELETMEKNOWANDACCEPTMYCONGRATULATIONSX";
    const LCIPHER_TXT: &str = "TLMAGOONSKJBJYBQVGDQCDUNWNMZPLOYCWPCWKWQRBOYADSLQBKYCDGXJOLONKTTLRUZZJQGJBQNRQHQRREUIYIDHZOMVWZMVYUFQOGSNNUVYTJGQPSQTBRWFHLTCLVVBPMYYQVC";
    const KEY_PLAIN: &str = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
    const KEY_CIPHER: &str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";

    #[test]
    fn test_new_cipher() {
        let c = Chaocipher::new(ALPHABET, ALPHABET).unwrap();
        assert_eq!(c.block_size(), 1);
    }

    #[test]
    fn test_new_cipher_bad_len() {
        assert!(Chaocipher::new("AB", "CD").is_err());
    }

    #[rstest]
    #[case(PLAIN_TXT, CIPHER_TXT)]
    #[case(LPLAIN_TXT, LCIPHER_TXT)]
    fn test_chaocipher_encrypt(#[case] pt: &str, #[case] ct: &str) {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let src = pt.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(dst, ct.as_bytes());
    }

    #[rstest]
    #[case(CIPHER_TXT, PLAIN_TXT)]
    #[case(LCIPHER_TXT, LPLAIN_TXT)]
    fn test_chaocipher_decrypt(#[case] ct: &str, #[case] pt: &str) {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let src = ct.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.decrypt(&mut dst, src);
        assert_eq!(dst, pt.as_bytes());
    }

    #[rstest]
    #[case('A', 12, "PFJRIGTWOBNYQEHXUCZVAMDSLK", "VZGJRIHWXUMCPKTLNBQDEOYSFA")]
    #[case('W', 21, "ONYQHXUCZVAMDBSLKPEFJRIGTW", "XUCPTLNBQDEOYMSFAVZKGJRIHW")]
    fn test_advance(#[case] c_find: char, #[case] expected_idx: usize, #[case] expected_cw: &str, #[case] expected_pw: &str) {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let idx = KEY_PLAIN.find(c_find).unwrap();
        assert_eq!(idx, expected_idx);

        {
            let mut state = c.state.borrow_mut();
            Chaocipher::advance(&mut state, idx);
        }
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().cw), expected_cw);
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().pw), expected_pw);
    }
}
