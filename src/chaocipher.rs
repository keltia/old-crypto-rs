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
//! use old_crypto_rs::{Block, Chaocipher};
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
use std::cell::RefCell;
use std::marker::PhantomData;

use crate::Block;
use crate::helpers::{Alphabet, Latin26};

use eyre::Result;
use crate::error::Error;

const ZENITH: usize = 0;

/// A Chaocipher instance, generic over an [`Alphabet`].
///
/// The `Chao` struct maintains two alphabet keys (plaintext and cipher keys)
/// and an internal state that is updated after each character encryption/decryption.
/// The state is kept in a `RefCell` to allow interior mutability during const operations.
///
pub struct ChaoBasic<A: Alphabet> {
    /// The plaintext alphabet key (right alphabet)
    pkey: Vec<u8>,
    /// The cipher alphabet key (left alphabet)
    ckey: Vec<u8>,
    /// Internal mutable state containing the working alphabets
    state: RefCell<ChaocipherState>,
    _phantom: PhantomData<A>,
}

/// Chaocipher over the standard 26-letter Latin alphabet (A-Z).
pub type Chaocipher = ChaoBasic<Latin26>;

/// Internal state of the Chaocipher algorithm.
///
/// Contains the two working alphabets that are permuted after each character operation,
/// plus lookup tables for O(1) character position finding.
///
struct ChaocipherState {
    /// The plaintext working alphabet (right alphabet)
    pw: Vec<u8>,
    /// The cipher working alphabet (left alphabet)
    cw: Vec<u8>,
    /// Lookup table: maps character byte to its position in pw
    pw_lookup: [u8; 256],
    /// Lookup table: maps character byte to its position in cw
    cw_lookup: [u8; 256],
}

impl ChaocipherState {
    /// Creates a new state from the given alphabet keys.
    fn new(pkey: &[u8], ckey: &[u8]) -> Self {
        let mut state = ChaocipherState {
            pw: pkey.to_vec(),
            cw: ckey.to_vec(),
            pw_lookup: [0; 256],
            cw_lookup: [0; 256],
        };
        state.rebuild_lookups();
        state
    }

    /// Rebuilds the lookup tables after alphabet permutation.
    ///
    /// This method creates reverse mappings from character bytes to their positions
    /// in the working alphabets, enabling O(1) character lookups.
    #[inline]
    fn rebuild_lookups(&mut self) {
        for i in 0..self.pw.len() {
            self.pw_lookup[self.pw[i] as usize] = i as u8;
            self.cw_lookup[self.cw[i] as usize] = i as u8;
        }
    }
}

impl<A: Alphabet> ChaoBasic<A> {
    /// Creates a new Chaocipher instance with the provided keys.
    ///
    /// Both keys must be exactly `A::SIZE` characters long.
    ///
    /// # Arguments
    ///
    /// * `pkey` - The plaintext alphabet key (right alphabet)
    /// * `ckey` - The cipher alphabet key (left alphabet)
    ///
    /// # Returns
    ///
    /// Returns `Ok(Chao)` if the keys are valid, or `Err` if either key
    /// has an incorrect length.
    ///
    /// # Example
    ///
    /// ```
    /// use old_crypto_rs::Chaocipher;
    ///
    /// let cipher = Chaocipher::new(
    ///     "PTLNBQDEOYSFAVZKGJRIHWXUMC",
    ///     "HXUCZVAMDSLKPEFJRIGTWOBNYQ"
    /// ).unwrap();
    /// ```
    ///
    pub fn new(pkey: &str, ckey: &str) -> Result<Self> {
        if pkey.len() != A::SIZE || ckey.len() != A::SIZE {
            return Err(Error::AlphabetTooShort(A::SIZE).into());
        }

        let pkey_bytes = pkey.as_bytes().to_vec();
        let ckey_bytes = ckey.as_bytes().to_vec();

        Ok(ChaoBasic {
            pkey: pkey_bytes.clone(),
            ckey: ckey_bytes.clone(),
            state: RefCell::new(ChaocipherState::new(&pkey_bytes, &ckey_bytes)),
            _phantom: PhantomData,
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
    /// The nadir is always at the midpoint of the alphabet (`len / 2`).
    ///
    /// # Arguments
    ///
    /// * `state` - The current cipher state to be modified
    /// * `idx` - The position of the character that was just processed
    ///
    fn advance(state: &mut ChaocipherState, idx: usize) {
        let nadir = state.cw.len() / 2;

        // First we shift the left alphabet (cw)
        Self::lshift_n(&mut state.cw, idx);
        let l = state.cw[ZENITH + 1];
        state.cw[ZENITH + 1..nadir + 1].rotate_left(1);
        state.cw[nadir] = l;

        // Then we shift the right alphabet (pw)
        Self::lshift_n(&mut state.pw, idx + 1);
        let l = state.pw[ZENITH + 2];
        state.pw[ZENITH + 2..nadir + 1].rotate_left(1);
        state.pw[nadir] = l;

        // Rebuild lookup tables after permutation
        state.rebuild_lookups();
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
            state.pw_lookup[ch as usize] as usize
        } else {
            state.cw_lookup[ch as usize] as usize
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
        state.pw = self.pkey.clone();
        state.cw = self.ckey.clone();
        state.rebuild_lookups();
    }
}

impl<A: Alphabet> Block for ChaoBasic<A> {
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
    /// use old_crypto_rs::{Block, Chaocipher};
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
    /// use old_crypto_rs::{Block, Chaocipher};
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
    use crate::helpers::REGULAR_ALPHABET;

    use rstest::rstest;

    const PLAIN_TXT: &str = "WELLDONEISBETTERTHANWELLSAID";
    const CIPHER_TXT: &str = "OAHQHCNYNXTSZJRRHJBYHQKSOUJY";
    const LPLAIN_TXT: &str = "IFYOUCANREADTHISYOUEITHERDOWNLOADEDMYOWNIMPLEMENTATIONOFCHAOCIPHERORYOUWROTEONEOFYOUROWNINEITHERCASELETMEKNOWANDACCEPTMYCONGRATULATIONSX";
    const LCIPHER_TXT: &str = "TLMAGOONSKJBJYBQVGDQCDUNWNMZPLOYCWPCWKWQRBOYADSLQBKYCDGXJOLONKTTLRUZZJQGJBQNRQHQRREUIYIDHZOMVWZMVYUFQOGSNNUVYTJGQPSQTBRWFHLTCLVVBPMYYQVC";
    const KEY_PLAIN: &str = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
    const KEY_CIPHER: &str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";

    #[test]
    fn test_new_cipher() {
        let c = Chaocipher::new(REGULAR_ALPHABET, REGULAR_ALPHABET).unwrap();
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
            ChaoBasic::<Latin26>::advance(&mut state, idx);
        }
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().cw), expected_cw);
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().pw), expected_pw);
    }
}
