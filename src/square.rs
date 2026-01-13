//! Square Cipher implementation for classical cryptography.
//!
//! The Square Cipher (also known as Polybius Square) is a fractionating
//! substitution cipher that replaces each plaintext character with a pair of characters
//! (bigram) from a given character set.
//!
//! # Algorithm
//!
//! 1. A key is combined with a base alphabet (BASE36) and condensed to remove duplicates
//! 2. The condensed alphabet is arranged in a square grid
//! 3. Each character is encoded as coordinates (row, column) using the character set
//! 4. Decryption reverses the process by looking up bigrams in the grid
//!
//! # Example
//!
//! ```
//! use old_crypto_rs::{Block, SquareCipher};
//!
//! let cipher = SquareCipher::new("PORTABLE", "ADFGVX").unwrap();
//! let plaintext = b"ATTACK";
//! let mut ciphertext = vec![0u8; plaintext.len() * 2];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```
//! 
use crate::Block;
use crate::helpers;
use std::collections::HashMap;

/// Base alphabet used for creating the cipher square.
/// Contains all uppercase letters A-Z followed by digits 0-9.
pub const BASE36: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// A Square Cipher that implements fractionating substitution.
///
/// The cipher maintains both encryption and decryption mappings between
/// single characters and character pairs (bigrams). The key determines
/// the arrangement of characters in the square, while the character set
/// (chrs) determines the symbols used for encoding coordinates.
///
/// # Fields
///
/// * `key` - The keyword used to initialize the cipher square
/// * `chrs` - The character set used for bigram generation (e.g., "ADFGVX" or "012345")
/// * `alpha` - The condensed alphabet used to populate the cipher square
/// * `enc` - Encryption mapping from plaintext byte to bigram string
/// * `dec` - Decryption mapping from bigram string to plaintext byte
/// 
pub struct SquareCipher {
    key: String,
    chrs: String,
    alpha: Vec<u8>,
    enc: HashMap<u8, String>,
    dec: HashMap<String, u8>,
}

impl SquareCipher {
    /// Creates a new Square Cipher with the given key and character set.
    ///
    /// The key is combined with BASE36 alphabet and condensed to remove duplicate characters.
    /// The character set determines which symbols will be used for the bigram encoding.
    ///
    /// # Arguments
    ///
    /// * `key` - A non-empty keyword to initialize the cipher square
    /// * `chrs` - A non-empty character set for bigram generation (length should match square dimensions)
    ///
    /// # Returns
    ///
    /// * `Ok(SquareCipher)` - Successfully created cipher
    /// * `Err(String)` - Error message if key or chrs is empty
    ///
    /// # Example
    ///
    /// ```
    /// use old_crypto_rs::SquareCipher;
    ///
    /// // Create ADFGVX cipher with "PORTABLE" key
    /// let cipher = SquareCipher::new("PORTABLE", "ADFGVX").unwrap();
    ///
    /// // Create numeric variant with "ARABESQUE" key
    /// let cipher2 = SquareCipher::new("ARABESQUE", "012345").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if either `key` or `chrs` is an empty string.
    /// 
    pub fn new(key: &str, chrs: &str) -> Result<Self, String> {
        if key.is_empty() || chrs.is_empty() {
            return Err("neither key nor chrs can be empty".to_string());
        }

        let alpha = helpers::condense(&format!("{}{}", key, BASE36)).as_bytes().to_vec();

        let mut c = SquareCipher {
            key: key.to_string(),
            chrs: chrs.to_string(),
            alpha,
            enc: HashMap::new(),
            dec: HashMap::new(),
        };
        c.expand_key();
        Ok(c)
    }

    /// Expands the key into encryption and decryption lookup tables.
    ///
    /// This method generates all possible bigrams from the character set and maps them
    /// to/from the condensed alphabet. Each character in the alphabet is assigned
    /// coordinates (i, j) which are encoded as a bigram using characters from `chrs`.
    ///
    /// For example, with chrs="ADFGVX" and a 6x6 grid:
    /// - Position (0,0) → "AA"
    /// - Position (0,1) → "AD"
    /// - Position (1,0) → "DA"
    /// - etc.
    /// 
    fn expand_key(&mut self) {
        let mut bigr = vec![0u8; 2];
        let klen = self.chrs.len();
        let chrs_bytes = self.chrs.as_bytes();

        // Generate all bigrams by iterating through character set twice (i, j)
        for i in 0..klen {
            for j in 0..klen {
                // Create bigram: first char from row i, second char from column j
                bigr[0] = chrs_bytes[i];
                bigr[1] = chrs_bytes[j];

                // Calculate linear index in the square (row * width + column)
                let ind = i * klen + j;
                let bigr_str = String::from_utf8(bigr.clone()).unwrap();

                // Only map if we haven't exceeded the alphabet length
                if ind < self.alpha.len() {
                    // Forward mapping: alphabet character → bigram
                    self.enc.insert(self.alpha[ind], bigr_str.clone());
                    // Reverse mapping: bigram → alphabet character
                    self.dec.insert(bigr_str, self.alpha[ind]);
                }
            }
        }
    }
}

impl Block for SquareCipher {
    /// Returns the block size for this cipher.
    ///
    /// The block size is equal to the key length. This determines how many
    /// characters are processed together during encryption/decryption operations.
    ///
    /// # Returns
    ///
    /// The length of the cipher key in bytes.
    /// 
    fn block_size(&self) -> usize {
        self.key.len()
    }

    /// Encrypts plaintext into ciphertext using the Square Cipher.
    ///
    /// Each byte in the source is replaced by a two-character bigram, effectively
    /// doubling the length of the output. The bigram represents the row and column
    /// coordinates of the character in the cipher square.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for ciphertext (must be at least 2 * src.len())
    /// * `src` - Source plaintext bytes to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to dst (always 2 * src.len())
    ///
    /// # Note
    ///
    /// Characters not found in the encryption table are silently skipped.
    /// 
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        for (i, &ch) in src.iter().enumerate() {
            if let Some(ct) = self.enc.get(&ch) {
                let ct_bytes = ct.as_bytes();
                // Write the two-character bigram to destination
                dst[i * 2] = ct_bytes[0];
                dst[i * 2 + 1] = ct_bytes[1];
            }
        }
        src.len() * 2
    }

    /// Decrypts ciphertext back into plaintext using the Square Cipher.
    ///
    /// Processes the source in pairs of characters (bigrams), looking up each
    /// bigram in the decryption table to recover the original character.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for plaintext (must be at least src.len() / 2)
    /// * `src` - Source ciphertext bytes to decrypt (must have even length)
    ///
    /// # Returns
    ///
    /// The number of bytes written to dst (always src.len() / 2)
    ///
    /// # Note
    ///
    /// Bigrams not found in the decryption table are silently skipped.
    /// 
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // Process source in steps of 2 (each bigram)
        for i in (0..src.len()).step_by(2) {
            let pt_str = String::from_utf8(vec![src[i], src[i + 1]]).unwrap();
            if let Some(&pt) = self.dec.get(&pt_str) {
                // Write the recovered character to destination
                dst[i / 2] = pt;
            }
        }
        src.len() / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_key() {
        let test_data = [
            ("PORTABLE", "ADFGVX"),
            ("ARABESQUE", "012345"),
        ];

        for (key, chrs) in test_data {
            let _c = SquareCipher::new(key, chrs).unwrap();
            // In Rust we don't need to test multiple versions of expand_key
            // we just test that the maps are correct.
            // Since the maps are private and would be tedious to recreate here,
            // we can test the functional encryption/decryption which depends on them.
        }
    }

    #[test]
    fn test_new_cipher() {
        let c = SquareCipher::new("PORTABLE", "ADFGVX");
        assert!(c.is_ok());
    }

    #[test]
    fn test_new_cipher_empty_key() {
        let c = SquareCipher::new("", "012345");
        assert!(c.is_err());
    }

    #[test]
    fn test_new_cipher_empty_chrs() {
        let c = SquareCipher::new("SUBWAY", "");
        assert!(c.is_err());
    }

    #[test]
    fn test_square_cipher_block_size() {
        let test_data = [
            ("PORTABLE", "ADFGVX"),
            ("ARABESQUE", "012345"),
        ];
        for (key, chrs) in test_data {
            let c = SquareCipher::new(key, chrs).unwrap();
            assert_eq!(c.block_size(), key.len());
        }
    }

    #[test]
    fn test_square_cipher_encrypt() {
        let test_data = [
            ("PORTABLE", "ADFGVX", "ATTACKATDAWN", "AVAGAGAVDFFGAVAGDGAVGVFX"),
            ("ARABESQUE", "012345", "ATTACKATDAWN", "003232001122003212003425"),
        ];

        for (key, chrs, pt, ct) in test_data {
            let c = SquareCipher::new(key, chrs).unwrap();
            let src = pt.as_bytes();
            let mut dst = vec![0u8; 2 * pt.len()];
            c.encrypt(&mut dst, src);
            assert_eq!(String::from_utf8(dst).unwrap(), ct);
        }
    }

    #[test]
    fn test_square_cipher_decrypt() {
        let test_data = [
            ("PORTABLE", "ADFGVX", "ATTACKATDAWN", "AVAGAGAVDFFGAVAGDGAVGVFX"),
            ("ARABESQUE", "012345", "ATTACKATDAWN", "003232001122003212003425"),
        ];

        for (key, chrs, pt, ct) in test_data {
            let c = SquareCipher::new(key, chrs).unwrap();
            let src = ct.as_bytes();
            let mut dst = vec![0u8; src.len() / 2];
            c.decrypt(&mut dst, src);
            assert_eq!(String::from_utf8(dst).unwrap(), pt);
        }
    }
}
