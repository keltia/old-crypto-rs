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
//! use old_crypto_rs::helpers::{Latin36, ADFGVX};
//!
//! let cipher = SquareCipher::<ADFGVX, Latin36>::new("PORTABLE").unwrap();
//! let plaintext = b"ATTACK";
//! let mut ciphertext = vec![0u8; plaintext.len() * 2];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```
//!

use std::fmt::Debug;
use std::marker::PhantomData;

use eyre::Result;

use crate::Block;
use crate::error::Error;
use crate::helpers;
use crate::helpers::{Alphabet, Coordinates, Latin25, Latin36, Numeric5};


// -----

// -----

/// Compact encoding entry for a single plaintext byte.
///
/// `len` is 0 for unmapped bytes, or 2 for the bigram length.
/// `bytes` stores the bigram bytes for the code.
#[derive(Copy, Clone, Debug, Default)]
struct EncEntry {
    len: u8,
    bytes: [u8; 2],
}

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
/// * `enc_table` - Fast encryption table from plaintext byte to bigram bytes
/// * `dec_table` - Fast decryption table from bigram bytes to plaintext byte
/// 
#[derive(Debug)]
pub struct SquareCipher<C: Coordinates, A: Alphabet> {
    key: String,
    alpha: Vec<u8>,
    enc_table: [EncEntry; 256],
    dec_table: Box<[u8; 256 * 256]>,
    _marker: PhantomData<(C, A)>,
}

/// The most used square cipher is the Polybius one.
/// 5x5, and thus using the restricted 25-letter alphabet
///
pub type PolybiusCipher = SquareCipher<Numeric5, Latin25>;

impl<C: Coordinates, A: Alphabet> SquareCipher<C, A> {
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
    /// use old_crypto_rs::{ADFGVXSquare, SquareCipher};
    /// use old_crypto_rs::helpers::{Latin36, ADFGVX, Numeric6};
    ///
    /// // Create ADFGVX cipher with "PORTABLE" key
    /// let cipher = ADFGVXSquare::new("PORTABLE").unwrap();
    ///
    /// // Create numeric variant with "ARABESQUE" key
    /// let cipher2 = SquareCipher::<Numeric6,Latin36>::new("ARABESQUE").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if either `key` or `chrs` is an empty string.
    /// 
    pub fn new(key: &str) -> Result<Self> {
        if key.is_empty() {
            return Err(Error::EmptyKeys.into());
        }
        // Check that we have compatible variants.
        //
        let n = C::SYMBOLS.len();
        if A::SIZE != n * n {
            return Err(Error::IncompatibleVariants.into());
        }

        // Step 1: Condense key + alphabet (letters only)
        //
        let alpha = String::from_utf8(A::ALPHABET.to_vec())?;
        let condensed_letters = helpers::condense(&format!("{}{}", key, alpha));

        let mut alpha = Vec::new();
        if A::SIZE == Latin36::SIZE {
            // Now, only for Latin36 alphabet:
            //
            // Step 2: Insert digits after corresponding letters
            // 1 after A, 2 after B, 3 after C, 4 after D, 5 after E,
            // 6 after F, 7 after G, 8 after H, 9 after I, 0 after J
            //
            // This follows <https://en.wikipedia.org/wiki/ADFGVX_cipher method>. That way, numbers
            // positions are less predictable
            //
            for ch in condensed_letters.chars() {
                alpha.push(ch as u8);
                match ch {
                    'A' => alpha.push(b'1'),
                    'B' => alpha.push(b'2'),
                    'C' => alpha.push(b'3'),
                    'D' => alpha.push(b'4'),
                    'E' => alpha.push(b'5'),
                    'F' => alpha.push(b'6'),
                    'G' => alpha.push(b'7'),
                    'H' => alpha.push(b'8'),
                    'I' => alpha.push(b'9'),
                    'J' => alpha.push(b'0'),
                    _ => {}
                }
            }
        } else {
            alpha = condensed_letters.into_bytes();
        }
        let alpha = helpers::condense_str(&String::from_utf8(alpha)?);
        let mut c = SquareCipher {
            key: key.to_string(),
            alpha: alpha.into_bytes(),
            enc_table: [EncEntry::default(); 256],
            dec_table: Box::new([0; 256 * 256]),
            _marker: PhantomData,
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
        let klen = C::SYMBOLS.len();
        let chrs_bytes = C::SYMBOLS;

        // Generate all bigrams by iterating through character set twice (i, j)
        for i in 0..klen {
            for j in 0..klen {
                // Create bigram: first char from row i, second char from column j
                bigr[0] = chrs_bytes[i];
                bigr[1] = chrs_bytes[j];

                // Calculate linear index in the square (row * width + column)
                let ind = i * klen + j;

                // Only map if we haven't exceeded the alphabet length
                if ind < self.alpha.len() {
                    // Forward mapping: alphabet character → bigram
                    let pt = self.alpha[ind];
                    let entry = EncEntry {
                        len: 2,
                        bytes: [bigr[0], bigr[1]],
                    };
                    self.enc_table[pt as usize] = entry;
                    // Reverse mapping: bigram → alphabet character
                    let idx = ((bigr[0] as usize) << 8) | (bigr[1] as usize);
                    self.dec_table[idx] = pt;
                }
            }
        }
    }
}

impl<C: Coordinates, A: Alphabet> Block for SquareCipher<C, A> {
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
            let entry = self.enc_table[ch as usize];
            if entry.len == 2 {
                // Write the two-character bigram to destination
                dst[i * 2] = entry.bytes[0];
                dst[i * 2 + 1] = entry.bytes[1];
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
            let idx = ((src[i] as usize) << 8) | (src[i + 1] as usize);
            let pt = self.dec_table[idx];
            if pt != 0 {
                // Write the recovered character to destination
                dst[i / 2] = pt;
            }
        }
        src.len() / 2
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::{Latin36, Numeric6, ADFGVX};
    use super::*;

    #[test]
    fn test_expand_key_25() {
        let c2 = PolybiusCipher::new("ARABESQUE").unwrap();
        let alpha = c2.alpha.iter().map(|&x| x as char).collect::<String>();
        dbg!(alpha);
    }

    #[test]
    fn test_expand_key_36() {
        let c1 = SquareCipher::<ADFGVX, Latin36>::new("PORTABLE").unwrap();
        let alpha = c1.alpha.iter().map(|&x| x as char).collect::<String>();
        dbg!(alpha);
    }

    #[test]
    fn test_new_cipher() {
        let c = SquareCipher::<ADFGVX, Latin36>::new("PORTABLE");
        assert!(c.is_ok());
        let alpha = c.unwrap().alpha.iter().map(|&x| x as char).collect::<String>();
        dbg!(alpha);
    }

    #[test]
    fn test_new_cipher_empty_key() {
        let c = SquareCipher::<Numeric5, Latin25>::new("");
        assert!(c.is_err());
    }

    #[test]
    fn test_square_cipher_block_size() {
        let c1 = SquareCipher::<ADFGVX, Latin36>::new("PORTABLE").unwrap();
        assert_eq!(c1.block_size(), "PORTABLE".len());
        let c2 = SquareCipher::<Numeric5, Latin25>::new("ARABESQUE").unwrap();
        assert_eq!(c2.block_size(), "ARABESQUE".len());
    }

    #[test]
    fn test_square_cipher_encrypt() {
        let c = SquareCipher::<ADFGVX, Latin36>::new("PORTABLE").unwrap();
        let src = b"ATTACKATDAWN";
        let mut dst = vec![0u8; src.len() * 2];
        c.encrypt(&mut dst, src);
        assert_eq!(String::from_utf8(dst).unwrap(), "AVAGAGAVDXVDAVAGFDAVXGVG");

        let c2 = SquareCipher::<Numeric6, Latin36>::new("ARABESQUE").unwrap();
        let src2 = b"ATTACKATDAWN";
        dbg!(c2.alpha.iter().map(|&x| x as char).collect::<String>());
        let mut dst2 = vec![0u8; src2.len() * 2];
        c2.encrypt(&mut dst2, src2);
        assert_eq!(String::from_utf8(dst2).unwrap(), "005050001440005020005343");

        let c3 = SquareCipher::<ADFGVX, Latin36>::new("NACHTBOMMENWERPER").unwrap();
        let src3 = b"ATTACKAT1200AM";
        let mut dst3 = vec![0u8; src3.len() * 2];
        c3.encrypt(&mut dst3, src3);
        assert_eq!(String::from_utf8(dst3).unwrap(), "ADDDDDADAGVGADDDAFDGVFVFADDX");
    }

    #[test]
    fn test_square_cipher_decrypt() {
        let c = SquareCipher::<ADFGVX, Latin36>::new("PORTABLE").unwrap();
        let src = b"AVAGAGAVDXVDAVAGFDAVXGVG";
        let mut dst = vec![0u8; src.len() / 2];
        c.decrypt(&mut dst, src);
        assert_eq!(String::from_utf8(dst).unwrap(), "ATTACKATDAWN");

        let c2 = SquareCipher::<Numeric6, Latin36>::new("ARABESQUE").unwrap();
        let src2 = b"005050001440005020005343";
        let mut dst2 = vec![0u8; src2.len() / 2];
        c2.decrypt(&mut dst2, src2);
        assert_eq!(String::from_utf8(dst2).unwrap(), "ATTACKATDAWN");

        let c3 = SquareCipher::<ADFGVX, Latin36>::new("NACHTBOMMENWERPER").unwrap();
        let src3 = b"ADDDDDADAGVGADDDAFDGVFVFADDX";
        let mut dst3 = vec![0u8; src3.len() / 2];
        c3.decrypt(&mut dst3, src3);
        assert_eq!(String::from_utf8(dst3).unwrap(), "ATTACKAT1200AM");
    }
}
