//! ADFGVX cipher implementation.
//!
//! The ADFGVX cipher is a field cipher used by the German Army during World War I.
//! It combines a modified Polybius square with a columnar transposition to provide
//! encryption. The cipher is named after the six letters (A, D, F, G, V, X) used to
//! represent the rows and columns of a 6×6 Polybius square, which allows for 36
//! characters (26 letters + 10 digits).
//!
//! The encryption process consists of two stages:
//! 1. Substitution using a 6×6 Polybius square (keyed with `key1`)
//! 2. Transposition using columnar transposition (keyed with `key2`)
//!
//! # Examples
//!
//! ```
//! # use old_crypto_rs::ADFGVXCipher;
//! # use old_crypto_rs::Block;
//!
//! let cipher = ADFGVXCipher::new("PORTABLE", "SUBWAY").unwrap();
//! let plaintext = b"ATTACKATDAWN";
//! let mut ciphertext = vec![0u8; 24];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```
//!
use crate::Block;
use crate::square::{SquareCipher, ADFGVX, ADFGX};
use crate::transposition::Transposition;

use std::cell::RefCell;

use eyre::Result;
use crate::helpers::{Latin25, Latin36};

pub type ADFGXSquare = SquareCipher<ADFGX, Latin25>;
pub type ADFGVXSquare = SquareCipher<ADFGVX, Latin36>;

/// ADFGVX cipher combining Polybius square substitution with columnar transposition.
///
/// This structure holds the two components of the ADFGVX cipher:
/// - A Polybius square cipher using the letters A, D, F, G, V, X
/// - A columnar transposition cipher for the second encryption stage
///
#[derive(Debug)]
pub struct ADFGVXCipher {
    sqr: ADFGVXSquare,
    transp: Transposition,
    buf: RefCell<Vec<u8>>,
}

impl ADFGVXCipher {
    /// Creates a new ADFGVX cipher with the given keys.
    ///
    /// # Arguments
    ///
    /// * `key1` - The keyword for the Polybius square substitution (should contain unique letters)
    /// * `key2` - The keyword for the columnar transposition (defines column order)
    ///
    /// # Returns
    ///
    /// Returns `Ok(ADFGVX)` if both keys are valid, or `Err(String)` with an error message
    /// if either key is invalid (e.g., empty or contains invalid characters).
    ///
    /// # Examples
    ///
    /// ```
    /// # use old_crypto_rs::ADFGVXCipher;
    /// let cipher = ADFGVXCipher::new("PORTABLE", "SUBWAY").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Either key is empty
    /// - The keys contain invalid characters
    /// - The Polybius square or transposition cipher cannot be initialized
    ///
    pub fn new(key1: &str, key2: &str) -> Result<Self> {
        let sqr = ADFGVXSquare::new(key1)?;
        let transp = Transposition::new(key2)?;

        Ok(ADFGVXCipher {
            sqr,
            transp,
            buf: RefCell::new(Vec::new()),
        })
    }
}

impl Block for ADFGVXCipher {
    /// Returns the block size for the cipher.
    ///
    /// The block size is determined by the transposition cipher's block size,
    /// which is twice the length of the transposition key (since each character
    /// is first encoded into two ADFGVX characters).
    ///
    /// # Returns
    ///
    /// The block size in bytes.
    ///
    fn block_size(&self) -> usize {
        self.transp.block_size()
    }

    /// Encrypts plaintext using the ADFGVX cipher.
    ///
    /// The encryption is performed in two stages:
    /// 1. Each plaintext character is substituted using the Polybius square,
    ///    producing two ADFGVX characters (row and column coordinates)
    /// 2. The resulting bigrammatic text is transposed using columnar transposition
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for the ciphertext (must be large enough)
    /// * `src` - Source plaintext bytes to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`.
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = self.buf.borrow_mut();
        let needed = 2 * src.len();
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        let n = self.sqr.encrypt(&mut buf[..needed], src);
        self.transp.encrypt(dst, &buf[..n])
    }

    /// Decrypts ciphertext using the ADFGVX cipher.
    ///
    /// The decryption is performed by reversing the two encryption stages:
    /// 1. The columnar transposition is reversed to recover the bigrammatic text
    /// 2. Each pair of ADFGVX characters is converted back to the original character
    ///    using the Polybius square
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for the plaintext (must be large enough)
    /// * `src` - Source ciphertext bytes to decrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`.
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = self.buf.borrow_mut();
        let needed = src.len();
        if buf.len() < needed {
            buf.resize(needed, 0);
        }
        let n = self.transp.decrypt(&mut buf[..needed], src);
        self.sqr.decrypt(dst, &buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[test]
    fn test_new_cipher() {
        let _c = ADFGVXCipher::new("PORTABLE", "SUBWAY").unwrap();
    }

    #[test]
    fn test_new_cipher_bad_keys() {
        assert!(ADFGVXCipher::new("PORTABLE", "").is_err());
        assert!(ADFGVXCipher::new("", "SUBWAY").is_err());
    }

    #[test]
    fn test_adfgvx_block_size() {
        let c = ADFGVXCipher::new("PORTABLE", "SUBWAY").unwrap();
        assert_eq!(c.block_size(), 6);
    }

    #[rstest]
    #[case("PORTABLE", "SUBWAY", "ATTACKATDAWN", "AVFVADAXAAAAVVVVGXGGGDDG")]
    #[case("NACHTBOMMENWERPER", "PRIVACY", "ATTACKAT1200AM", "DGDDDAGDDGAFADDFDADVDVFAADVX")]
    fn test_adfgvx_encrypt(#[case] key1: &str, #[case] key2: &str, #[case] pt: &str, #[case] ct: &str) {
        let c = ADFGVXCipher::new(key1, key2).unwrap();
        let mut dst = vec![0u8; ct.len()];
        c.encrypt(&mut dst, pt.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst), ct);
    }

    #[rstest]
    #[case("PORTABLE", "SUBWAY", "ATTACKATDAWN", "AVFVADAXAAAAVVVVGXGGGDDG")]
    #[case("NACHTBOMMENWERPER", "PRIVACY", "ATTACKAT1200AM", "DGDDDAGDDGAFADDFDADVDVFAADVX")]
    fn test_adfgvx_decrypt(#[case] key1: &str, #[case] key2: &str, #[case] pt: &str, #[case] ct: &str) {
        let c = ADFGVXCipher::new(key1, key2).unwrap();
        let mut dst = vec![0u8; pt.len()];
        c.decrypt(&mut dst, ct.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst), pt);
    }
}
