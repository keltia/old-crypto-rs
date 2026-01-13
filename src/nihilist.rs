//! Nihilist cipher implementation.
//!
//! The Nihilist cipher is a classical encryption method that combines a straddling checkerboard
//! with columnar transposition for super-encipherment. It was historically used by Russian
//! Nihilist revolutionaries in the 1880s.
//!
//! # Examples
//!
//! ```
//! use old_crypto_rs::Block;
//! use old_crypto_rs::nihilist::Nihilist;
//!
//! let cipher = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
//! let plaintext = b"IFYOUCANREADTHIS";
//! let mut ciphertext = vec![0u8; 22];
//!
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```

use crate::Block;
use crate::straddling::StraddlingCheckerboard;
use crate::transposition::Transposition;

/// Nihilist cipher combining straddling checkerboard and transposition.
///
/// This cipher performs a two-stage encryption:
/// 1. Converts plaintext to digits using a straddling checkerboard
/// 2. Applies columnar transposition to the resulting digits
///
/// The decryption process reverses these steps in opposite order.
pub struct Nihilist {
    /// Straddling checkerboard for initial text-to-digits conversion
    sc: StraddlingCheckerboard,
    /// Transposition cipher for super-encipherment
    transp: Transposition,
}

impl Nihilist {
    /// Creates a new Nihilist cipher with the specified keys.
    ///
    /// # Arguments
    ///
    /// * `key1` - The key for the straddling checkerboard (e.g., "ARABESQUE")
    /// * `key2` - The key for the transposition cipher (e.g., "SUBWAY")
    /// * `chrs` - Two characters defining the blank positions in the checkerboard (e.g., "37")
    ///
    /// # Returns
    ///
    /// Returns `Ok(Nihilist)` if both keys are valid, or `Err(String)` with an error message
    /// if either key is invalid or empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::nihilist::Nihilist;
    ///
    /// let cipher = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `key1` is empty or invalid for the straddling checkerboard
    /// - `key2` is empty or invalid for the transposition cipher
    /// - `chrs` is not exactly two characters or contains invalid positions
    pub fn new(key1: &str, key2: &str, chrs: &str) -> Result<Self, String> {
        let sc = StraddlingCheckerboard::new(key1, chrs)?;
        let transp = Transposition::new(key2)?;

        Ok(Nihilist {
            sc,
            transp,
        })
    }
}

impl Block for Nihilist {
    /// Returns the block size of the cipher.
    ///
    /// The block size is determined by the transposition cipher's key length.
    ///
    /// # Returns
    ///
    /// The number of characters that can be processed in one block.
    ///
    fn block_size(&self) -> usize {
        self.transp.block_size()
    }

    /// Encrypts the source data into the destination buffer.
    ///
    /// The encryption process:
    /// 1. Converts plaintext to digits using the straddling checkerboard
    /// 2. Applies columnar transposition to the resulting digits
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for the ciphertext (must be large enough)
    /// * `src` - Source plaintext to encrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`.
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = vec![0u8; 2 * src.len()];
        let n = self.sc.encrypt(&mut buf, src);
        self.transp.encrypt(dst, &buf[..n])
    }

    /// Decrypts the source ciphertext into the destination buffer.
    ///
    /// The decryption process:
    /// 1. Reverses the columnar transposition
    /// 2. Converts the resulting digits back to plaintext using the straddling checkerboard
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer for the plaintext (must be large enough)
    /// * `src` - Source ciphertext to decrypt
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst`.
    /// 
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = vec![0u8; src.len()];
        let n = self.transp.decrypt(&mut buf, src);
        self.sc.decrypt(dst, &buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cipher() {
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
        assert_eq!(c.block_size(), 6);
    }

    #[test]
    fn test_new_cipher_bad_keys() {
        assert!(Nihilist::new("PORTABLE", "", "89").is_err());
        assert!(Nihilist::new("", "SUBWAY", "62").is_err());
    }

    #[test]
    fn test_nihilist_encrypt() {
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
        let pt = "IFYOUCANREADTHIS";
        let ct = "1037306631738227035749";
        let mut dst = vec![0u8; ct.len()];
        c.encrypt(&mut dst, pt.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst), ct);
    }

    #[test]
    fn test_nihilist_decrypt() {
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
        let pt = "IFYOUCANREADTHIS";
        let ct = "1037306631738227035749";
        let mut dst = vec![0u8; pt.len()];
        c.decrypt(&mut dst, ct.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst).trim_matches('\0'), pt);
    }
}
