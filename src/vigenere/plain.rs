//! Vigenere cipher implementation.
//!
//! The Vigenere cipher is a polyalphabetic substitution cipher, where each plaintext letter is
//! replaced by a letter some fixed number of positions down the alphabet.  The number of position
//! shifts is calculated through a simple key, duplicated across the whole plaintext.
//!
//! Essentially, the key creates a Caesar cipher for each letter in the key.
//!
//! [Vigenère Cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
//!
//! # Examples
//!
//! ```
//! use old_crypto_rs::Block;
//! use old_crypto_rs::VigenereCipher;
//!
//! let cipher = VigenereCipher::new("KEY");
//! let plaintext = b"HELLO";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! assert_eq!(&ciphertext, b"RIJVS");
//! ```
//!
use std::marker::PhantomData;

use crate::Block;
use crate::helpers::{Alphabet, Latin26};

use eyre::Result;
use crate::error::Error;

/// A Vigenere cipher implementation, generic over an [`Alphabet`].
///
/// This cipher uses a keyword to perform a series of Caesar ciphers on the plaintext.
/// It is a classic example of a polyalphabetic substitution cipher.
///
#[derive(Debug)]
pub struct Vigenere<A: Alphabet> {
    /// The numeric key values (0..A::SIZE) derived from the key string.
    key: Vec<u8>,
    _phantom: PhantomData<A>,
}

/// Vigenere cipher over the standard 26-letter Latin alphabet (A-Z).
pub type VigenereCipher = Vigenere<Latin26>;

impl<A: Alphabet> Vigenere<A> {
    /// Creates a new Vigenere cipher with the given key string.
    ///
    /// Characters not in the alphabet are ignored. The key is converted
    /// to uppercase before processing.
    ///
    /// # Arguments
    ///
    /// * `key` - The string used to derive the shift values.
    ///
    pub fn new(key: &str) -> Self {
        let key_vec = key.to_ascii_uppercase().as_bytes().iter()
            .filter_map(|&b| A::normalize(b).map(|idx| idx as u8))
            .collect::<Vec<_>>();
        Vigenere { key: key_vec, _phantom: PhantomData }
    }
}

/// Core function to perform modular addition of two numeric vectors.
///
/// This function adds the corresponding elements of the `plain` and `key` vectors
/// modulo `A::SIZE`. This is used as the basic operation for both encryption and
/// decryption in the Vigenere cipher.
///
/// # Arguments
///
/// * `plain` - A vector of numeric values (0..A::SIZE) to be shifted.
/// * `key` - A vector of numeric values (0..A::SIZE) representing the shift amounts.
///
/// # Returns
///
/// Returns a `Result` containing the resulting numeric vector if the inputs are
/// valid and have the same length, or an error otherwise.
///
pub(crate) fn encode_one<A: Alphabet>(plain: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    if plain.is_empty() || key.is_empty() {
        return Err(Error::EmptyInput.into());
    }

    if plain.len() != key.len() {
        return Err(Error::LengthMismatch(plain.len(), key.len()).into());
    }

    let n = A::SIZE as u8;
    let ct = plain.iter().zip(key.iter()).map(|(p, k)| (p + k) % n).collect::<Vec<_>>();
    Ok(ct)
}

impl<A: Alphabet> Block for Vigenere<A> {
    /// Returns the length of the Vigenere key.
    fn block_size(&self) -> usize {
        self.key.len()
    }

    /// Encrypts source bytes into destination buffer using the Vigenere cipher.
    ///
    /// This method maps source characters through the alphabet, applies the
    /// Vigenere shift from the key, and then maps the result back to characters.
    /// Non-alphabet characters are passed through with the raw shift applied.
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer for the encrypted bytes.
    /// * `src` - The source plaintext bytes to encrypt.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to `dst`.
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() || self.key.is_empty() {
            return 0;
        }

        let mut plain = Vec::with_capacity(src.len());
        let mut key = Vec::with_capacity(src.len());

        for (i, &p) in src.iter().enumerate() {
            if i >= dst.len() {
                break;
            }
            let p_val = match A::normalize(p) {
                Some(idx) => idx as u8,
                None => p,
            };
            plain.push(p_val);
            key.push(self.key[i % self.key.len()]);
        }

        let ct_vals = match encode_one::<A>(plain, key) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        for (i, &val) in ct_vals.iter().enumerate() {
            dst[i] = A::denormalize(val as usize);
        }

        ct_vals.len()
    }

    /// Decrypts source bytes into destination buffer using the Vigenere cipher.
    ///
    /// This method reverses the Vigenere shift by subtracting the key values
    /// from the ciphertext values modulo the alphabet size.
    ///
    /// # Arguments
    ///
    /// * `dst` - The destination buffer for the decrypted bytes.
    /// * `src` - The source ciphertext bytes to decrypt.
    ///
    /// # Returns
    ///
    /// Returns the number of bytes written to `dst`.
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() || self.key.is_empty() {
            return 0;
        }

        let n = A::SIZE as u8;
        let mut cipher = Vec::with_capacity(src.len());
        let mut neg_key = Vec::with_capacity(src.len());

        for (i, &c) in src.iter().enumerate() {
            if i >= dst.len() {
                break;
            }
            let c_val = match A::normalize(c) {
                Some(idx) => idx as u8,
                None => c,
            };
            cipher.push(c_val);
            let k = self.key[i % self.key.len()];
            neg_key.push((n - k) % n);
        }

        let pt_vals = match encode_one::<A>(cipher, neg_key) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        for (i, &val) in pt_vals.iter().enumerate() {
            dst[i] = A::denormalize(val as usize);
        }

        pt_vals.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::Latin26;

    #[test]
    fn test_encode_one_valid_input() {
        let plain = vec![7, 4, 11, 11, 14]; // "HELLO"
        let key = vec![10, 4, 24, 18, 19]; // "KEYST"
        let result = encode_one::<Latin26>(plain, key).unwrap();
        let expected = vec![17, 8, 9, 3, 7]; // (H+K)%26, (E+E)%26, etc.
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_one_empty_plaintext() {
        let plain = vec![];
        let key = vec![1, 2, 3];
        let result = encode_one::<Latin26>(plain, key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Empty input");
    }

    #[test]
    fn test_encode_one_empty_key() {
        let plain = vec![1, 2, 3];
        let key = vec![];
        let result = encode_one::<Latin26>(plain, key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Empty input");
    }

    #[test]
    fn test_encode_one_mismatched_lengths() {
        let plain = vec![1, 2, 3];
        let key = vec![1, 2];
        let result = encode_one::<Latin26>(plain, key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Every input must have the same length: 3 vs 2");
    }

    #[test]
    fn test_vigenere_cipher_encrypt_decrypt() {
        let cipher = VigenereCipher::new("KEY");
        let pt = b"HELLO";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        assert_eq!(&ct, b"RIJVS");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_vigenere_cipher_multi_block() {
        let cipher = VigenereCipher::new("ABC"); // Shift by 0, 1, 2
        let pt = b"AAAAAA";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        assert_eq!(&ct, b"ABCABC");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_wikipedia_example_lemon() {
        // From Wikipedia: Plaintext "ATTACKATDAWN", Key "LEMON", Ciphertext "LXFOPVEFRNHR"
        let cipher = VigenereCipher::new("LEMON");
        let pt = b"ATTACKATDAWN";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);
        assert_eq!(&ct, b"LXFOPVEFRNHR");

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }

    #[test]
    fn test_wikipedia_example_babbage() {
        // From Wikipedia: Babbage's challenge from Thwaites used "TWO" and "COMBINED"
        // Let's test with one of them.
        let cipher = VigenereCipher::new("COMBINED");
        let pt = b"DEFENDTHEEASTWALLOFTHECASTLE";
        let mut ct = vec![0u8; pt.len()];
        cipher.encrypt(&mut ct, pt);

        let mut dec = vec![0u8; ct.len()];
        cipher.decrypt(&mut dec, &ct);
        assert_eq!(&dec, pt);
    }
}
