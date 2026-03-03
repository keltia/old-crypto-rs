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
use crate::Block;

use eyre::Result;

/// A Vigenere cipher implementation.
///
/// This cipher uses a keyword to perform a series of Caesar ciphers on the plaintext.
/// It is a classic example of a polyalphabetic substitution cipher.
/// 
#[derive(Debug)]
pub struct VigenereCipher {
    /// The numeric key values (0-25) derived from the key string.
    key: Vec<u8>,
}

impl VigenereCipher {
    /// Creates a new Vigenere cipher with the given key string.
    ///
    /// Non-alphabetic characters in the key are ignored. The key is converted
    /// to uppercase before processing.
    ///
    /// # Arguments
    ///
    /// * `key` - The string used to derive the shift values.
    ///
    pub fn new(key: &str) -> Self {
        let key_vec = key.to_ascii_uppercase().as_bytes().iter()
            .filter(|&&b| b >= b'A' && b <= b'Z')
            .map(|&b| b - b'A')
            .collect::<Vec<_>>();
        VigenereCipher {
            key: key_vec,
        }
    }
}

/// Core function to perform modular addition of two numeric vectors.
///
/// This function adds the corresponding elements of the `plain` and `key` vectors
/// modulo 26. This is used as the basic operation for both encryption and decryption
/// in the Vigenere cipher.
///
/// # Arguments
///
/// * `plain` - A vector of numeric values (0-25) to be shifted.
/// * `key` - A vector of numeric values (0-25) representing the shift amounts.
///
/// # Returns
///
/// Returns a `Result` containing the resulting numeric vector if the inputs are
/// valid and have the same length, or an error otherwise.
/// 
pub(crate) fn encode_one(plain: Vec<u8>, key: Vec<u8>) -> Result<Vec<u8>> {
    if plain.is_empty() || key.is_empty() {
        return Err(eyre::eyre!("empty input"));
    }

    if plain.len() != key.len() {
        return Err(eyre::eyre!("plain and key must have the same length"));
    }
    
    let ct = plain.iter().zip(key.iter()).map(|(p, k)| (p + k) % 26).collect::<Vec<_>>();
    Ok(ct)
}

impl Block for VigenereCipher {
    /// Returns the length of the Vigenere key.
    fn block_size(&self) -> usize {
        self.key.len()
    }

    /// Encrypts source bytes into destination buffer using the Vigenere cipher.
    ///
    /// This method maps source characters 'A'-'Z' to values 0-25, applies the
    /// Vigenere shift from the key, and then maps the result back to uppercase letters.
    /// Non-alphabetic characters are currently handled by applying the shift to their
    /// raw ASCII value, though most usage expects only 'A'-'Z' input.
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
            // Assumes src is A-Z (ASCII 65-90)
            let p_val = if p >= b'A' && p <= b'Z' {
                p - b'A'
            } else {
                p
            };
            plain.push(p_val);
            key.push(self.key[i % self.key.len()]);
        }

        let ct_vals = match encode_one(plain, key) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        for (i, &val) in ct_vals.iter().enumerate() {
            dst[i] = val + b'A';
        }

        ct_vals.len()
    }

    /// Decrypts source bytes into destination buffer using the Vigenere cipher.
    ///
    /// This method reverses the Vigenere shift by subtracting the key values
    /// from the ciphertext values modulo 26.
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

        let mut cipher = Vec::with_capacity(src.len());
        let mut neg_key = Vec::with_capacity(src.len());

        for (i, &c) in src.iter().enumerate() {
            if i >= dst.len() {
                break;
            }
            let c_val = if c >= b'A' && c <= b'Z' {
                c - b'A'
            } else {
                c
            };
            cipher.push(c_val);
            // Vigenere decryption: (c - k) % 26
            // We can use encode_one by providing -k mod 26
            let k = self.key[i % self.key.len()];
            neg_key.push((26 - k) % 26);
        }

        let pt_vals = match encode_one(cipher, neg_key) {
            Ok(v) => v,
            Err(_) => return 0,
        };

        for (i, &val) in pt_vals.iter().enumerate() {
            dst[i] = val + b'A';
        }

        pt_vals.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_one_valid_input() {
        let plain = vec![7, 4, 11, 11, 14]; // "HELLO"
        let key = vec![10, 4, 24, 18, 19]; // "KEYST"
        let result = encode_one(plain, key).unwrap();
        let expected = vec![17, 8, 9, 3, 7]; // (H+K)%26, (E+E)%26, etc.
        assert_eq!(result, expected);
    }

    #[test]
    fn test_encode_one_empty_plaintext() {
        let plain = vec![];
        let key = vec![1, 2, 3];
        let result = encode_one(plain, key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "empty input");
    }

    #[test]
    fn test_encode_one_empty_key() {
        let plain = vec![1, 2, 3];
        let key = vec![];
        let result = encode_one(plain, key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "empty input");
    }

    #[test]
    fn test_encode_one_mismatched_lengths() {
        let plain = vec![1, 2, 3];
        let key = vec![1, 2];
        let result = encode_one(plain, key);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "plain and key must have the same length");
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

