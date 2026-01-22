//! Playfair cipher implementation.
//!
//! The Playfair cipher is a manual symmetric encryption technique and was the first literal
//! digraph substitution cipher. The scheme was invented in 1854 by Charles Wheatstone but
//! bears the name of Lord Playfair who promoted the use of the cipher.
//!
//! The Playfair cipher encrypts pairs of letters (bigrams or digraphs), instead of single
//! letters as in the simple substitution cipher. The key is a 5×5 grid of letters constructed
//! using a keyword. The letters I and J are typically combined into a single cell.
//!
//! # Algorithm
//!
//! 1. Create a 5×5 matrix using a keyword (duplicates removed) followed by remaining alphabet letters
//! 2. Split plaintext into pairs of letters (digraphs)
//! 3. Apply transformation rules based on the position of letter pairs in the matrix:
//!    - Same row: shift each letter one position to the right (wrapping around)
//!    - Same column: shift each letter one position down (wrapping around)
//!    - Rectangle: swap columns of the two letters
//!
//! # Example
//!
//! ```rust
//! use old_crypto_rs::{Block, PlayfairCipher};
//!
//! let cipher = PlayfairCipher::new("PLAYFAIREXAMPLE");
//! let plaintext = b"HIDETHEGOLDINTHETREXESTUMP";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(&mut ciphertext, plaintext);
//! ```
//! 
use crate::Block;
use crate::helpers;

const ALPHABET: &str = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
const OP_ENCRYPT: u8 = 1;
const OP_DECRYPT: u8 = 4;
const CODE_WORD: &str = "01234";

/// Playfair cipher implementation using a 5×5 keyed matrix.
///
/// The `PlayfairCipher` struct holds the cipher key and maintains bidirectional tables
/// between characters and their positions in the 5×5 Playfair matrix. This allows for
/// efficient encryption and decryption operations.
///
/// # Fields
///
/// * `key` - The condensed key string used to build the cipher matrix
/// * `i2c` - Table from character (as u8) to its `Couple` position in the matrix
/// * `c2i` - Table from matrix position to its character (as u8)
/// 
pub struct PlayfairCipher {
    #[allow(dead_code)]
    key: String,
    i2c: [Couple; 256],
    c2i: [u8; 25],
}

/// Represents a coordinate pair (row, column) in the 5×5 Playfair matrix.
///
/// A `Couple` is used to represent either:
/// - The position of a character in the Playfair matrix (as a coordinate)
/// - A pair of characters to be encrypted/decrypted (as indices)
///
/// # Fields
///
/// * `r` - Row index (0-4) or first character of a bigram
/// * `c` - Column index (0-4) or second character of a bigram
/// 
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Couple {
    r: u8,
    c: u8,
}

const INVALID_COUPLE: Couple = Couple { r: 0xFF, c: 0xFF };

impl PlayfairCipher {
    fn lookup(&self, ch: u8) -> Couple {
        let couple = self.i2c[ch as usize];
        if couple.r == 0xFF {
            panic!("invalid character");
        }
        couple
    }

    /// Transforms a pair of characters using the Playfair cipher rules.
    ///
    /// This is the core encryption/decryption function that applies the Playfair transformation
    /// rules based on the relative positions of two characters in the matrix.
    ///
    /// # Arguments
    ///
    /// * `pt` - A `Couple` where `r` and `c` represent the two characters to transform
    /// * `opt` - Operation mode: `OP_ENCRYPT` (1) for encryption, `OP_DECRYPT` (4) for decryption
    ///
    /// # Returns
    ///
    /// A `Couple` containing the transformed character pair
    ///
    /// # Transformation Rules
    ///
    /// 1. **Same row**: Shift each character by `opt` positions to the right (modulo 5)
    /// 2. **Same column**: Shift each character by `opt` positions down (modulo 5)
    /// 3. **Rectangle**: Swap the columns of the two characters
    /// 
    fn transform(&self, pt: Couple, opt: u8) -> Couple {
        let bg1 = self.lookup(pt.r);
        let bg2 = self.lookup(pt.c);
        if bg1.r == bg2.r {
            let ct1 = Couple { r: bg1.r, c: (bg1.c + opt) % 5 };
            let ct2 = Couple { r: bg2.r, c: (bg2.c + opt) % 5 };
            return Couple {
                r: self.c2i[(ct1.r as usize) * 5 + ct1.c as usize],
                c: self.c2i[(ct2.r as usize) * 5 + ct2.c as usize],
            };
        }
        if bg1.c == bg2.c {
            let ct1 = Couple { r: (bg1.r + opt) % 5, c: bg1.c };
            let ct2 = Couple { r: (bg2.r + opt) % 5, c: bg2.c };
            return Couple {
                r: self.c2i[(ct1.r as usize) * 5 + ct1.c as usize],
                c: self.c2i[(ct2.r as usize) * 5 + ct2.c as usize],
            };
        }
        let ct1 = Couple { r: bg1.r, c: bg2.c };
        let ct2 = Couple { r: bg2.r, c: bg1.c };
        Couple {
            r: self.c2i[(ct1.r as usize) * 5 + ct1.c as usize],
            c: self.c2i[(ct2.r as usize) * 5 + ct2.c as usize],
        }
    }

    /// Creates a new Playfair cipher with the specified key.
    ///
    /// The key is used to construct a 5×5 matrix by:
    /// 1. Condensing the key (removing duplicates and converting to uppercase)
    /// 2. Appending the remaining alphabet letters (I and J are combined)
    /// 3. Filling the matrix row by row with these characters
    ///
    /// # Arguments
    ///
    /// * `key` - The keyword used to generate the cipher matrix
    ///
    /// # Returns
    ///
    /// A new `PlayfairCipher` instance with initialized mapping tables
    ///
    /// # Example
    ///
    /// ```rust
    /// use old_crypto_rs::PlayfairCipher;
    ///
    /// let cipher = PlayfairCipher::new("PLAYFAIREXAMPLE");
    /// ```
    /// 
    pub fn new(key: &str) -> Self {
        let condensed_key = helpers::condense(&format!("{}{}", key, ALPHABET));
        let mut i2c = [INVALID_COUPLE; 256];
        let mut c2i = [0u8; 25];
        
        let mut ind = 0;
        let key_bytes = condensed_key.as_bytes();
        for i in 0..CODE_WORD.len() {
            for j in 0..CODE_WORD.len() {
                let c = key_bytes[ind];
                let couple = Couple { r: i as u8, c: j as u8 };
                i2c[c as usize] = couple;
                c2i[i * 5 + j] = c;
                ind += 1;
            }
        }

        PlayfairCipher {
            key: condensed_key,
            i2c,
            c2i,
        }
    }
}

impl Block for PlayfairCipher {
    /// BlockSize is part of the interface
    fn block_size(&self) -> usize {
        2
    }

    /// Encrypts plaintext using the Playfair cipher.
    ///
    /// This method processes the input plaintext in pairs of characters (digraphs) and applies
    /// the Playfair transformation rules. If the plaintext has an odd length, an 'X' is
    /// automatically appended as padding.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer where the ciphertext will be written. Must be at least as
    ///           large as the source length (rounded up to the nearest even number if odd).
    /// * `src` - Source plaintext bytes to encrypt. Each byte should represent an uppercase
    ///           letter from the Playfair alphabet.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the destination buffer (always even).
    ///
    /// # Example
    ///
    /// ```rust
    /// use old_crypto_rs::{Block, PlayfairCipher};
    ///
    /// let cipher = PlayfairCipher::new("PLAYFAIREXAMPLE");
    /// let plaintext = b"HIDETHEGOLD";
    /// let mut ciphertext = vec![0u8; 12]; // Account for potential padding
    /// let written = cipher.encrypt(&mut ciphertext, plaintext);
    /// assert_eq!(written, 12); // 11 chars + 1 'X' padding = 12
    /// ```
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut src_vec = src.to_vec();
        if src_vec.len() % 2 == 1 {
            src_vec.push(b'X');
        }

        for i in (0..src_vec.len()).step_by(2) {
            let bg = self.transform(Couple { r: src_vec[i], c: src_vec[i+1] }, OP_ENCRYPT);
            dst[i] = bg.r;
            dst[i+1] = bg.c;
        }
        src_vec.len()
    }

    /// Decrypts ciphertext using the Playfair cipher.
    ///
    /// This method processes the input ciphertext in pairs of characters (digraphs) and applies
    /// the inverse Playfair transformation rules to recover the original plaintext.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination buffer where the plaintext will be written. Must be at least as
    ///           large as the source length.
    /// * `src` - Source ciphertext bytes to decrypt. Must have an even length, as Playfair
    ///           operates on character pairs.
    ///
    /// # Returns
    ///
    /// The number of bytes written to the destination buffer (equal to source length).
    ///
    /// # Panics
    ///
    /// Panics if the source ciphertext has an odd number of bytes, as this violates the
    /// Playfair cipher's requirement to operate on digraphs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use old_crypto_rs::{Block, PlayfairCipher};
    ///
    /// let cipher = PlayfairCipher::new("PLAYFAIREXAMPLE");
    /// let ciphertext = b"BMODZBXDNABEKUDMUIXMMOUVIF";
    /// let mut plaintext = vec![0u8; ciphertext.len()];
    /// let written = cipher.decrypt(&mut plaintext, ciphertext);
    /// assert_eq!(written, ciphertext.len());
    /// ```
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.len() % 2 == 1 {
            panic!("odd number of elements");
        }

        for i in (0..src.len()).step_by(2) {
            let bg = self.transform(Couple { r: src[i], c: src[i+1] }, OP_DECRYPT);
            dst[i] = bg.r;
            dst[i+1] = bg.c;
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cipher() {
        let _c = PlayfairCipher::new("ARABESQUE");
    }

    #[test]
    fn test_playfair_cipher_block_size() {
        let c = PlayfairCipher::new("ARABESQUE");
        assert_eq!(c.block_size(), 2);
    }

    #[test]
    fn test_playfair_cipher_encrypt() {
        let c = PlayfairCipher::new("PLAYFAIREXAMPLE");
        let pt = b"HIDETHEGOLDINTHETREXESTUMP";
        let ct = b"BMODZBXDNABEKUDMUIXMMOUVIF";
        let mut dst = vec![0u8; ct.len()];
        c.encrypt(&mut dst, pt);
        assert_eq!(dst, ct);
    }

    #[test]
    fn test_playfair_cipher_encrypt_x() {
        let c = PlayfairCipher::new("PLAYFAIREXAMPLE");
        let pt = b"HID";
        let ct = b"BMGE";
        let mut dst = vec![0u8; 4];
        c.encrypt(&mut dst, pt);
        assert_eq!(dst, ct);
    }

    #[test]
    fn test_playfair_cipher_decrypt() {
        let c = PlayfairCipher::new("PLAYFAIREXAMPLE");
        let ct = b"BMODZBXDNABEKUDMUIXMMOUVIF";
        let pt = b"HIDETHEGOLDINTHETREXESTUMP";
        let mut dst = vec![0u8; ct.len()];
        c.decrypt(&mut dst, ct);
        assert_eq!(dst, pt);
    }

    #[test]
    #[should_panic(expected = "odd number of elements")]
    fn test_playfair_cipher_decrypt_panic() {
        let c = PlayfairCipher::new("PLAYFAIREXAMPLE");
        let ct = b"BMO";
        let mut dst = vec![0u8; 3];
        c.decrypt(&mut dst, ct);
    }
}
