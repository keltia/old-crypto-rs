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
//! ```
//!
use crate::{Block, VicCipher};
use crate::helpers::to_numeric;

#[derive(Debug)]
pub struct VigenereCipher {
    key: Vec<u8>,
}

impl VigenereCipher {
    fn new(key: &str) -> Self {
        VigenereCipher {
            key: to_numeric(key),
        }
    }
}

impl Block for VigenereCipher {
    fn block_size(&self) -> usize {
        self.key.len()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        src.len()
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        src.len()
    }
}
