//! Autocrypt is the autoclave system where the ciphertext is used as key, instead of repeating the
//! key several times.  This is the equivalent on an IV in modern systems, and this is the ancestor
//! of the CBC mode for modern ciphers.
//!

use crate::Block;

#[derive(Debug)]
pub struct Autocrypt {
    /// The numeric key values (0-25) derived from the key string.
    key: Vec<u8>,
}

impl Autocrypt {
    pub fn new(key: &str) -> Self {
        let key_vec = key.as_bytes().iter()
            .map(|&b| b - b'A')
            .collect::<Vec<_>>();
        Autocrypt {
            key: key_vec,
        }
    }
}

impl Block for Autocrypt {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }
        let mut plain: Vec<u8> = Vec::with_capacity(src.len());
        let mut key: Vec<u8> = Vec::with_capacity(src.len());
        0
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }
        let mut cipher: Vec<u8> = Vec::with_capacity(src.len());
        let mut neg_key:Vec<u8>  = Vec::with_capacity(src.len());
        0
    }
}
