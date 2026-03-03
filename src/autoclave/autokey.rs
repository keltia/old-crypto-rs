//! Autokey is the autoclave system where the plaintext is used as key, instead of repeating the
//! key several times.  In essence, the key is just used for the initial "block", then cleartext
//! is appended.
//! 

use crate::Block;

#[derive(Debug)]
pub struct Autokey {
    /// The numeric key values (0-25) derived from the key string.
    key: Vec<u8>,
}

impl Autokey {
    pub fn new(key: &str) -> Self {
        let key_vec = key.as_bytes().iter()
            .map(|&b| b - b'A')
            .collect::<Vec<_>>();
        Autokey {
            key: key_vec,
        }
    }
}

#[allow(dead_code)]
impl Block for Autokey {
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
        let mut neg_key: Vec<u8> = Vec::with_capacity(src.len());
        0
    }
}
