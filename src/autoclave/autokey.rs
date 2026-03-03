
use crate::Block;
use crate::vigenere::encode_one;

#[derive(Debug)]
pub struct Autokey {
    /// The numeric key values (0-25) derived from the key string.
    key: Vec<u8>,
}

impl crate::Autokey {
    pub fn new(key: &str) -> Self {
        let key_vec = key.as_bytes().iter()
            .map(|&b| b - b'A')
            .collect::<Vec<_>>();
        crate::Autokey {
            key: key_vec,
        }
    }
}

impl Block for crate::Autokey {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }
        let mut plain = Vec::with_capacity(src.len());
        let mut key = Vec::with_capacity(src.len());
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        if src.is_empty() {
            return 0;
        }
        let mut cipher = Vec::with_capacity(src.len());
        let mut neg_key = Vec::with_capacity(src.len());
    }
}
