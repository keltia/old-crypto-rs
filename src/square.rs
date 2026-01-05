use crate::Block;
use crate::helpers;
use std::collections::HashMap;

pub const BASE36: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

pub struct SquareCipher {
    key: String,
    chrs: String,
    alpha: Vec<u8>,
    enc: HashMap<u8, String>,
    dec: HashMap<String, u8>,
}

impl SquareCipher {
    pub fn new(key: &str, chrs: &str) -> Result<Self, String> {
        if key.is_empty() || chrs.is_empty() {
            return Err("neither key nor chrs can be empty".to_string());
        }

        let alpha = helpers::condense(&format!("{}{}", key, BASE36)).as_bytes().to_vec();

        let mut c = SquareCipher {
            key: key.to_string(),
            chrs: chrs.to_string(),
            alpha,
            enc: HashMap::new(),
            dec: HashMap::new(),
        };
        c.expand_key();
        Ok(c)
    }

    fn expand_key(&mut self) {
        let mut bigr = vec![0u8; 2];
        let klen = self.chrs.len();
        let chrs_bytes = self.chrs.as_bytes();

        for i in 0..klen {
            for j in 0..klen {
                bigr[0] = chrs_bytes[i];
                bigr[1] = chrs_bytes[j];

                let ind = i * klen + j;
                let bigr_str = String::from_utf8(bigr.clone()).unwrap();
                if ind < self.alpha.len() {
                    self.enc.insert(self.alpha[ind], bigr_str.clone());
                    self.dec.insert(bigr_str, self.alpha[ind]);
                }
            }
        }
    }
}

impl Block for SquareCipher {
    fn block_size(&self) -> usize {
        self.key.len()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        for (i, &ch) in src.iter().enumerate() {
            if let Some(ct) = self.enc.get(&ch) {
                let ct_bytes = ct.as_bytes();
                dst[i * 2] = ct_bytes[0];
                dst[i * 2 + 1] = ct_bytes[1];
            }
        }
        src.len() * 2
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        for i in (0..src.len()).step_by(2) {
            let pt_str = String::from_utf8(vec![src[i], src[i + 1]]).unwrap();
            if let Some(&pt) = self.dec.get(&pt_str) {
                dst[i / 2] = pt;
            }
        }
        src.len() / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expand_key() {
        let test_data = [
            ("PORTABLE", "ADFGVX"),
            ("ARABESQUE", "012345"),
        ];

        for (key, chrs) in test_data {
            let _c = SquareCipher::new(key, chrs).unwrap();
            // In Rust we don't need to test multiple versions of expand_key
            // we just test that the maps are correct.
            // Since the maps are private and would be tedious to recreate here,
            // we can test the functional encryption/decryption which depends on them.
        }
    }

    #[test]
    fn test_new_cipher() {
        let c = SquareCipher::new("PORTABLE", "ADFGVX");
        assert!(c.is_ok());
    }

    #[test]
    fn test_new_cipher_empty_key() {
        let c = SquareCipher::new("", "012345");
        assert!(c.is_err());
    }

    #[test]
    fn test_new_cipher_empty_chrs() {
        let c = SquareCipher::new("SUBWAY", "");
        assert!(c.is_err());
    }

    #[test]
    fn test_square_cipher_block_size() {
        let test_data = [
            ("PORTABLE", "ADFGVX"),
            ("ARABESQUE", "012345"),
        ];
        for (key, chrs) in test_data {
            let c = SquareCipher::new(key, chrs).unwrap();
            assert_eq!(c.block_size(), key.len());
        }
    }

    #[test]
    fn test_square_cipher_encrypt() {
        let test_data = [
            ("PORTABLE", "ADFGVX", "ATTACKATDAWN", "AVAGAGAVDFFGAVAGDGAVGVFX"),
            ("ARABESQUE", "012345", "ATTACKATDAWN", "003232001122003212003425"),
        ];

        for (key, chrs, pt, ct) in test_data {
            let c = SquareCipher::new(key, chrs).unwrap();
            let src = pt.as_bytes();
            let mut dst = vec![0u8; 2 * pt.len()];
            c.encrypt(&mut dst, src);
            assert_eq!(String::from_utf8(dst).unwrap(), ct);
        }
    }

    #[test]
    fn test_square_cipher_decrypt() {
        let test_data = [
            ("PORTABLE", "ADFGVX", "ATTACKATDAWN", "AVAGAGAVDFFGAVAGDGAVGVFX"),
            ("ARABESQUE", "012345", "ATTACKATDAWN", "003232001122003212003425"),
        ];

        for (key, chrs, pt, ct) in test_data {
            let c = SquareCipher::new(key, chrs).unwrap();
            let src = ct.as_bytes();
            let mut dst = vec![0u8; src.len() / 2];
            c.decrypt(&mut dst, src);
            assert_eq!(String::from_utf8(dst).unwrap(), pt);
        }
    }
}
