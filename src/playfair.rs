use crate::Block;
use crate::helpers;
use std::collections::HashMap;

const ALPHABET: &str = "ABCDEFGHIKLMNOPQRSTUVWXYZ";
const OP_ENCRYPT: u8 = 1;
const OP_DECRYPT: u8 = 4;
const CODE_WORD: &str = "01234";

// Cipher holds the key and transformation maps
pub struct PlayfairCipher {
    #[allow(dead_code)]
    key: String,
    i2c: HashMap<u8, Couple>,
    c2i: HashMap<Couple, u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct Couple {
    r: u8,
    c: u8,
}

impl PlayfairCipher {
    // transform is the cipher itself
    fn transform(&self, pt: Couple, opt: u8) -> Couple {
        let bg1 = self.i2c[&pt.r];
        let bg2 = self.i2c[&pt.c];
        if bg1.r == bg2.r {
            let ct1 = Couple { r: bg1.r, c: (bg1.c + opt) % 5 };
            let ct2 = Couple { r: bg2.r, c: (bg2.c + opt) % 5 };
            return Couple { r: self.c2i[&ct1], c: self.c2i[&ct2] };
        }
        if bg1.c == bg2.c {
            let ct1 = Couple { r: (bg1.r + opt) % 5, c: bg1.c };
            let ct2 = Couple { r: (bg2.r + opt) % 5, c: bg2.c };
            return Couple { r: self.c2i[&ct1], c: self.c2i[&ct2] };
        }
        let ct1 = Couple { r: bg1.r, c: bg2.c };
        let ct2 = Couple { r: bg2.r, c: bg1.c };
        Couple { r: self.c2i[&ct1], c: self.c2i[&ct2] }
    }

    /// NewCipher is part of the interface
    pub fn new(key: &str) -> Self {
        let condensed_key = helpers::condense(&format!("{}{}", key, ALPHABET));
        let mut i2c = HashMap::new();
        let mut c2i = HashMap::new();
        
        let mut ind = 0;
        let key_bytes = condensed_key.as_bytes();
        for i in 0..CODE_WORD.len() {
            for j in 0..CODE_WORD.len() {
                let c = key_bytes[ind];
                let couple = Couple { r: i as u8, c: j as u8 };
                i2c.insert(c, couple);
                c2i.insert(couple, c);
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

    /// Encrypt is part of the interface
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

    /// Decrypt is part of the interface
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
