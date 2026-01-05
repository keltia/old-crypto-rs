use crate::Block;
use std::collections::HashMap;

const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ALPHABET_SIZE: usize = ALPHABET.len();

pub struct CaesarCipher {
    #[allow(dead_code)]
    key: u8,
    enc: HashMap<u8, u8>,
    dec: HashMap<u8, u8>,
}

fn expand_key(key: u8, enc: &mut HashMap<u8, u8>, dec: &mut HashMap<u8, u8>) {
    for (i, &ch) in ALPHABET.iter().enumerate() {
        let transform = (i + key as usize) % ALPHABET_SIZE;
        enc.insert(ch, ALPHABET[transform]);
        dec.insert(ALPHABET[transform], ch);
    }
}

impl CaesarCipher {
    /// NewCipher creates a new instance of cipher.Block
    pub fn new(key: i32) -> Self {
        let mut enc = HashMap::new();
        let mut dec = HashMap::new();
        let key_u8 = key as u8;
        expand_key(key_u8, &mut enc, &mut dec);
        CaesarCipher {
            key: key_u8,
            enc,
            dec,
        }
    }
}

impl Block for CaesarCipher {
    /// BlockSize is part of the interface
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypt is part of the interface
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = *self.enc.get(&ch).unwrap_or(&ch);
        }
        src.len()
    }

    /// Decrypt is part of the interface
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = *self.dec.get(&ch).unwrap_or(&ch);
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CaesarTest {
        key: i32,
        pt: &'static str,
        ct: &'static str,
    }

    const ENCRYPT_CAESAR_TESTS: [CaesarTest; 3] = [
        CaesarTest { key: 3, pt: "ABCDE", ct: "DEFGH" },
        CaesarTest { key: 4, pt: "COUCOU", ct: "GSYGSY" },
        CaesarTest { key: 13, pt: "COUCOU", ct: "PBHPBH" },
    ];

    #[test]
    fn test_expand_key() {
        let mut enc = HashMap::new();
        let mut dec = HashMap::new();

        let mut myenc = HashMap::new();
        let myenc_data = [
            (b'A', b'D'), (b'B', b'E'), (b'C', b'F'), (b'D', b'G'), (b'E', b'H'), (b'F', b'I'),
            (b'G', b'J'), (b'H', b'K'), (b'I', b'L'), (b'J', b'M'), (b'K', b'N'), (b'L', b'O'),
            (b'M', b'P'), (b'N', b'Q'), (b'O', b'R'), (b'P', b'S'), (b'Q', b'T'), (b'R', b'U'),
            (b'S', b'V'), (b'T', b'W'), (b'U', b'X'), (b'V', b'Y'), (b'W', b'Z'), (b'X', b'A'),
            (b'Y', b'B'), (b'Z', b'C'),
        ];
        for (k, v) in myenc_data { myenc.insert(k, v); }

        let mut mydec = HashMap::new();
        let mydec_data = [
            (b'D', b'A'), (b'E', b'B'), (b'F', b'C'), (b'G', b'D'), (b'H', b'E'), (b'I', b'F'),
            (b'J', b'G'), (b'K', b'H'), (b'L', b'I'), (b'M', b'J'), (b'N', b'K'), (b'O', b'L'),
            (b'P', b'M'), (b'Q', b'N'), (b'R', b'O'), (b'S', b'P'), (b'T', b'Q'), (b'U', b'R'),
            (b'V', b'S'), (b'W', b'T'), (b'X', b'U'), (b'Y', b'V'), (b'Z', b'W'), (b'A', b'X'),
            (b'B', b'Y'), (b'C', b'Z'),
        ];
        for (k, v) in mydec_data { mydec.insert(k, v); }

        expand_key(3, &mut enc, &mut dec);
        assert_eq!(myenc, enc);
        assert_eq!(mydec, dec);
    }

    #[test]
    fn test_caesar_cipher_block_size() {
        for test in ENCRYPT_CAESAR_TESTS {
            let c = CaesarCipher::new(test.key);
            assert_eq!(c.block_size(), 1);
        }
    }

    #[test]
    fn test_caesar_cipher_encrypt() {
        for test in ENCRYPT_CAESAR_TESTS {
            let c = CaesarCipher::new(test.key);
            let plain = test.pt.as_bytes();
            let mut cipher = vec![0u8; plain.len()];
            c.encrypt(&mut cipher, plain);
            assert_eq!(cipher, test.ct.as_bytes());
        }
    }

    #[test]
    fn test_caesar_cipher_decrypt() {
        for test in ENCRYPT_CAESAR_TESTS {
            let c = CaesarCipher::new(test.key);
            let cipher = test.ct.as_bytes();
            let mut plain = vec![0u8; cipher.len()];
            c.decrypt(&mut plain, cipher);
            assert_eq!(plain, test.pt.as_bytes());
        }
    }
}
