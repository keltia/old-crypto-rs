use crate::Block;

pub struct NullCipher;

impl NullCipher {
    /// NewCipher creates a new instance of cipher.Block
    pub fn new() -> Self {
        NullCipher
    }
}

impl Block for NullCipher {
    /// BlockSize is part of the interface
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypt is part of the interface
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        dst[..src.len()].copy_from_slice(src);
        src.len()
    }

    /// Decrypt is part of the interface
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        dst[..src.len()].copy_from_slice(src);
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cipher() {
        let _ = NullCipher::new();
    }

    #[test]
    fn test_null_cipher_block_size() {
        let c = NullCipher::new();
        assert_eq!(c.block_size(), 1);
    }

    #[test]
    fn test_null_cipher_encrypt() {
        let c = NullCipher::new();
        let tests = [
            ("ABCDE", "ABCDE"),
            ("COUCOU", "COUCOU"),
        ];

        for (pt, ct) in tests {
            let plain = pt.as_bytes();
            let mut cipher = vec![0u8; plain.len()];
            c.encrypt(&mut cipher, plain);
            assert_eq!(cipher, ct.as_bytes());
        }
    }

    #[test]
    fn test_null_cipher_decrypt() {
        let c = NullCipher::new();
        let tests = [
            ("ABCDE", "ABCDE"),
            ("COUCOU", "COUCOU"),
        ];

        for (pt, ct) in tests {
            let cipher = ct.as_bytes();
            let mut plain = vec![0u8; cipher.len()];
            c.decrypt(&mut plain, cipher);
            assert_eq!(plain, pt.as_bytes());
        }
    }
}
