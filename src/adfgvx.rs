use crate::Block;
use crate::square::SquareCipher;
use crate::transposition::Transposition;

pub struct ADFGVX {
    sqr: SquareCipher,
    transp: Transposition,
}

impl ADFGVX {
    pub fn new(key1: &str, key2: &str) -> Result<Self, String> {
        let sqr = SquareCipher::new(key1, "ADFGVX")?;
        let transp = Transposition::new(key2)?;

        Ok(ADFGVX {
            sqr,
            transp,
        })
    }
}

impl Block for ADFGVX {
    fn block_size(&self) -> usize {
        self.transp.block_size()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = vec![0u8; 2 * src.len()];
        let n = self.sqr.encrypt(&mut buf, src);
        self.transp.encrypt(dst, &buf[..n])
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = vec![0u8; src.len()];
        let n = self.transp.decrypt(&mut buf, src);
        self.sqr.decrypt(dst, &buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cipher() {
        let _c = ADFGVX::new("PORTABLE", "SUBWAY").unwrap();
    }

    #[test]
    fn test_new_cipher_bad_keys() {
        assert!(ADFGVX::new("PORTABLE", "").is_err());
        assert!(ADFGVX::new("", "SUBWAY").is_err());
    }

    #[test]
    fn test_adfgvx_block_size() {
        let c = ADFGVX::new("PORTABLE", "SUBWAY").unwrap();
        assert_eq!(c.block_size(), 6);
    }

    #[test]
    fn test_adfgvx_encrypt() {
        let c = ADFGVX::new("PORTABLE", "SUBWAY").unwrap();
        let pt = "ATTACKATDAWN";
        let ct = "AFDFADAGAAAAVVVVGFGVGGGX";
        let mut dst = vec![0u8; ct.len()];
        c.encrypt(&mut dst, pt.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst), ct);
    }

    #[test]
    fn test_adfgvx_decrypt() {
        let c = ADFGVX::new("PORTABLE", "SUBWAY").unwrap();
        let pt = "ATTACKATDAWN";
        let ct = "AFDFADAGAAAAVVVVGFGVGGGX";
        let mut dst = vec![0u8; pt.len()];
        c.decrypt(&mut dst, ct.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst), pt);
    }
}
