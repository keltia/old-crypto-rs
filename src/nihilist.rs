use crate::Block;
use crate::straddling::StraddlingCheckerboard;
use crate::transposition::Transposition;

pub struct Nihilist {
    sc: StraddlingCheckerboard,
    transp: Transposition,
}

impl Nihilist {
    pub fn new(key1: &str, key2: &str, chrs: &str) -> Result<Self, String> {
        let sc = StraddlingCheckerboard::new(key1, chrs)?;
        let transp = Transposition::new(key2)?;

        Ok(Nihilist {
            sc,
            transp,
        })
    }
}

impl Block for Nihilist {
    fn block_size(&self) -> usize {
        self.transp.block_size()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = vec![0u8; 2 * src.len()];
        let n = self.sc.encrypt(&mut buf, src);
        self.transp.encrypt(dst, &buf[..n])
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut buf = vec![0u8; src.len()];
        let n = self.transp.decrypt(&mut buf, src);
        self.sc.decrypt(dst, &buf[..n])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cipher() {
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
        assert_eq!(c.block_size(), 6);
    }

    #[test]
    fn test_new_cipher_bad_keys() {
        assert!(Nihilist::new("PORTABLE", "", "89").is_err());
        assert!(Nihilist::new("", "SUBWAY", "62").is_err());
    }

    #[test]
    fn test_nihilist_encrypt() {
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
        let pt = "IFYOUCANREADTHIS";
        let ct = "1037306631738227035749";
        let mut dst = vec![0u8; ct.len()];
        c.encrypt(&mut dst, pt.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst), ct);
    }

    #[test]
    fn test_nihilist_decrypt() {
        let c = Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap();
        let pt = "IFYOUCANREADTHIS";
        let ct = "1037306631738227035749";
        let mut dst = vec![0u8; pt.len()];
        c.decrypt(&mut dst, ct.as_bytes());
        assert_eq!(String::from_utf8_lossy(&dst).trim_matches('\0'), pt);
    }
}
