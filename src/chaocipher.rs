use crate::Block;
use std::cell::RefCell;

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const ZENITH: usize = 0;
const NADIR: usize = 13;

pub struct Chaocipher {
    pkey: String,
    ckey: String,
    state: RefCell<ChaocipherState>,
}

struct ChaocipherState {
    pw: Vec<u8>,
    cw: Vec<u8>,
}

impl Chaocipher {
    /// NewCipher creates a new cipher with the provided keys
    pub fn new(pkey: &str, ckey: &str) -> Result<Self, String> {
        if pkey.len() != ALPHABET.len() || ckey.len() != ALPHABET.len() {
            return Err("bad alphabet length".to_string());
        }

        Ok(Chaocipher {
            pkey: pkey.to_string(),
            ckey: ckey.to_string(),
            state: RefCell::new(ChaocipherState {
                pw: pkey.as_bytes().to_vec(),
                cw: ckey.as_bytes().to_vec(),
            }),
        })
    }

    fn lshift_n(a: &mut [u8], n: usize) {
        if a.is_empty() { return; }
        let n = n % a.len();
        a.rotate_left(n);
    }

    fn advance(state: &mut ChaocipherState, idx: usize) {
        // First we shift the left alphabet (cw)
        Self::lshift_n(&mut state.cw, idx);
        let l = state.cw[ZENITH + 1];
        state.cw[ZENITH + 1..NADIR + 1].rotate_left(1);
        state.cw[NADIR] = l;

        // Then we shift the right alphabet (pw)
        Self::lshift_n(&mut state.pw, idx + 1);
        let l = state.pw[ZENITH + 2];
        state.pw[ZENITH + 2..NADIR + 1].rotate_left(1);
        state.pw[NADIR] = l;
    }

    fn encode_both(&self, is_encrypt: bool, ch: u8) -> u8 {
        let mut state = self.state.borrow_mut();
        let idx = if is_encrypt {
            state.pw.iter().position(|&x| x == ch).unwrap_or(0)
        } else {
            state.cw.iter().position(|&x| x == ch).unwrap_or(0)
        };

        let pt = if is_encrypt {
            state.cw[idx]
        } else {
            state.pw[idx]
        };

        Self::advance(&mut state, idx);
        pt
    }

    fn reset(&self) {
        let mut state = self.state.borrow_mut();
        state.pw = self.pkey.as_bytes().to_vec();
        state.cw = self.ckey.as_bytes().to_vec();
    }
}

impl Block for Chaocipher {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.encode_both(true, ch);
        }
        src.len()
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.encode_both(false, ch);
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_TXT: &str = "WELLDONEISBETTERTHANWELLSAID";
    const CIPHER_TXT: &str = "OAHQHCNYNXTSZJRRHJBYHQKSOUJY";
    const LPLAIN_TXT: &str = "IFYOUCANREADTHISYOUEITHERDOWNLOADEDMYOWNIMPLEMENTATIONOFCHAOCIPHERORYOUWROTEONEOFYOUROWNINEITHERCASELETMEKNOWANDACCEPTMYCONGRATULATIONSX";
    const LCIPHER_TXT: &str = "TLMAGOONSKJBJYBQVGDQCDUNWNMZPLOYCWPCWKWQRBOYADSLQBKYCDGXJOLONKTTLRUZZJQGJBQNRQHQRREUIYIDHZOMVWZMVYUFQOGSNNUVYTJGQPSQTBRWFHLTCLVVBPMYYQVC";
    const KEY_PLAIN: &str = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
    const KEY_CIPHER: &str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";

    #[test]
    fn test_new_cipher() {
        let c = Chaocipher::new(ALPHABET, ALPHABET).unwrap();
        assert_eq!(c.block_size(), 1);
    }

    #[test]
    fn test_new_cipher_bad_len() {
        assert!(Chaocipher::new("AB", "CD").is_err());
    }

    #[test]
    fn test_chaocipher_encrypt() {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let src = PLAIN_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(dst, CIPHER_TXT.as_bytes());
    }

    #[test]
    fn test_chaocipher_encrypt_long() {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let src = LPLAIN_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(dst, LCIPHER_TXT.as_bytes());
    }

    #[test]
    fn test_chaocipher_decrypt() {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let src = CIPHER_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.decrypt(&mut dst, src);
        assert_eq!(dst, PLAIN_TXT.as_bytes());
    }

    #[test]
    fn test_chaocipher_decrypt_long() {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let src = LCIPHER_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.decrypt(&mut dst, src);
        assert_eq!(dst, LPLAIN_TXT.as_bytes());
    }

    #[test]
    fn test_advance() {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let idx = KEY_PLAIN.find('A').unwrap();
        assert_eq!(idx, 12);

        {
            let mut state = c.state.borrow_mut();
            Chaocipher::advance(&mut state, idx);
        }
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().cw), "PFJRIGTWOBNYQEHXUCZVAMDSLK");
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().pw), "VZGJRIHWXUMCPKTLNBQDEOYSFA");
    }

    #[test]
    fn test_advance_real() {
        let c = Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap();
        let idx = KEY_PLAIN.find('W').unwrap();
        assert_eq!(idx, 21);

        {
            let mut state = c.state.borrow_mut();
            Chaocipher::advance(&mut state, idx);
        }
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().cw), "ONYQHXUCZVAMDBSLKPEFJRIGTW");
        assert_eq!(String::from_utf8_lossy(&c.state.borrow().pw), "XUCPTLNBQDEOYMSFAVZKGJRIHW");
    }
}
