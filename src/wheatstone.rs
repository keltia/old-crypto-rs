use crate::Block;
use crate::helpers;
use std::cell::RefCell;

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LEN_PL: usize = ALPHABET.len() + 1;
const LEN_CT: usize = ALPHABET.len();

pub struct Wheatstone {
    aplw: Vec<u8>,
    actw: Vec<u8>,
    start: u8,
    state: RefCell<WheatstoneState>,
}

struct WheatstoneState {
    curpos: usize,
    ctpos: usize,
}

impl Wheatstone {
    /// NewCipher creates a new cipher with the provided keys
    pub fn new(start: u8, pkey: &str, ckey: &str) -> Result<Self, String> {
        if pkey.is_empty() || ckey.is_empty() {
            return Err("keys can not be empty".to_string());
        }

        // Transform with key
        let pkey_shuffled = format!("+{}", helpers::shuffle(pkey, ALPHABET));
        let ckey_shuffled = helpers::shuffle(ckey, ALPHABET);

        let aplw = pkey_shuffled.as_bytes().to_vec();
        let actw = ckey_shuffled.as_bytes().to_vec();

        let ctpos = actw.iter().position(|&x| x == start).unwrap_or(0);

        Ok(Wheatstone {
            aplw,
            actw,
            start,
            state: RefCell::new(WheatstoneState {
                curpos: 0,
                ctpos,
            }),
        })
    }

    fn encode(&self, ch: u8) -> u8 {
        let mut state = self.state.borrow_mut();
        let a = self.aplw.iter().position(|&x| x == ch).unwrap_or(0);
        let off = if a <= state.curpos {
            (a + LEN_PL) - state.curpos
        } else {
            a - state.curpos
        };
        state.curpos = a;
        state.ctpos = (state.ctpos + off) % LEN_CT;
        self.actw[state.ctpos]
    }

    fn decode(&self, ch: u8) -> u8 {
        let mut state = self.state.borrow_mut();
        let a = self.actw.iter().position(|&x| x == ch).unwrap_or(0);
        let off = if a <= state.ctpos {
            (a + LEN_CT) - state.ctpos
        } else {
            a - state.ctpos
        };
        state.ctpos = a;
        state.curpos = (state.curpos + off) % LEN_PL;
        self.aplw[state.curpos]
    }

    fn reset(&self) {
        let mut state = self.state.borrow_mut();
        state.curpos = 0;
        state.ctpos = self.actw.iter().position(|&x| x == self.start).unwrap_or(0);
    }
}

impl Block for Wheatstone {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.encode(ch);
        }
        src.len()
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.reset();
        for (i, &ch) in src.iter().enumerate() {
            dst[i] = self.decode(ch);
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN_TXT: &str = "CHARLES+WHEATSTONE+HAD+A+REMARKABLY+FERTILE+MIND";
    const CIPHER_TXT: &str = "BYVLQKWAMNLCYXIOUBFLHTXGHFPBJHZZLUEZFHIVBVRTFVRQ";
    const KEY1: &str = "CIPHER";
    const KEY2: &str = "MACHINE";
    const LPLAIN_TXT: &str = "IFYOUCANREADTHISYOUEITHERDOWNLOADEDMYOWNIMPLEMENTATIONOFCHAOCIPHERORYOUWROTEONEOFYOUROWNINEITHERCASELETMEKNOWANDACCEPTMYCONGRATULATIONSX";
    const LCIPHER_TXT: &str = "PIPTIADNMEWJYKGHGVEOIZUVWEPWVKCIMWBOKXHCLDAOGCRGPMWDNJKJVJDLDQYZEBMOXBKVAVSOABVDBJWBQFQPTWFEMPQRZNTXBHVWGLHIJLGFMMLBZHXYCDUTUOCYNYQJYABYX";

    #[test]
    fn test_new_cipher() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        assert_eq!(c.aplw.len(), 27);
        assert_eq!(c.actw.len(), 26);
    }

    #[test]
    fn test_encode() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        assert_eq!(c.state.borrow().curpos, 0);
        assert_eq!(c.state.borrow().ctpos, 0);

        // Round 1
        assert_eq!(c.encode(b'C'), b'B');
        assert_eq!(c.state.borrow().curpos, 1);
        assert_eq!(c.state.borrow().ctpos, 1);

        // Round 2
        assert_eq!(c.encode(b'H'), b'Y');
        assert_eq!(c.state.borrow().curpos, 15);
        assert_eq!(c.state.borrow().ctpos, 15);

        // Round 3
        assert_eq!(c.encode(b'A'), b'V');
        assert_eq!(c.state.borrow().curpos, 2);
        assert_eq!(c.state.borrow().ctpos, 3);

        // Round 4
        assert_eq!(c.encode(b'R'), b'L');
        assert_eq!(c.state.borrow().curpos, 23);
        assert_eq!(c.state.borrow().ctpos, 24);
    }

    #[test]
    fn test_decode() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        assert_eq!(c.state.borrow().curpos, 0);
        assert_eq!(c.state.borrow().ctpos, 0);

        assert_eq!(c.decode(b'B'), b'C');
        assert_eq!(c.state.borrow().curpos, 1);
        assert_eq!(c.state.borrow().ctpos, 1);

        assert_eq!(c.decode(b'Y'), b'H');
        assert_eq!(c.state.borrow().curpos, 15);
        assert_eq!(c.state.borrow().ctpos, 15);

        assert_eq!(c.decode(b'V'), b'A');
        assert_eq!(c.state.borrow().curpos, 2);
        assert_eq!(c.state.borrow().ctpos, 3);

        assert_eq!(c.decode(b'L'), b'R');
        assert_eq!(c.state.borrow().curpos, 23);
        assert_eq!(c.state.borrow().ctpos, 24);
    }

    #[test]
    fn test_wheatstone_encrypt() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let src = PLAIN_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(dst, CIPHER_TXT.as_bytes());
    }

    #[test]
    fn test_wheatstone_encrypt_start_a() {
        let c = Wheatstone::new(b'A', KEY1, KEY2).unwrap();
        let src = PLAIN_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(String::from_utf8_lossy(&dst), "DZWORUXCALOHZYNPVDGOIMYJIGQDKIEEOVBEGINWDWSMGWSR");
    }

    #[test]
    fn test_wheatstone_encrypt_long() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let plain = helpers::fix_double(LPLAIN_TXT, 'Q');
        let src = plain.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.encrypt(&mut dst, src);
        assert_eq!(dst, LCIPHER_TXT.as_bytes());
    }

    #[test]
    fn test_wheatstone_decrypt() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let src = CIPHER_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.decrypt(&mut dst, src);
        assert_eq!(dst, PLAIN_TXT.as_bytes());
    }

    #[test]
    fn test_wheatstone_decrypt_long() {
        let c = Wheatstone::new(b'M', KEY1, KEY2).unwrap();
        let plain = helpers::fix_double(LPLAIN_TXT, 'Q');
        let src = LCIPHER_TXT.as_bytes();
        let mut dst = vec![0u8; src.len()];
        c.decrypt(&mut dst, src);
        assert_eq!(dst, plain.as_bytes());
    }
}
