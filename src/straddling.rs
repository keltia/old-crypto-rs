use crate::Block;
use crate::helpers;
use std::collections::HashMap;

pub const ALPHABET_TXT: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ/-";
const ALL_CIPHER: &[u8] = b"0123456789";

#[derive(Debug)]
pub struct StraddlingCheckerboard {
    key: String,
    longc: Vec<u8>,
    #[allow(dead_code)]
    shortc: Vec<u8>,
    full: String,
    pub enc: HashMap<u8, String>,
    pub dec: HashMap<String, u8>,
}

impl StraddlingCheckerboard {
    pub fn new(key: &str, chrs: &str) -> Result<Self, String> {
        Self::new_with_freq(key, chrs, "ESANTIRU", ALPHABET_TXT)
    }

    pub fn new_with_freq(key: &str, chrs: &str, freq_str: &str, alphabet: &str) -> Result<Self, String> {
        if key.is_empty() {
            return Err("key can not be empty".to_string());
        }
        if chrs.len() < 2 {
            return Err("longc must have at least 2 characters".to_string());
        }

        let longc = vec![chrs.as_bytes()[0], chrs.as_bytes()[1]];
        let full = if key.is_empty() {
            alphabet.to_string()
        } else {
            helpers::shuffle(key, alphabet)
        };
        // Remove digits from full if they were added by the key but not in the alphabet
        let full_clean: String = full.chars().filter(|&c| alphabet.contains(c)).collect();
        let shortc = Self::extract(ALL_CIPHER, &longc);

        let mut c = StraddlingCheckerboard {
            key: key.to_string(),
            full: full_clean,
            longc,
            shortc: shortc.clone(),
            enc: HashMap::new(),
            dec: HashMap::new(),
        };
        c.expand_key(shortc, freq_str.as_bytes());
        Ok(c)
    }

    fn extract(set: &[u8], two: &[u8]) -> Vec<u8> {
        set.iter().cloned().filter(|&x| !two.contains(&x)).collect()
    }

    fn times10(c: u8) -> Vec<String> {
        let mut tmp = Vec::with_capacity(10);
        if c == b'0' {
            for &b in ALL_CIPHER {
                tmp.push((b as char).to_string());
            }
        } else {
            for &b in ALL_CIPHER {
                let mut s = (c as char).to_string();
                s.push(b as char);
                tmp.push(s);
            }
        }
        tmp
    }

    fn set_times10(set: &[u8]) -> Vec<String> {
        let mut longc = Vec::with_capacity(20);
        longc.extend(Self::times10(set[0]));
        longc.extend(Self::times10(set[1]));
        longc
    }

    fn expand_key(&mut self, shortc: Vec<u8>, freq: &[u8]) {
        let longc = Self::set_times10(&self.longc);

        let mut i = 0;
        let mut j = 0;
        for &ch in self.full.as_bytes() {
            if freq.contains(&ch) {
                if i < shortc.len() {
                    let s = (shortc[i] as char).to_string();
                    self.enc.insert(ch, s.clone());
                    self.dec.insert(s, ch);
                    i += 1;
                }
            } else {
                if j < longc.len() {
                    let s = longc[j].clone();
                    self.enc.insert(ch, s.clone());
                    self.dec.insert(s, ch);
                    j += 1;
                }
            }
        }
    }
}

impl Block for StraddlingCheckerboard {
    fn block_size(&self) -> usize {
        self.key.len()
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut offset = 0;
        for &ch in src {
            if ch.is_ascii_digit() {
                let marker = self.enc.get(&b'/').unwrap();
                dst[offset..offset + marker.len()].copy_from_slice(marker.as_bytes());
                offset += marker.len();
                
                dst[offset] = ch;
                dst[offset + 1] = ch;
                offset += 2;
                
                dst[offset..offset + marker.len()].copy_from_slice(marker.as_bytes());
                offset += marker.len();
            } else if let Some(s) = self.enc.get(&ch) {
                let s_bytes = s.as_bytes();
                dst[offset..offset + s_bytes.len()].copy_from_slice(s_bytes);
                offset += s_bytes.len();
            }
        }
        offset
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        let mut pt_offset = 0;
        let mut i = 0;
        while i < src.len() {
            let ch = src[i];
            let mut ptc;
            let mut db_str = String::new();

            if self.longc.contains(&ch) {
                if i + 1 < src.len() {
                    db_str.push(ch as char);
                    db_str.push(src[i + 1] as char);
                    ptc = *self.dec.get(&db_str).unwrap_or(&0);
                    i += 2;
                } else {
                    i += 1;
                    continue;
                }
            } else {
                db_str.push(ch as char);
                ptc = *self.dec.get(&db_str).unwrap_or(&0);
                i += 1;
            }

            if ptc == b'/' {
                if i + 4 <= src.len() {
                    let numb = &src[i..i+4];
                    if numb[0] == numb[1] {
                        let row_check = (numb[2] as char).to_string() + &(numb[3] as char).to_string();
                        if row_check == db_str || self.dec.get(&row_check) == Some(&b'/') {
                            ptc = numb[0];
                            i += 4;
                        }
                    }
                }
            }
            if ptc != 0 {
                dst[pt_offset] = ptc;
                pt_offset += 1;
            }
        }
        pt_offset
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_cipher() {
        let c = StraddlingCheckerboard::new("ARABESQUE", "89").unwrap();
        assert_eq!(c.full, "ACKVRDLWBFMXEGNYSHOZQIP/UJT-");
        assert_eq!(c.shortc, b"01234567");
        assert_eq!(c.longc, b"89");
    }

    #[test]
    fn test_new_cipher_bad_keys() {
        assert!(StraddlingCheckerboard::new("ARABESQUE", "").is_err());
        assert!(StraddlingCheckerboard::new("", "89").is_err());
    }

    #[test]
    fn test_expand_key() {
        let c = StraddlingCheckerboard::new("ARABESQUE", "89").unwrap();
        assert_eq!(c.enc.get(&b'V').unwrap(), "82");
        assert_eq!(c.enc.get(&b'K').unwrap(), "81");
        assert_eq!(c.enc.get(&b'A').unwrap(), "0");
        assert_eq!(c.enc.get(&b'E').unwrap(), "2");
        assert_eq!(c.dec.get("82").unwrap(), &b'V');
        assert_eq!(c.dec.get("0").unwrap(), &b'A');
    }

    #[test]
    fn test_times10() {
        assert_eq!(StraddlingCheckerboard::times10(b'3'), vec!["30", "31", "32", "33", "34", "35", "36", "37", "38", "39"]);
        assert_eq!(StraddlingCheckerboard::times10(b'1'), vec!["10", "11", "12", "13", "14", "15", "16", "17", "18", "19"]);
    }

    #[test]
    fn test_extract() {
        assert_eq!(StraddlingCheckerboard::extract(ALL_CIPHER, b"25"), b"01346789");
        assert_eq!(StraddlingCheckerboard::extract(ALL_CIPHER, b"16"), b"02345789");
        assert_eq!(StraddlingCheckerboard::extract(ALL_CIPHER, b"42"), b"01356789");
    }

    #[test]
    fn test_straddling_encrypt() {
        let test_data = [
            ("ARABESQUE", "89", "ATTACKAT2AM", "0770808107972297088"),
            ("ARABESQUE", "36", "ATTACKAT2AM", "0990303109672267038"),
            ("ARABESQUE", "37", "IFYOUCANREADTHIS", "6377173830041203397265"),
            ("ARABESQUE", "89", "ATTACK", "07708081"),
            ("SUBWAY", "89", "TOLKIEN", "6819388137"),
            ("PORTABLE", "89", "RETRIBUTION", "1721693526840"),
        ];
        for (key, chrs, pt, ct) in test_data {
            let c = StraddlingCheckerboard::new(key, chrs).unwrap();
            let mut dst = vec![0u8; 100];
            c.encrypt(&mut dst, pt.as_bytes());
            let sct = String::from_utf8_lossy(&dst).trim_matches('\0').to_string();
            assert_eq!(sct, ct);
        }
    }

    #[test]
    fn test_straddling_decrypt() {
        let test_data = [
            ("ARABESQUE", "89", "ATTACKAT2AM", "0770808107972297088"),
            ("ARABESQUE", "36", "ATTACKAT2AM", "0990303109672267038"),
            ("ARABESQUE", "37", "IFYOUCANREADTHIS", "6377173830041203397265"),
            ("ARABESQUE", "89", "ATTACK", "07708081"),
            ("SUBWAY", "89", "TOLKIEN", "6819388137"),
            ("PORTABLE", "89", "RETRIBUTION", "1721693526840"),
        ];
        for (key, chrs, pt, ct) in test_data {
            let c = StraddlingCheckerboard::new(key, chrs).unwrap();
            let mut dst = vec![0u8; 100];
            c.decrypt(&mut dst, ct.as_bytes());
            let spt = String::from_utf8_lossy(&dst).trim_matches('\0').to_string();
            assert_eq!(spt, pt);
        }
    }
}
