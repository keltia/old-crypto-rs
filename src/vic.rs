use crate::Block;
use crate::transposition::Transposition;
use crate::straddling::{StraddlingCheckerboard, ALPHABET_TXT};
use crate::helpers;

/*
Full description & test vectors: http://www.quadibloc.com/crypto/pp1324.htm
*/

#[derive(Debug)]
pub struct VicCipher {
    // First transposition
    firsttp: Transposition,
    // Second transposition
    secondtp: Transposition,
    // Straddling Checkerboard
    pub sc: StraddlingCheckerboard,
}

impl VicCipher {
    pub fn new(persn: &str, ind: &str, phrase: &str, imsg: &str) -> Result<Self, String> {
        let imsg_int = str2int(imsg);
        let ikey5 = str2int(&ind[..5]);

        let expanded = expand_key(phrase, &imsg_int, &ikey5);

        // First transposition is regular, using 'second' as key
        let firsttp = Transposition::new(&String::from_utf8_lossy(&expanded.second))?;

        // Second transposition is irregular, using 'third' as key
        let secondtp = Transposition::new(&String::from_utf8_lossy(&expanded.third))?;

        // Straddling Checkerboard using 'sckey' (converted to letters) and 'persn'
        let sc_key_str: String = expanded.sckey.iter().map(|&v| (b'0' + v) as char).collect();
        let sc = StraddlingCheckerboard::new_with_freq(&sc_key_str, persn, "ATONESIR", ALPHABET_TXT)?;

        Ok(VicCipher {
            firsttp,
            secondtp,
            sc,
        })
    }
}

#[derive(Debug)]
struct ExpandedKey {
    second: Vec<u8>,
    third: Vec<u8>,
    sckey: Vec<u8>,
}

fn expand_key(phrase: &str, imsg: &[u8], ikey5: &[u8]) -> ExpandedKey {
    let ph1 = to_numeric_one(&phrase[..10]);
    let ph2 = to_numeric_one(&phrase[10..]);

    let res = submod10(imsg, ikey5);
    let first = expand5to10(&res);

    let tmp = addmod10(&first, &ph1);
    let second = first_encode(&tmp, &ph2);

    let mut r = second.clone();
    for _ in 0..5 {
        chainadd_inplace(&mut r);
    }

    // In VIC, the key for the second transposition and the SC is derived 
    // from the 5th iteration of chain addition.
    let third = r.clone();
    let r_str: String = r.iter().map(|&b| (b + b'0') as char).collect();
    let sckey = helpers::to_numeric(&r_str);

    ExpandedKey {
        second,
        third,
        sckey,
    }
}

fn to_numeric_one(key: &str) -> Vec<u8> {
    let letters = key.as_bytes();
    let mut indexed: Vec<(usize, u8)> = letters.iter().enumerate().map(|(i, &b)| (i, b)).collect();
    indexed.sort_by_key(|&(_, b)| b);

    let mut ar = vec![0u8; letters.len()];
    for (rank, (original_idx, _)) in indexed.into_iter().enumerate() {
        ar[original_idx] = ((rank + 1) % 10) as u8;
    }
    ar
}

fn str2int(str: &str) -> Vec<u8> {
    str.bytes().map(|b| b - b'0').collect()
}

fn addmod10(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| (x + y) % 10).collect()
}

fn submod10(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b).map(|(x, y)| (x + 10 - y) % 10).collect()
}

fn chainadd_inplace(a: &mut [u8]) {
    let l = a.len();
    if l == 0 { return; }
    for i in 0..l {
        a[i] = (a[i] + a[(i + 1) % l]) % 10;
    }
}

fn chainadd(a: &[u8]) -> Vec<u8> {
    let mut b = a.to_vec();
    chainadd_inplace(&mut b);
    b
}

fn expand5to10(a: &[u8]) -> Vec<u8> {
    let mut res = a.to_vec();
    res.extend_from_slice(&chainadd(a));
    res
}

fn first_encode(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().map(|&v| b[((v as i32 + 10) % 10 - 1) as usize]).collect()
}

impl Block for VicCipher {
    fn block_size(&self) -> usize {
        1
    }

    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // VIC Encipherment:
        // 1. Straddling Checkerboard
        // 2. First Transposition (regular)
        // 3. Second Transposition (irregular)

        let mut buf_sc = vec![0u8; src.len() * 3]; // Straddling can expand
        let sc_len = self.sc.encrypt(&mut buf_sc, src);
        let sc_res = &buf_sc[..sc_len];

        let mut buf_tp1 = vec![0u8; sc_res.len()];
        let tp1_len = self.firsttp.encrypt(&mut buf_tp1, sc_res);

        self.secondtp.encrypt(dst, &buf_tp1[..tp1_len])
    }

    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // VIC Decipherment (Reverse of Encipherment):
        // 1. Second Transposition (irregular)
        // 2. First Transposition (regular)
        // 3. Straddling Checkerboard

        let mut buf_tp2 = vec![0u8; src.len()];
        let tp2_len = self.secondtp.decrypt(&mut buf_tp2, src);

        let mut buf_tp1 = vec![0u8; tp2_len];
        let tp1_len = self.firsttp.decrypt(&mut buf_tp1, &buf_tp2[..tp2_len]);

        self.sc.decrypt(dst, &buf_tp1[..tp1_len])
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::output_as_block;
    use super::*;

    #[test]
    fn test_new_cipher() {
        let _c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();
    }

    #[test]
    fn test_to_numeric_one() {
        let test_data = [
            ("IDREAMOFJE", vec![6, 2, 0, 3, 1, 8, 9, 5, 7, 4]),
            ("ANNIEWITHT", vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9]),
        ];
        for (s, r) in test_data {
            assert_eq!(to_numeric_one(s), r);
        }
    }

    #[test]
    fn test_addmod10() {
        let test_data = [
            (vec![8, 6, 1, 5, 4], vec![2, 0, 9, 5, 2], vec![0, 6, 0, 0, 6]),
            (vec![7, 7, 6, 5, 1], vec![7, 4, 1, 7, 7], vec![4, 1, 7, 2, 8]),
        ];
        for (a, b, c) in test_data {
            assert_eq!(addmod10(&a, &b), c);
        }
    }

    #[test]
    fn test_submod10() {
        let test_data = [
            (vec![8, 6, 1, 5, 4], vec![2, 0, 9, 5, 2], vec![6, 6, 2, 0, 2]),
            (vec![7, 7, 6, 5, 1], vec![7, 4, 1, 7, 7], vec![0, 3, 5, 8, 4]),
        ];
        for (a, b, c) in test_data {
            assert_eq!(submod10(&a, &b), c);
        }
    }

    #[test]
    fn test_chainadd() {
        let test_data = [
            (vec![8, 6, 1, 5, 4], vec![4, 7, 6, 9, 8]),
            (vec![7, 7, 6, 5, 1], vec![4, 3, 1, 6, 5]),
        ];
        for (a, b) in test_data {
            assert_eq!(chainadd(&a), b);
        }
    }

    #[test]
    fn test_expand5to10() {
        let test_data = [
            (vec![8, 6, 1, 5, 4], vec![8, 6, 1, 5, 4, 4, 7, 6, 9, 8]),
            (vec![7, 7, 6, 5, 1], vec![7, 7, 6, 5, 1, 4, 3, 1, 6, 5]),
            (vec![0, 3, 5, 8, 4], vec![0, 3, 5, 8, 4, 3, 8, 3, 2, 7]),
        ];
        for (a, b) in test_data {
            assert_eq!(expand5to10(&a), b);
        }
    }

    #[test]
    fn test_first_encode() {
        let r1 = vec![6, 5, 5, 1, 5, 1, 7, 8, 9, 1];
        let r2 = vec![1, 6, 7, 4, 2, 0, 5, 8, 3, 9];
        let r = vec![0, 2, 2, 1, 2, 1, 5, 8, 3, 1];
        assert_eq!(first_encode(&r1, &r2), r);
    }

    #[test]
    fn test_vic_cipher_full() {
        let c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();
        
        let pt = "HELLOWORLD";
        let mut ct = vec![0u8; 100];
        c.encrypt(&mut ct, pt.as_bytes());
        
        let ct_len = ct.iter().position(|&x| x == 0).unwrap_or(ct.len());
        let ct_trimmed = &ct[..ct_len];

        dbg!(ct_trimmed);

        let mut decrypted = vec![0u8; 100];
        c.decrypt(&mut decrypted, ct_trimmed);
        
        let res = String::from_utf8_lossy(&decrypted).trim_matches('\0').to_string();
        assert_eq!(res, pt);
    }

    #[test]
    fn test_vic_cipher_example() {
        let c = VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap();

        let pt = "WEAREPLEASEDTOHEAROFYOURSUCCESSINESTABLISHINGYOURFALSEIDENTITYYOUWILLBESENTSOMEMONEYTOCOVEREXPENSESWITHINAMONTH";
        let mut ct = vec![0u8; 200];
        c.encrypt(&mut ct, pt.as_bytes());

        let ct_len = ct.iter().position(|&x| x == 0).unwrap_or(ct.len());
        let ct_trimmed = &ct[..ct_len];

        println!("{:?}", output_as_block(&String::from_utf8_lossy(&ct_trimmed).to_string()));

        let mut decrypted = vec![0u8; 200];
        c.decrypt(&mut decrypted, ct_trimmed);

        let res = String::from_utf8_lossy(&decrypted).trim_matches('\0').to_string();
        assert_eq!(res, pt);
    }
}
