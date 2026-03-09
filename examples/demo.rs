use old_crypto_rs::{ADFGVX, Block, CaesarCipher, Chaocipher, Nihilist, PlayfairCipher, Solitaire, SquareCipher, StraddlingCheckerboard, Transposition, VicCipher, Wheatstone, helpers, IrregularTransposition, SecomCipher, VigenereCipher};

const KEY_PLAIN: &str = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
const KEY_CIPHER: &str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";
const PLAIN: &str = "CETOOTESTCHIFFREAVECADFGVXETLESCLESMASTODONETSOCIALX";

const KEY1: &str = "SUBWAY";
const KEY2: &str = "ARABESQUE";
const KEY3: &str = "CIPHER";
const KEY4: &str = "MACHINE";
const KEY5: &str = "MASTODON";
const KEY6: &str = "SOCIAL";

struct Cph {
    name: String,
    c: Box<dyn Block>,
    size: usize,
}

fn main() {
    let mut allciphers: Vec<Cph> = Vec::new();

    allciphers.push(Cph {
        name: "Caesar (3)".to_string(),
        c: Box::new(CaesarCipher::new(3)),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Vigenère ({})", KEY1),
        c: Box::new(VigenereCipher::new("SUBWAY")),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Polybius Square ({})", KEY2),
        c: Box::new(SquareCipher::new(KEY2, "012345").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("Transposition ({})", KEY1),
        c: Box::new(Transposition::new(KEY1).unwrap()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Irregular. Transposition ({})", KEY1),
        c: Box::new(IrregularTransposition::new(KEY1).unwrap()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Playfair ({})", KEY2),
        c: Box::new(PlayfairCipher::new(KEY2)),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("ADFGVX ({}, {})", KEY2, KEY1),
        c: Box::new(ADFGVX::new("ARABESQUE", "SUBWAY").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("ADFGVX ({}, {})", KEY5, KEY6),
        c: Box::new(ADFGVX::new(KEY5, KEY6).unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("Straddling ({})", KEY2),
        c: Box::new(StraddlingCheckerboard::new(KEY2, "37").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("Nihilist ({}, {})", KEY2, KEY1),
        c: Box::new(Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap()),
        size: PLAIN.len() * 2,
    });

    const PERSN: &str = "89";
    const INDN: &str = "741776";
    const PHRS: &str = "IDREAMOFJEANNIEWITHT";
    const RNDN: &str = "77651";
    allciphers.push(Cph {
        name: format!("VIC ({}, {}, {}, {})", PERSN, INDN, PHRS, RNDN),
        c: Box::new(VicCipher::new(PERSN, INDN, PHRS, RNDN).unwrap()),
        size: PLAIN.len() * 2,
    });

    const SPHASS: &str = "ANTICONSTITUTIONNELLEMENT";
    const FREQ: &str = "ESANTIR";
    allciphers.push(Cph {
        name: format!("SECOM ({}, {})", SPHASS, FREQ),
        c: Box::new(SecomCipher::new(SPHASS, FREQ).unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("Chaocipher ({}, {})", KEY_PLAIN, KEY_CIPHER),
        c: Box::new(Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: "Solitaire".to_string(),
        c: Box::new(Solitaire::new_unkeyed()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Wheatstone ({}, {})", KEY3, KEY4),
        c: Box::new(Wheatstone::new(b'M', KEY3, KEY4).unwrap()),
        size: PLAIN.len(),
    });

    println!("==> Plain = \n{}\n", PLAIN);

    for cp in allciphers {
        let mut fixpt: String;
        let mut dst: Vec<u8>;
        let mut dst1: Vec<u8>;

        if cp.name == "Wheatstone" {
            fixpt = helpers::fix_double(PLAIN, 'Q');
            dst = vec![0u8; fixpt.len()];
            dst1 = vec![0u8; fixpt.len()];
        } else if cp.name == "Playfair" {
            fixpt = helpers::fix_double(PLAIN, 'X');
            let mut pt_vec = fixpt.as_bytes().to_vec();
            if pt_vec.len() % 2 == 1 {
                pt_vec.push(b'X');
            }
            fixpt = String::from_utf8_lossy(&pt_vec).to_string();
            dst = vec![0u8; fixpt.len()];
            dst1 = vec![0u8; fixpt.len()];
        } else {
            fixpt = PLAIN.to_string();
            dst = vec![0u8; cp.size];
            dst1 = vec![0u8; cp.size];
        }

        let n = cp.c.encrypt(&mut dst, fixpt.as_bytes());
        println!("==> {}", cp.name);
        println!("{}", helpers::by_n(&String::from_utf8_lossy(&dst[..n]), 5));

        let n1 = cp.c.decrypt(&mut dst1, &dst[..n]);

        let nplain = String::from_utf8_lossy(&dst1[..n1]);
        if nplain == fixpt {
            println!("decrypt ok\n");
        } else {
            println!("decrypt not ok\n{}\n{}\n", fixpt, nplain);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main() {
        main();
    }
}
