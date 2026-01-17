use old_crypto_rs::{ADFGVX, Block, CaesarCipher, Chaocipher, Nihilist, PlayfairCipher, Solitaire, SquareCipher, StraddlingCheckerboard, Transposition, VicCipher, Wheatstone, helpers, IrregularTransposition};

const KEY_PLAIN: &str = "PTLNBQDEOYSFAVZKGJRIHWXUMC";
const KEY_CIPHER: &str = "HXUCZVAMDSLKPEFJRIGTWOBNYQ";
const PLAIN: &str = "CETOOTESTCHIFFREAVECADFGVXETLESCLESMASTODONETSOCIALX";

struct Cph {
    name: String,
    c: Box<dyn Block>,
    size: usize,
}

fn main() {
    let mut allciphers: Vec<Cph> = Vec::new();

    allciphers.push(Cph {
        name: "Caesar".to_string(),
        c: Box::new(CaesarCipher::new(3)),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: "Square".to_string(),
        c: Box::new(SquareCipher::new("ARABESQUE", "012345").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: "Transp".to_string(),
        c: Box::new(Transposition::new("SUBWAY").unwrap()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: "Irr. Transp.".to_string(),
        c: Box::new(IrregularTransposition::new("SUBWAY").unwrap()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: "Chaocipher".to_string(),
        c: Box::new(Chaocipher::new(KEY_PLAIN, KEY_CIPHER).unwrap()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: "Playfair".to_string(),
        c: Box::new(PlayfairCipher::new("ARABESQUE")),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: "ADFGVX".to_string(),
        c: Box::new(ADFGVX::new("ARABESQUE", "SUBWAY").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: "ADFGVX2".to_string(),
        c: Box::new(ADFGVX::new("MASTODON", "SOCIAL").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: "Straddling".to_string(),
        c: Box::new(StraddlingCheckerboard::new("ARABESQUE", "37").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: "Nihilist".to_string(),
        c: Box::new(Nihilist::new("ARABESQUE", "SUBWAY", "37").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: "Wheatstone".to_string(),
        c: Box::new(Wheatstone::new(b'M', "CIPHER", "MACHINE").unwrap()),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: "VIC".to_string(),
        c: Box::new(VicCipher::new("89", "741776", "IDREAMOFJEANNIEWITHT", "77651").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: "Solitaire".to_string(),
        c: Box::new(Solitaire::new_unkeyed()),
        size: PLAIN.len(),
    });

    println!("==> Plain = \n{}", PLAIN);

    for cp in allciphers {
        let fixpt: String;
        let mut dst: Vec<u8>;
        let mut dst1: Vec<u8>;

        if cp.name == "Wheatstone" {
            fixpt = helpers::fix_double(PLAIN, 'Q');
            dst = vec![0u8; fixpt.len()];
            dst1 = vec![0u8; fixpt.len()];
        } else {
            fixpt = PLAIN.to_string();
            dst = vec![0u8; cp.size];
            dst1 = vec![0u8; PLAIN.len()];
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
