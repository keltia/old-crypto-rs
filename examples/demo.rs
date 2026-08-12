use old_crypto_rs::{ADFGVXCipher, Block, CaesarCipher, Chaocipher, Nihilist, PlayfairCipher, Solitaire, Transposition, VicCipher, Wheatstone, helpers, IrregularTransposition, SecomCipher, VigenereCipher, AutokeyCipher, AutocryptCipher, PolybiusCipher, EnglishStraddling};
#[cfg(feature = "sigaba")]
use old_crypto_rs::{
    Sigaba, SigabaConfig, SigabaIndexPosition, SigabaIndexRotorId,
    SigabaIndexRotorSetting, SigabaLargeRotorSetting, SigabaOrientation,
    SigabaRotorId, SigabaRotorPosition, SigabaRotorSet,
};
use old_crypto_rs::helpers::{shuffle, transp_shuffle, English, French, Horizontal, LatinSC, REGULAR_ALPHABET};

#[cfg(feature = "fialka")]
use old_crypto_rs::{Fialka, FialkaCommutator, FialkaConfig, FialkaRotorSeries};

use eyre::Result;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;


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
    /// Name of the cipher
    name: String,
    /// Cipher
    c: Box<dyn Block>,
    /// Relative size of the ciphertext
    size: usize,
}

fn main() -> Result<()>{
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let mut allciphers: Vec<Cph> = Vec::new();

    allciphers.push(Cph {
        name: "Caesar (3)".to_string(),
        c: Box::new(CaesarCipher::new(3)),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Vigenère ({})", KEY1),
        c: Box::new(VigenereCipher::new(KEY1)),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Autokey Vigenère ({})", KEY1),
        c: Box::new(AutokeyCipher::new(KEY1)),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Autocrypt Vigenère ({})", KEY1),
        c: Box::new(AutocryptCipher::new(KEY1)),
        size: PLAIN.len(),
    });

    allciphers.push(Cph {
        name: format!("Polybius Square ({})", KEY2),
        c: Box::new(PolybiusCipher::new(KEY2).unwrap()),
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
        c: Box::new(ADFGVXCipher::new("ARABESQUE", "SUBWAY").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("ADFGVX ({}, {})", KEY5, KEY6),
        c: Box::new(ADFGVXCipher::new(KEY5, KEY6).unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("Straddling ({})", KEY2),
        c: Box::new(EnglishStraddling::new(KEY2, "37").unwrap()),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("Nihilist ({}, {})", KEY2, KEY1),
        c: Box::new(Nihilist::<LatinSC, English>::new("ARABESQUE", "SUBWAY", "37").unwrap()),
        size: PLAIN.len() * 2,
    });

    const INDN: &str = "741776";
    const PHRS: &str = "IDREAMOFJEANNIEWITHT";
    const RNDN: &str = "77651";
    const PERSN: usize = 6;

    allciphers.push(Cph {
        name: format!("VIC ({}, {}, {})", INDN, PHRS, RNDN),
        c: Box::new(VicCipher::<LatinSC, Horizontal, English>::new(INDN, PHRS, RNDN, PERSN)?),
        size: PLAIN.len() * 2,
    });

    const SPHASS: &str = "IDREAMOFJEANNIEWITHT";
    allciphers.push(Cph {
        name: format!("SECOM ({}, English)", SPHASS),
        c: Box::new(SecomCipher::<English>::new(SPHASS)?),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("SECOM ({}, French)", SPHASS),
        c: Box::new(SecomCipher::<French>::new(SPHASS)?),
        size: PLAIN.len() * 2,
    });

    allciphers.push(Cph {
        name: format!("Chaocipher official ({}, {})", KEY_PLAIN, KEY_CIPHER),
        c: Box::new(Chaocipher::new(KEY_PLAIN, KEY_CIPHER)?),
        size: PLAIN.len(),
    });

    let key3 = shuffle(KEY3, REGULAR_ALPHABET);
    let key4 = shuffle(KEY4, REGULAR_ALPHABET);
    allciphers.push(Cph {
        name: format!("Chaocipher keywords ({}, {})", KEY3, KEY4),
        c: Box::new(Chaocipher::new(&key3, &key4).unwrap()),
        size: PLAIN.len(),
    });

    let key3 = transp_shuffle(KEY3, REGULAR_ALPHABET)?;
    let key4 = transp_shuffle(KEY4, REGULAR_ALPHABET)?;
    allciphers.push(Cph {
        name: format!("Chaocipher keywords ({}, {}) transp shuffle" , KEY3, KEY4),
        c: Box::new(Chaocipher::new(&key3, &key4).unwrap()),
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
        let fixpt: String;
        let mut dst: Vec<u8>;
        let mut dst1: Vec<u8>;

        println!("==> {}", cp.name);
        if cp.name.starts_with("Wheatstone") {
            // Wheatstone can't process double letters at all, regardless of boundary
            //
            fixpt = helpers::fix_double(PLAIN, 'Q');
            println!("Wheatstone will process (Q) in plaintext:\n{fixpt}\n");
            dst = vec![0u8; fixpt.len()];
            dst1 = vec![0u8; fixpt.len()];
        } else if cp.name.starts_with("Playfair") {
            // Playfair handles fix_double_aligned internally, but we need to know
            // what it will produce for comparison
            //
            let temp = PLAIN.to_ascii_uppercase().replace('J', "I");
            let temp_fixed = helpers::fix_double_aligned(&temp, 'X');
            let mut pt_vec = temp_fixed.as_bytes().to_vec();
            if pt_vec.len() % 2 == 1 {
                pt_vec.push(b'X');
            }
            let expected = String::from_utf8_lossy(&pt_vec).to_string();
            println!("Playfair will process (X): {}\n", expected);

            // But we pass the original PLAIN to encrypt
            //
            fixpt = expected;
            dst = vec![0u8; cp.size];
            dst1 = vec![0u8; cp.size];
        } else {
            fixpt = PLAIN.to_string();
            dst = vec![0u8; cp.size];
            dst1 = vec![0u8; fixpt.len()];
        }

        // For Playfair, always pass PLAIN since it does its own processing
        let input_text = if cp.name.starts_with("Playfair") { PLAIN } else { &fixpt };
        let n = cp.c.encrypt(&mut dst, input_text.as_bytes());
        println!("{}", helpers::by_n(&String::from_utf8_lossy(&dst[..n]), 5));

        let n1 = cp.c.decrypt(&mut dst1, &dst[..n]);

        let nplain = String::from_utf8_lossy(&dst1[..n1]);
        if nplain == fixpt {
            println!("decrypt ok\n");
        } else {
            println!("decrypt not ok (fixpt len={}, nplain len={})", fixpt.len(), nplain.len());
            println!("Expected: {}", fixpt);
            println!("Got:      {}\n", nplain);
        }
    }

    #[cfg(feature = "fialka")]
    demo_fialka()?;
    #[cfg(feature = "sigaba")]
    demo_sigaba()?;
    Ok(())
}

#[cfg(feature = "fialka")]
fn demo_fialka() -> Result<()> {
    const FIALKA_PLAIN: &str = "СЕКРЕТНОЕСООБЩЕНИЕ";

    let config = FialkaConfig::overall_base(
        FialkaRotorSeries::Polish3K,
        FialkaCommutator::identity(),
    );
    let fialka = Fialka::new(config);
    let ciphertext = fialka.encrypt_russian_letters(FIALKA_PLAIN)?;
    let recovered = fialka.decrypt_russian_letters(&ciphertext)?;

    println!("==> Fialka M-125-3 (Polish 3K, overall base)");
    println!("Plain:  {FIALKA_PLAIN}");
    println!("Cipher: {ciphertext}");
    assert_eq!(recovered, FIALKA_PLAIN);
    println!("decrypt ok\n");

    const FIALKA_LATIN_PLAIN: &str = "TAJNASPRAVA2578";
    let config = FialkaConfig::overall_base(
        FialkaRotorSeries::Czechoslovak6K,
        FialkaCommutator::identity(),
    );
    let fialka = Fialka::new(config);
    let ciphertext = fialka.encrypt_latin(FIALKA_LATIN_PLAIN)?;
    let recovered = fialka.decrypt_latin(&ciphertext)?;

    println!("==> Fialka M-125-3 (Czechoslovak 6K, Latin, overall base)");
    println!("Plain:  {FIALKA_LATIN_PLAIN}");
    println!("Cipher: {ciphertext}");
    assert_eq!(recovered, FIALKA_LATIN_PLAIN);
    println!("decrypt ok\n");

    const FIALKA_NUMERIC_PLAIN: &str = "31415926535897932384";
    let ciphertext = fialka.encrypt_numeric(FIALKA_NUMERIC_PLAIN)?;
    let recovered = fialka.decrypt_numeric(&ciphertext)?;

    println!("==> Fialka M-125-3 (30<->10 numbers-only mode)");
    println!("Plain:  {FIALKA_NUMERIC_PLAIN}");
    println!("Cipher: {ciphertext}");
    assert_eq!(recovered, FIALKA_NUMERIC_PLAIN);
    println!("decrypt ok\n");

    Ok(())
}



#[cfg(feature = "sigaba")]
fn sigaba_reference_config() -> Result<SigabaConfig> {
    let large = |id: u8| -> Result<SigabaLargeRotorSetting> {
        Ok(SigabaLargeRotorSetting::new(
            SigabaRotorId::new(id).ok_or_else(|| eyre::eyre!("invalid SIGABA rotor id"))?,
            SigabaRotorPosition::new(14)
                .ok_or_else(|| eyre::eyre!("invalid SIGABA rotor position"))?,
            SigabaOrientation::Normal,
        ))
    };
    let index = |id: u8| -> Result<SigabaIndexRotorSetting> {
        Ok(SigabaIndexRotorSetting::new(
            SigabaIndexRotorId::new(id)
                .ok_or_else(|| eyre::eyre!("invalid SIGABA index rotor id"))?,
            SigabaIndexPosition::ZERO,
        ))
    };

    Ok(SigabaConfig::new(
        SigabaRotorSet::PekelneyReference,
        [large(0)?, large(1)?, large(2)?, large(3)?, large(4)?],
        [large(5)?, large(6)?, large(7)?, large(8)?, large(9)?],
        [index(0)?, index(1)?, index(2)?, index(3)?, index(4)?],
    )?)
}

#[cfg(feature = "sigaba")]
fn demo_sigaba() -> Result<()> {
    const PLAIN: &str = "HELLO WORLD";
    const EXPECTED: &str = "FLQGFQUEQCH";

    let sigaba = Sigaba::new(sigaba_reference_config()?);
    let ciphertext = sigaba.encrypt_text(PLAIN)?;
    let recovered = sigaba.decrypt_text(&ciphertext)?;

    println!("==> SIGABA CSP-889 (Pekelney reference key)");
    println!("Plain:  {PLAIN}");
    println!("Cipher: {ciphertext}");
    assert_eq!(ciphertext, EXPECTED);
    assert_eq!(recovered, PLAIN);
    println!("decrypt ok\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_main() {
        main();
    }
}
