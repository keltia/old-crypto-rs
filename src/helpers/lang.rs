//! Language-specific symbol frequency definitions.
//!
//! This module provides a trait and implementations for different languages,
//! defining the most frequently used symbols in each language. These symbols
//! are used for character frequency analysis.
//!
//! Currently implemented languages:
//! - French
//! - English
//! - German
//! - Italian
//! - Spanish
//! - Dutch
//!
//! cf. <https://en.wikipedia.org/wiki/Letter_frequency#Relative_frequencies_of_letters_in_other_languages>
//!
//! NOTE: We use the WP page as a reference, except for English & French as it would probably invalidate
//! all the tests in the library.

/// Trait for languages that define their most frequently occurring symbols.
///
/// This trait allows language-specific types to provide a set of symbols
/// (as bytes) that are most commonly used in that language. This is useful
/// for frequency analysis and cryptographic applications.
///
pub trait Frequent {
    /// The most frequent symbols in the language, ordered by frequency.
    ///
    /// These symbols are represented as ASCII bytes for efficient processing.
    ///
    const SYMBOLS: &'static [u8];

    /// This is the character we use to mark a potential hole in a checkerboard.
    /// The default is a period (.), but it can be overridden by a specific `impl`.
    ///
    const HOLE: u8 = b'.';

    /// Returns the list of holes in `SYMBOLS`.
    /// Given a 10-character string, find the indices where the "." character is present
    ///
    /// It is used to derive the characters that will be the bigrams in a straddling checkerboard.
    ///
    fn holes() -> Vec<usize> {
        Self::SYMBOLS
            .iter()
            .enumerate()
            .filter_map(|(idx, x): (usize, &u8)| if *x == Self::HOLE { Some(idx )} else { None })
            .collect::<Vec<usize>>()
    }
}

// These are default implementations for the Frequent trait -----
// Mostly for checkerboards with 2 holes.

/// Represents the French language for frequency analysis.
///
/// French uses the symbol set "ESANTIRU" as its most frequent characters.
///
#[derive(Debug)]
pub struct French;

/// Represents the English language for frequency analysis.
///
/// English uses the symbol set "ATONESIR" as its most frequent characters.
///
#[derive(Debug)]
pub struct English;

/// Represents the German language for frequency analysis.
///
/// German uses the symbol set "ENSRIATD" as its most frequent characters.
///
#[derive(Debug)]
pub struct German;

/// Represents the German language for frequency analysis.
///
/// German uses the symbol set "EAIONLRT" as its most frequent characters.
///
#[derive(Debug)]
pub struct Italian;

#[derive(Debug)]
/// Represents the German language for frequency analysis.
///
/// German uses the symbol set "EAOSRNID" as its most frequent characters.
///
pub struct Spanish;

/// Represents the Dutch language for frequency analysis.
///
/// Dutch uses the symbol set "ENATIROD" as its most frequent characters.
///
#[derive(Debug)]
pub struct Dutch;

impl Frequent for French {
    const SYMBOLS: &'static [u8] = b"ESANTIRU..";
}

impl Frequent for English {
    const SYMBOLS: &'static [u8] = b"ATONESIR..";
}

impl Frequent for German {
    const SYMBOLS: &'static [u8] = b"ENSRIATD..";
}

impl Frequent for Italian {
    const SYMBOLS: &'static [u8] = b"EAIONLRT..";
}

impl Frequent for Spanish {
    const SYMBOLS: &'static [u8] = b"EAOSRNID..";
}

impl Frequent for Dutch {
    const SYMBOLS: &'static [u8] = b"ENATIROD..";
}

// These are default implementations for the Frequent trait -----
// Mostly for checkerboards with 3 holes.

/// Represents the French language for frequency analysis.
///
/// French uses the symbol set "ESANTIRU" as its most frequent characters.
///
#[derive(Debug)]
pub struct FrenchExt;

/// Represents the English language for frequency analysis.
///
/// English uses the symbol set "ATONESIR" as its most frequent characters.
///
#[derive(Debug)]
pub struct EnglishExt;

/// Represents the German language for frequency analysis.
///
/// German uses the symbol set "ENSRIATD" as its most frequent characters.
///
#[derive(Debug)]
pub struct GermanExt;

/// Represents the German language for frequency analysis.
///
/// German uses the symbol set "EAIONLRT" as its most frequent characters.
///
#[derive(Debug)]
pub struct ItalianExt;

#[derive(Debug)]
/// Represents the German language for frequency analysis.
///
/// German uses the symbol set "EAOSRNID" as its most frequent characters.
///
pub struct SpanishExt;

/// Represents the Dutch language for frequency analysis.
///
/// Dutch uses the symbol set "ENATIROD" as its most frequent characters.
///
#[derive(Debug)]
pub struct DutchExt;

impl Frequent for FrenchExt {
    const SYMBOLS: &'static [u8] = b"ESANTIR...";
}

impl Frequent for EnglishExt {
    const SYMBOLS: &'static [u8] = b"ATONESI...";
}

impl Frequent for GermanExt {
    const SYMBOLS: &'static [u8] = b"ENSRIAT...";
}

impl Frequent for ItalianExt {
    const SYMBOLS: &'static [u8] = b"EAIONLR...";
}

impl Frequent for SpanishExt {
    const SYMBOLS: &'static [u8] = b"EAOSRNI...";
}

impl Frequent for DutchExt {
    const SYMBOLS: &'static [u8] = b"ENATIRO...";
}

pub struct EnglishAlt;

impl Frequent for EnglishAlt {
    const SYMBOLS: &'static [u8] = b"ESTONIA...";
}

/// Represents the English language for frequency analysis, with holes put in different places.
/// cf. example for the VIC Cipher
///
pub struct VicEnglish;

impl Frequent for VicEnglish {
    const SYMBOLS: &'static [u8] = b"AT.ONE.SIR";
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_frequent_pattern<F: Frequent>(
        expected_symbols: &[u8],
        expected_holes: &[usize],
    ) {
        assert_eq!(F::SYMBOLS, expected_symbols);
        assert_eq!(F::SYMBOLS.len(), 10);
        assert_eq!(F::holes(), expected_holes);

        let hole_count = F::SYMBOLS
            .iter()
            .filter(|&&b| b == F::HOLE)
            .count();

        assert_eq!(hole_count, expected_holes.len());

        let mut seen = [false; 256];

        for &b in F::SYMBOLS {
            if b == F::HOLE {
                continue;
            }

            assert!(
                b.is_ascii_uppercase(),
                "non-hole symbol must be ASCII uppercase: {b:?}"
            );

            assert!(
                !seen[b as usize],
                "duplicate non-hole symbol: {}",
                b as char
            );

            seen[b as usize] = true;
        }
    }

    #[test]
    fn test_base_language_patterns() {
        assert_frequent_pattern::<French>(b"ESANTIRU..", &[8, 9]);
        assert_frequent_pattern::<English>(b"ATONESIR..", &[8, 9]);
        assert_frequent_pattern::<German>(b"ENSRIATD..", &[8, 9]);
        assert_frequent_pattern::<Italian>(b"EAIONLRT..", &[8, 9]);
        assert_frequent_pattern::<Spanish>(b"EAOSRNID..", &[8, 9]);
        assert_frequent_pattern::<Dutch>(b"ENATIROD..", &[8, 9]);
    }

    #[test]
    fn test_extended_language_patterns() {
        assert_frequent_pattern::<FrenchExt>(b"ESANTIR...", &[7, 8, 9]);
        assert_frequent_pattern::<EnglishExt>(b"ATONESI...", &[7, 8, 9]);
        assert_frequent_pattern::<GermanExt>(b"ENSRIAT...", &[7, 8, 9]);
        assert_frequent_pattern::<ItalianExt>(b"EAIONLR...", &[7, 8, 9]);
        assert_frequent_pattern::<SpanishExt>(b"EAOSRNI...", &[7, 8, 9]);
        assert_frequent_pattern::<DutchExt>(b"ENATIRO...", &[7, 8, 9]);
    }

    #[test]
    fn test_alt_language_pattern() {
        assert_frequent_pattern::<EnglishAlt>(b"ESTONIA...", &[7, 8, 9]);
        assert_frequent_pattern::<VicEnglish>(b"AT.ONE.SIR", &[2, 6]);
    }

    #[test]
    fn test_custom_hole_marker_is_respected() {
        struct CustomHole;

        impl Frequent for CustomHole {
            const SYMBOLS: &'static [u8] = b"ATONESIR--";
            const HOLE: u8 = b'-';
        }

        assert_eq!(CustomHole::holes(), vec![8, 9]);
    }
}