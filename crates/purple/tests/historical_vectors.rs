//! Historical known-answer tests for the December 1941 fourteen-part message.
//!
//! Source: Wes Freeman, Geoff Sullivan and Frode Weierud,
//! "PURPLE Revealed: Simulation and Computer-aided Cryptanalysis of
//! Angooki Taipu B", Cryptologia 27(1), 2003, pp. 26–27,
//! Figure 18 and the first three CT/PT rows on page 27.
//! https://cryptocellar.org/pubs/PurpleRevealed.pdf
//!
//! The PT rows are *raw machine plaintext*, not the authors' corrected
//! Japanese romanization (HS) or English translation (FT). No spaces or
//! formatting characters are fed into the machine; each letter advances it.

use purple::{
    PurpleAlphabet, PurpleMachine, PurpleMotion, SwitchPosition, TwentiesSwitchId,
};

const ALPHABET: &str = "NOKTYUXEQLHBRMPDICJASVWGZF";

// Three consecutive, ungarbled CT/PT rows from page 27 (96 letters).
// Keep their original row boundaries visible to ease checking the source.
const CIPHERTEXT_ROWS: [&[u8]; 3] = [
    b"ZTXODNWKCCMAVNZXYWEETUQTCIMN",
    b"VEUVIWBLUAXRRTLVARGNTPCNOIUP",
    b"JLCIVRTPJKAUHVMUDTHKTXYZELQTVWGBUHFAWSHU",
];
const PLAINTEXT_ROWS: [&[u8]; 3] = [
    b"FOVTATAKIDASINIMUIMINOMOXIWO",
    b"IRUBESIFYXXFCKZZRDXOOVBTNFYX",
    b"FAEMEMORANDUMFIOFOVOOMOJIBAKARIFYXRAICCY",
];

fn historical_machine() -> PurpleMachine {
    use TwentiesSwitchId::{One, Three, Two};
    let pos = |n| SwitchPosition::new(n).unwrap();
    // Part 1, message indicator 15739: sixes 9; physical twenties
    // switches #1/#2/#3 at 1/24/6; motion fast/middle/slow = 2/3/1.
    PurpleMachine::new(
        PurpleAlphabet::new(ALPHABET).unwrap(),
        pos(9),
        [pos(1), pos(24), pos(6)],
        PurpleMotion::new(Two, Three, One).unwrap(),
    )
}

fn combined(rows: &[&[u8]]) -> Vec<u8> {
    rows.iter().flat_map(|row| row.iter().copied()).collect()
}

#[test]
fn historical_decipherment_matches_published_raw_plaintext() {
    let mut machine = historical_machine();
    let mut produced = Vec::new();
    for (row, expected) in CIPHERTEXT_ROWS.iter().zip(PLAINTEXT_ROWS) {
        let actual = machine.decipher_bytes(row).unwrap();
        assert_eq!(actual, expected, "historical PT mismatch at offset {}", produced.len());
        produced.extend(actual);
    }
    assert_eq!(produced.len(), 96);
    assert_eq!(produced, combined(&PLAINTEXT_ROWS));
}

#[test]
fn historical_encipherment_matches_published_ciphertext() {
    let plaintext = combined(&PLAINTEXT_ROWS);
    let ciphertext = combined(&CIPHERTEXT_ROWS);
    assert_eq!(plaintext.len(), 96);
    assert_eq!(ciphertext.len(), 96);
    assert_eq!(historical_machine().encipher_bytes(&plaintext).unwrap(), ciphertext);
}

#[test]
fn historical_first_three_letters_match_published_path_and_stepping() {
    let mut machine = historical_machine();
    assert_eq!(machine.decipher_bytes(b"ZTX").unwrap(), b"FOV");
    assert_eq!(machine.state().sixes().number(), 12);
    assert_eq!(
        machine.state().twenties().map(SwitchPosition::number),
        [1, 2, 6],
    );
}

#[test]
fn historical_streaming_and_reset_preserve_exact_output() {
    let ciphertext = combined(&CIPHERTEXT_ROWS);
    let plaintext = combined(&PLAINTEXT_ROWS);
    let mut machine = historical_machine();
    let mut actual = Vec::new();
    // Split inside the first and second published rows, not only at row breaks.
    for chunk in ciphertext.chunks(13) {
        actual.extend(machine.decipher_bytes(chunk).unwrap());
    }
    assert_eq!(actual, plaintext);
    machine.reset();
    assert_eq!(machine.decipher_bytes(&ciphertext).unwrap(), plaintext);
}
