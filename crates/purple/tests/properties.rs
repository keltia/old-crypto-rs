//! Deterministic property tests for PURPLE's electrical and stepping behavior.
//!
//! No random-number dependency: the LCG and test-case schedule are fixed so
//! failures can be reproduced from a case number.

use purple::{
    PurpleAlphabet, PurpleConfig, PurpleMotion, PurpleStepping, SwitchPosition,
    TwentiesSwitchId,
};
use TwentiesSwitchId::{One, Three, Two};

const MOTIONS: [[TwentiesSwitchId; 3]; 6] = [
    [One, Two, Three],
    [One, Three, Two],
    [Two, One, Three],
    [Two, Three, One],
    [Three, One, Two],
    [Three, Two, One],
];

fn p(n: u8) -> SwitchPosition {
    SwitchPosition::new(n).unwrap()
}

fn motion(ids: [TwentiesSwitchId; 3]) -> PurpleMotion {
    PurpleMotion::new(ids[0], ids[1], ids[2]).unwrap()
}

fn config(seed: u32, ids: [TwentiesSwitchId; 3]) -> PurpleConfig {
    let position = |shift: u32| p(((seed.wrapping_add(shift) % 25) + 1) as u8);
    PurpleConfig::new(
        PurpleAlphabet::new("NOKTYUXEQLHBRMPDICJASVWGZF").unwrap(),
        position(0),
        [position(7), position(13), position(19)],
        motion(ids),
    )
}

fn message(seed: u32, len: usize) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            b'A' + ((x >> 16) % 26) as u8
        })
        .collect()
}

#[test]
fn stepping_moves_sixes_and_exactly_one_twenty_for_every_character() {
    for (case, ids) in MOTIONS.into_iter().enumerate() {
        let cfg = config(case as u32 * 11, ids);
        let mut stepping = PurpleStepping::new(cfg.sixes(), cfg.twenties(), cfg.motion());
        for index in 0..2_000 {
            let old_sixes = stepping.sixes();
            let old_twenty = stepping.twenties();
            let selected = stepping.step();
            assert_eq!(stepping.sixes(), old_sixes.advanced(), "motion {case}, step {index}");
            for id in [One, Two, Three] {
                let expected = if id == selected {
                    old_twenty[id.index()].advanced()
                } else {
                    old_twenty[id.index()]
                };
                assert_eq!(stepping.twenties_position(id), expected, "motion {case}, step {index}, switch {id:?}");
            }
        }
    }
}

#[test]
fn complete_stepping_cycle_for_every_motion() {
    // The period is 25^3 = 15,625, not 25^4: one twenties switch
    // moves each character, with the sixes position controlling turnovers.
    for (case, ids) in MOTIONS.into_iter().enumerate() {
        let cfg = config((case * 3) as u32, ids);
        let initial = PurpleStepping::new(cfg.sixes(), cfg.twenties(), cfg.motion());
        let mut stepping = initial;
        for step in 1..=15_625 {
            stepping.step();
            if step != 15_625 {
                assert_ne!(stepping, initial, "motion {case}: early repeat at {step}");
            }
        }
        assert_eq!(stepping, initial, "motion {case}: cycle didn't close");
    }
}

#[test]
fn encryption_is_reversible_and_streaming_is_equivalent_across_settings() {
    for (motion_idx, ids) in MOTIONS.into_iter().enumerate() {
        for position_case in 0..8u32 {
            let case = (motion_idx as u32) * 8 + position_case;
            let cfg = config(case * 17, ids);
            let input = message(case ^ 0x51A7_6B2D, 600 + position_case as usize * 13);
            let mut enc = cfg.build_machine();
            let ciphertext = enc.encipher_bytes(&input).unwrap();
            assert_eq!(ciphertext.len(), input.len(), "case {case}");

            let mut dec = cfg.build_machine();
            assert_eq!(dec.decipher_bytes(&ciphertext).unwrap(), input, "case {case}");
            assert_eq!(enc.state(), dec.state(), "case {case}: position drift");

            let split_at = (case as usize * 37 + 1) % input.len();
            let mut split = cfg.build_machine();
            let mut actual = split.encipher_bytes(&input[..split_at]).unwrap();
            actual.extend(split.encipher_bytes(&input[split_at..]).unwrap());
            assert_eq!(actual, ciphertext, "case {case}: streaming differs");
            assert_eq!(split.state(), enc.state(), "case {case}: state differs");

            split.reset();
            assert_eq!(split.encipher_bytes(&input).unwrap(), ciphertext, "case {case}: reset differs");
        }
    }
}

#[test]
fn invalid_character_does_not_consume_an_extra_step() {
    let cfg = config(19, MOTIONS[3]);
    let mut machine = cfg.build_machine();
    let prefix = b"SOMEPREFIX";
    machine.encipher_bytes(prefix).unwrap();
    let before_invalid = machine.state();
    assert!(machine.encipher(b'!').is_err());
    assert_eq!(machine.state(), before_invalid);

    let mut reference = cfg.build_machine();
    reference.encipher_bytes(prefix).unwrap();
    assert_eq!(machine.encipher(b'Z').unwrap(), reference.encipher(b'Z').unwrap());
    assert_eq!(machine.state(), reference.state());
}
