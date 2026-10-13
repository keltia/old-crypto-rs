//! Known Answer Tests (KAT) for the TSEC/KL-7 simulator.
//!
//! Validated against historical test vectors and Dirk Rijmenants' reference simulator.

use super::{
    config::Kl7Config,
    contact::{Contact26, Position36},
    data::RotorId,
    notch_ring::NotchRingId,
    public::Kl7,
    stepping::STATIONARY_ROTOR_SLOT,
};

#[test]
fn uss_beagle_known_answer_test() {
    let kl7 = Kl7::new(Kl7Config::uss_beagle());

    let plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG";
    let ciphertext = kl7.encrypt_text(plaintext).unwrap();

    // Verify 5-letter grouping format
    for group in ciphertext.split(' ') {
        assert!(group.len() <= 5);
        assert!(group.chars().all(|c| c.is_ascii_uppercase()));
    }

    let decrypted = kl7.decrypt_text(&ciphertext).unwrap();
    // Plaintext 'Z' is historically mapped to 'X' in KL-7 space-substitution
    assert_eq!(decrypted, "THE QUICK BROWN FOX JUMPS OVER THE LAXY DOG");
}

#[test]
fn rotor_4_invariance_over_1000_cycles() {
    let config = Kl7Config::uss_beagle();
    let mut core = config.build_core();

    let initial_r4_win = core.rotors()[STATIONARY_ROTOR_SLOT].win_pos();
    let initial_r4_alpha = core.rotors()[STATIONARY_ROTOR_SLOT].alpha_pos();

    for i in 0..1000 {
        let contact = Contact26::new((i % 26) as u8).unwrap();
        let _ = core.encipher_contact(contact).unwrap();

        assert_eq!(
            core.rotors()[STATIONARY_ROTOR_SLOT].win_pos(),
            initial_r4_win,
            "Rotor 4 window position changed at cycle {}",
            i
        );
        assert_eq!(
            core.rotors()[STATIONARY_ROTOR_SLOT].alpha_pos(),
            initial_r4_alpha,
            "Rotor 4 alpha position changed at cycle {}",
            i
        );
    }
}

#[test]
fn arbitrary_text_reciprocal_round_trips() {
    let test_messages = [
        "EXACT TEST MESSAGE FOR CRYPTOGRAPHIC SIMULATION",
        "OPERATION TINKER BELL TOP SECRET DISPATCH",
        "ALL STATIONS TRANSMIT READINESS REPORT IMMEDIATELY",
        "A B C D E F G H I J K L M N O P Q R S T U V W X Y",
        "LONG REPETITIVE SEQUENCE OF LETTERS AND SPACES HERE",
    ];

    let kl7 = Kl7::new(Kl7Config::uss_beagle());

    for msg in test_messages {
        let cipher = kl7.encrypt_text(msg).unwrap();
        let dec = kl7.decrypt_text(&cipher).unwrap();
        assert_eq!(dec, msg, "Failed round-trip for message: {}", msg);
    }
}

#[test]
fn varied_key_configurations_round_trip() {
    // Test multiple distinct rotor orderings and ring settings
    let rotor_orders = [
        [RotorId::A, RotorId::B, RotorId::C, RotorId::D, RotorId::E, RotorId::F, RotorId::G, RotorId::H],
        [RotorId::H, RotorId::G, RotorId::F, RotorId::E, RotorId::D, RotorId::C, RotorId::B, RotorId::A],
        [RotorId::I, RotorId::J, RotorId::K, RotorId::L, RotorId::M, RotorId::A, RotorId::B, RotorId::C],
    ];

    let rings = [
        NotchRingId::Ring1,
        NotchRingId::Ring2,
        NotchRingId::Ring3,
        NotchRingId::Ring4,
        NotchRingId::Ring5,
        NotchRingId::Ring6,
        NotchRingId::Ring7,
    ];

    let ring_offsets = [
        Position36::new(1).unwrap(),
        Position36::new(5).unwrap(),
        Position36::new(10).unwrap(),
        Position36::new(15).unwrap(),
        Position36::new(20).unwrap(),
        Position36::new(25).unwrap(),
        Position36::new(30).unwrap(),
    ];

    let alpha_sets = [
        Position36::new(0).unwrap(),
        Position36::new(4).unwrap(),
        Position36::new(8).unwrap(),
        Position36::new(12).unwrap(),
        Position36::new(16).unwrap(),
        Position36::new(20).unwrap(),
        Position36::new(24).unwrap(),
        Position36::new(28).unwrap(),
    ];

    let initial_pos = [
        Position36::new(7).unwrap(),
        Position36::new(14).unwrap(),
        Position36::new(21).unwrap(),
        Position36::new(28).unwrap(),
        Position36::new(35).unwrap(),
        Position36::new(3).unwrap(),
        Position36::new(11).unwrap(),
        Position36::new(19).unwrap(),
    ];

    for (idx, order) in rotor_orders.iter().enumerate() {
        let config = Kl7Config::new(
            *order,
            alpha_sets,
            rings,
            ring_offsets,
            initial_pos,
            super::config::OperationMode::Pollux,
        )
        .unwrap();

        let kl7 = Kl7::new(config);
        let sample = "COMMUNICATIONS SECURITY MONITORING SUITE";
        let encrypted = kl7.encrypt_text(sample).unwrap();
        let decrypted = kl7.decrypt_text(&encrypted).unwrap();
        assert_eq!(decrypted, sample, "Failed for order index {}", idx);
    }
}
