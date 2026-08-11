//! Frozen electrical path of the Fialka M-125-3.
//!
//! This module assembles the components already validated independently:
//!
//! keyboard -> commutator -> entry disc -> rotors 10..1 -> reflector
//!          -> rotors 1..10 -> entry disc -> inverse commutator -> output
//!
//! Rotor stepping is deliberately absent here.  Step 11 will couple this
//! electrical transform to the mechanical drum only after the frozen path has
//! its own exhaustive tests.

use super::{
    CipherDirection, Commutator, Contact, EntryDisc, ReflectorResult, ReflectorUnit, RotorDrum,
    RotorSlot,
};

/// Complete 30-contact electrical machine with rotor movement disabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FialkaCore {
    drum: RotorDrum,
    commutator: Commutator,
    entry_disc: EntryDisc,
    reflector: ReflectorUnit,
}

impl FialkaCore {
    /// Assemble a frozen Fialka electrical path.
    #[must_use]
    pub(crate) fn new(drum: RotorDrum, commutator: Commutator) -> Self {
        Self {
            drum,
            commutator,
            entry_disc: EntryDisc::new(),
            reflector: ReflectorUnit::new(),
        }
    }

    /// Process one contact in coding mode without stepping the drum.
    #[must_use]
    pub(crate) fn encode_contact(&self, input: Contact) -> Contact {
        self.process_contact(input, CipherDirection::Encode)
    }

    /// Process one contact in decoding mode without stepping the drum.
    #[must_use]
    pub(crate) fn decode_contact(&self, input: Contact) -> Contact {
        self.process_contact(input, CipherDirection::Decode)
    }

    /// Process one contact using the selected MODE-switch direction.
    #[must_use]
    pub(crate) fn process_contact(&self, input: Contact, direction: CipherDirection) -> Contact {
        let original_input = input;

        let mut contact = self.commutator.keyboard_to_drum(input);
        contact = self.entry_disc.card_to_drum(contact);

        // The keyboard is at the right of the drum.  Physical slots are stored
        // 1..10 from left to right, so the outward traversal reaches slot 10
        // first and slot 1 last.
        for slot in RotorSlot::ALL.into_iter().rev() {
            contact = self.drum.rotor(slot).right_to_left(contact);
        }

        match self.reflector.transform(contact, direction, original_input) {
            ReflectorResult::Plaintext(contact) => contact,
            ReflectorResult::ReturnThroughDrum(mut contact) => {
                // Return from the reflector crosses the physical slots 1..10.
                for slot in RotorSlot::ALL {
                    contact = self.drum.rotor(slot).left_to_right(contact);
                }

                contact = self.entry_disc.drum_to_card(contact);
                self.commutator.drum_to_output(contact)
            }
        }
    }

    #[must_use]
    pub(crate) const fn drum(&self) -> &RotorDrum {
        &self.drum
    }
}

/// Stateful Fialka machine.
///
/// Each contact is transformed using the current drum state and the drum is
/// advanced exactly once afterwards, matching the documented M-125-3 keypress
/// sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FialkaMachine {
    core: FialkaCore,
}

impl FialkaMachine {
    /// Assemble a stateful machine from a drum and punched-card commutator.
    #[must_use]
    pub(crate) fn new(drum: RotorDrum, commutator: Commutator) -> Self {
        Self {
            core: FialkaCore::new(drum, commutator),
        }
    }

    /// Process one contact in coding mode, then advance the drum once.
    pub(crate) fn encode_contact(&mut self, input: Contact) -> Contact {
        self.process_contact(input, CipherDirection::Encode)
    }

    /// Process one contact in decoding mode, then advance the drum once.
    pub(crate) fn decode_contact(&mut self, input: Contact) -> Contact {
        self.process_contact(input, CipherDirection::Decode)
    }

    /// Process one contact with the current state, then perform one mechanical
    /// step.  The ordering is intentional: Fialka enciphers/deciphers first
    /// and advances the wheels afterwards.
    pub(crate) fn process_contact(
        &mut self,
        input: Contact,
        direction: CipherDirection,
    ) -> Contact {
        let output = self.core.process_contact(input, direction);
        self.core.drum.step();
        output
    }

    #[must_use]
    pub(crate) const fn drum(&self) -> &RotorDrum {
        self.core.drum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::{
        CONTACT_COUNT, CoreSetting, CoreSide, Proton2Rotor, RingSetting, RotorId, RotorPosition,
        data::polish,
    };

    fn contact(value: u8) -> Contact {
        Contact::new(value).unwrap()
    }

    fn base_3k_drum() -> RotorDrum {
        RotorDrum::new(std::array::from_fn(|index| {
            let id = RotorId::ALL[index];
            Proton2Rotor::new(
                polish::body(id),
                polish::rotor(id),
                CoreSide::One,
                CoreSetting::A,
                RingSetting::A,
                RotorPosition::new(0).unwrap(),
            )
        }))
    }

    fn configured_3k_drum() -> RotorDrum {
        RotorDrum::new(std::array::from_fn(|index| {
            // Deliberately mix core identity, side, core/ring offsets and
            // visible position so the full-path inverse test exercises every
            // electrical layer rather than only the overall base setting.
            let body_id = RotorId::ALL[index];
            let core_id = RotorId::ALL[(index * 3 + 1) % 10];
            Proton2Rotor::new(
                polish::body(body_id),
                polish::rotor(core_id),
                if index % 2 == 0 {
                    CoreSide::One
                } else {
                    CoreSide::Two
                },
                CoreSetting::new(((index * 7 + 3) % CONTACT_COUNT) as u8).unwrap(),
                RingSetting::new(((index * 11 + 5) % CONTACT_COUNT) as u8).unwrap(),
                RotorPosition::new(((index * 13 + 2) % CONTACT_COUNT) as u8).unwrap(),
            )
        }))
    }

    fn non_reciprocal_card() -> Commutator {
        // Multiplication by 7 modulo 30 is a permutation and is intentionally
        // not reciprocal, ensuring the full return path really uses P^-1.
        let mapping = std::array::from_fn(|index| ((index * 7) % CONTACT_COUNT) as u8);
        Commutator::new(mapping).unwrap()
    }

    fn forward_to_reflector(core: &FialkaCore, input: Contact) -> Contact {
        let mut contact = core.commutator.keyboard_to_drum(input);
        contact = core.entry_disc.card_to_drum(contact);
        for slot in RotorSlot::ALL.into_iter().rev() {
            contact = core.drum.rotor(slot).right_to_left(contact);
        }
        contact
    }

    #[test]
    fn physical_rotor_traversal_order_is_ten_to_one_then_one_to_ten() {
        let core = FialkaCore::new(base_3k_drum(), Commutator::identity());
        let input = contact(4);

        let mut outward = core.commutator.keyboard_to_drum(input);
        outward = core.entry_disc.card_to_drum(outward);
        for slot in RotorSlot::ALL.into_iter().rev() {
            outward = core.drum.rotor(slot).right_to_left(outward);
        }

        assert_eq!(forward_to_reflector(&core, input), outward);

        let reflected = match core
            .reflector
            .transform(outward, CipherDirection::Encode, input)
        {
            ReflectorResult::ReturnThroughDrum(contact) => contact,
            ReflectorResult::Plaintext(_) => {
                // This chosen input is expected to exercise a normal return
                // path; fail loudly if future data changes that assumption.
                panic!("test input unexpectedly reached plaintext-enable contact")
            }
        };

        let mut returned = reflected;
        for slot in RotorSlot::ALL {
            returned = core.drum.rotor(slot).left_to_right(returned);
        }
        returned = core.entry_disc.drum_to_card(returned);
        returned = core.commutator.drum_to_output(returned);

        assert_eq!(core.encode_contact(input), returned);
    }


    #[test]
    fn base_3k_frozen_mapping_is_stable_for_both_mode_directions() {
        // One-based output contacts for an identity card, overall-base 3K
        // rotor set A..K, all visible positions A, and the documented entry
        // disc/reflector.  This is a frozen component-composition fixture, not
        // yet the historical message vector required by Step 12.
        const ENCODE_ONE_BASED: [u8; CONTACT_COUNT] = [
            15, 29, 17, 18, 30, 10, 21, 22, 20, 6, 12, 11, 25, 27, 1, 2, 3, 4, 24, 9, 7, 8,
            26, 19, 13, 23, 14, 28, 16, 5,
        ];
        const DECODE_ONE_BASED: [u8; CONTACT_COUNT] = [
            15, 16, 17, 18, 30, 10, 21, 22, 20, 6, 12, 11, 25, 27, 1, 29, 3, 4, 24, 9, 7, 8,
            26, 19, 13, 23, 14, 28, 2, 5,
        ];

        let core = FialkaCore::new(base_3k_drum(), Commutator::identity());

        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            assert_eq!(
                core.encode_contact(input).get() + 1,
                ENCODE_ONE_BASED[usize::from(value)]
            );
            assert_eq!(
                core.decode_contact(input).get() + 1,
                DECODE_ONE_BASED[usize::from(value)]
            );
        }
    }

    #[test]
    fn frozen_encode_and_decode_are_exact_inverses_in_base_configuration() {
        let core = FialkaCore::new(base_3k_drum(), Commutator::identity());

        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            assert_eq!(core.decode_contact(core.encode_contact(input)), input);
            assert_eq!(core.encode_contact(core.decode_contact(input)), input);
        }
    }

    #[test]
    fn frozen_encode_and_decode_are_exact_inverses_with_full_proton2_settings() {
        let core = FialkaCore::new(configured_3k_drum(), non_reciprocal_card());

        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            assert_eq!(core.decode_contact(core.encode_contact(input)), input);
            assert_eq!(core.encode_contact(core.decode_contact(input)), input);
        }
    }

    #[test]
    fn exactly_one_input_reaches_plaintext_enable_and_enciphers_to_itself() {
        let core = FialkaCore::new(configured_3k_drum(), non_reciprocal_card());
        let reflector_plaintext_contact = Contact::new(12).unwrap(); // historical 13

        let inputs: Vec<_> = (0..CONTACT_COUNT as u8)
            .map(contact)
            .filter(|&input| forward_to_reflector(&core, input) == reflector_plaintext_contact)
            .collect();

        assert_eq!(inputs.len(), 1);
        let input = inputs[0];
        assert_eq!(core.encode_contact(input), input);
        assert_eq!(core.decode_contact(input), input);
    }

    #[test]
    fn frozen_processing_never_changes_rotor_positions() {
        let core = FialkaCore::new(configured_3k_drum(), non_reciprocal_card());
        let before = core.drum().positions();

        for value in 0..CONTACT_COUNT as u8 {
            let input = contact(value);
            let _ = core.encode_contact(input);
            let _ = core.decode_contact(input);
        }

        assert_eq!(core.drum().positions(), before);
    }

    #[test]
    fn stateful_machine_enciphers_before_it_steps() {
        let drum = base_3k_drum();
        let frozen = FialkaCore::new(drum.clone(), Commutator::identity());
        let mut machine = FialkaMachine::new(drum, Commutator::identity());
        let input = contact(0);

        // The first output must be produced by the initial all-А state.
        assert_eq!(machine.encode_contact(input), frozen.encode_contact(input));

        // Only after producing that output do the two unconditional drivers
        // advance: slot 2 А→Й and slot 9 А→Б.
        assert_eq!(
            machine.drum().positions().map(|position| position.get() + 1),
            [1, 30, 1, 1, 1, 1, 1, 1, 2, 1]
        );
    }

    #[test]
    fn stateful_processing_reproduces_the_published_twenty_keypress_trace() {
        const EXPECTED: [[u8; 10]; 21] = [
            [1, 1, 1, 1, 1, 1, 1, 1, 1, 1],
            [1, 30, 1, 1, 1, 1, 1, 1, 2, 1],
            [1, 29, 1, 1, 1, 1, 1, 1, 3, 1],
            [1, 28, 1, 1, 1, 1, 1, 1, 4, 1],
            [1, 27, 1, 1, 1, 1, 1, 1, 5, 1],
            [1, 26, 1, 30, 1, 30, 1, 1, 6, 1],
            [1, 25, 1, 30, 1, 30, 1, 1, 7, 1],
            [1, 24, 1, 29, 1, 30, 2, 1, 8, 1],
            [1, 23, 1, 29, 1, 30, 3, 1, 9, 1],
            [1, 22, 1, 28, 1, 30, 3, 1, 10, 1],
            [1, 21, 1, 27, 1, 30, 4, 1, 11, 1],
            [1, 20, 1, 26, 1, 30, 4, 1, 12, 1],
            [1, 19, 1, 26, 1, 30, 4, 1, 13, 1],
            [1, 18, 1, 25, 1, 29, 4, 1, 14, 1],
            [1, 17, 1, 25, 1, 29, 4, 1, 15, 1],
            [2, 16, 2, 24, 2, 29, 5, 1, 16, 1],
            [2, 15, 2, 24, 2, 29, 5, 1, 17, 1],
            [2, 14, 2, 23, 2, 28, 6, 30, 18, 30],
            [2, 13, 2, 22, 2, 28, 6, 30, 19, 30],
            [2, 12, 2, 22, 2, 28, 7, 30, 20, 30],
            [2, 11, 2, 22, 2, 28, 8, 30, 21, 30],
        ];

        let mut machine = FialkaMachine::new(base_3k_drum(), Commutator::identity());
        assert_eq!(
            machine.drum().positions().map(|position| position.get() + 1),
            EXPECTED[0]
        );

        // The actual electrical input is irrelevant to stepping; using А for
        // every keypress isolates state evolution from message contents.
        for (keypress, expected) in EXPECTED.iter().enumerate().skip(1) {
            let _ = machine.encode_contact(contact(0));
            assert_eq!(
                machine.drum().positions().map(|position| position.get() + 1),
                *expected,
                "after keypress {keypress}"
            );
        }
    }

    #[test]
    fn stateful_encode_and_decode_round_trip_with_identical_starting_state() {
        let drum = configured_3k_drum();
        let card = non_reciprocal_card();
        let mut encoder = FialkaMachine::new(drum.clone(), card.clone());
        let mut decoder = FialkaMachine::new(drum, card);

        let plaintext: Vec<_> = (0..90)
            .map(|index| contact(((index * 11 + 7) % CONTACT_COUNT) as u8))
            .collect();
        let ciphertext: Vec<_> = plaintext
            .iter()
            .copied()
            .map(|input| encoder.encode_contact(input))
            .collect();
        let recovered: Vec<_> = ciphertext
            .iter()
            .copied()
            .map(|input| decoder.decode_contact(input))
            .collect();

        assert_eq!(recovered, plaintext);
        assert_eq!(encoder.drum().positions(), decoder.drum().positions());
    }

    #[test]
    fn every_processed_contact_advances_the_drum_exactly_once() {
        let drum = base_3k_drum();
        let mut expected = drum.clone();
        let mut machine = FialkaMachine::new(drum, Commutator::identity());

        for value in 0..CONTACT_COUNT as u8 {
            let _ = machine.process_contact(contact(value), CipherDirection::Encode);
            expected.step();
            assert_eq!(machine.drum().positions(), expected.positions());
        }
    }

}
