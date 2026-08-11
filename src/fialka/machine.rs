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
}
