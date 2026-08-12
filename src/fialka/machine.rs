//! Frozen electrical path of the Fialka M-125-3.
//!
//! This module assembles the components already validated independently:
//!
//! keyboard -> fixed keyboard map -> commutator -> entry disc -> rotors 10..1
//!          -> reflector -> rotors 1..10 -> entry disc -> inverse commutator
//!          -> inverse keyboard map -> output
//!
//! Rotor stepping is deliberately absent here.  Step 11 will couple this
//! electrical transform to the mechanical drum only after the frozen path has
//! its own exhaustive tests.

use crate::Block;

use super::{
    CipherDirection, Commutator, Contact, EntryDisc, FialkaConfig, KeyboardMapping, ReflectorResult,
    NumericAlphabet, NumericModeError, ReductionSwitch, ReflectorUnit, RotorDrum, RotorSlot,
    RussianAlphabet, UnsupportedRussianLetter,
};

/// Complete 30-contact electrical machine with rotor movement disabled.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FialkaCore {
    drum: RotorDrum,
    keyboard: KeyboardMapping,
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
            keyboard: KeyboardMapping::new(),
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

        let mut contact = self.keyboard.keyboard_to_card(input);
        contact = self.commutator.keyboard_to_drum(contact);
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
                contact = self.commutator.drum_to_output(contact);
                self.keyboard.card_to_keyboard(contact)
            }
        }
    }

    /// Process one numbered-key contact with NumLock in position `10`,
    /// Process one complete NumLock keypress electrically, without stepping.
    ///
    /// The reduction network is bidirectional. Forward re-entry occurs at
    /// exported reflector contacts; reverse re-entry occurs when the return
    /// path reaches one of the twenty switched card-reader contacts.
    pub(crate) fn process_numeric_contact(
        &self,
        input: Contact,
        direction: CipherDirection,
    ) -> Result<Contact, NumericModeError> {
        let original_input = input;

        // The ten coloured numeric keys remain connected to the card reader.
        let mut card_input = self.keyboard.keyboard_to_card(input);

        // Forward reduction.
        let mut seen_forward = [false; 30];
        let terminal_reflector = loop {
            let reflector = self.card_input_to_reflector(card_input);

            let Some(next_card) = ReductionSwitch::card_input(reflector) else {
                break reflector;
            };

            let index = usize::from(reflector.get());
            if seen_forward[index] {
                return Err(NumericModeError::ReductionCycle {
                    reflector_contact: reflector.get() + 1,
                });
            }
            seen_forward[index] = true;
            card_input = next_card;
        };

        // Contact 13 selects the original mechanically encoded symbol and has
        // no electrical return path through the drum.
        let mut reflector_output = match self.reflector.transform(
            terminal_reflector,
            direction,
            original_input,
        ) {
            ReflectorResult::Plaintext(contact) => return Ok(contact),
            ReflectorResult::ReturnThroughDrum(contact) => contact,
        };

        // Reverse reduction. A switched card contact is connected directly to
        // its exported reflector contact and therefore starts another
        // left-to-right traversal of the rotor drum.
        let mut seen_reverse = [false; 30];
        loop {
            let card_output = self.reflector_to_card(reflector_output);

            if let Some(next_reflector) = ReductionSwitch::reflector_contact(card_output) {
                let index = usize::from(next_reflector.get());
                if seen_reverse[index] {
                    return Err(NumericModeError::ReductionCycle {
                        reflector_contact: next_reflector.get() + 1,
                    });
                }
                seen_reverse[index] = true;
                reflector_output = next_reflector;
                continue;
            }

            // Only the ten direct card contacts can reach the keyboard in
            // NumLock position 10.
            return Ok(self.keyboard.card_to_keyboard(card_output));
        }
    }

    /// Card-reader side -> reflector side.
    fn card_input_to_reflector(&self, mut contact: Contact) -> Contact {
        contact = self.commutator.keyboard_to_drum(contact);
        contact = self.entry_disc.card_to_drum(contact);
        for slot in RotorSlot::ALL.into_iter().rev() {
            contact = self.drum.rotor(slot).right_to_left(contact);
        }
        contact
    }

    /// Reflector side -> card-reader side.
    ///
    /// This deliberately stops before the fixed card->keyboard substitution,
    /// because NumLock intercepts twenty card contacts at this point.
    fn reflector_to_card(&self, mut contact: Contact) -> Contact {
        for slot in RotorSlot::ALL {
            contact = self.drum.rotor(slot).left_to_right(contact);
        }
        contact = self.entry_disc.drum_to_card(contact);
        self.commutator.drum_to_output(contact)
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

    /// Process a complete numbers-only keypress and step once afterwards.
    pub(crate) fn process_numeric_contact(
        &mut self,
        input: Contact,
        direction: CipherDirection,
    ) -> Result<Contact, NumericModeError> {
        let output = self.core.process_numeric_contact(input, direction)?;
        self.core.drum.step();
        Ok(output)
    }

    #[must_use]
    pub(crate) const fn drum(&self) -> &RotorDrum {
        self.core.drum()
    }
}


/// Public adapter for using a validated Fialka configuration through the
/// crate's [`Block`] interface.
///
/// The `Block` byte domain is deliberately the machine's native electrical
/// coordinate system: every source byte must be a contact number in `0..30`.
/// Text/Unicode conversion belongs to the alphabet layer and is not performed
/// implicitly here.
///
/// Each `encrypt()` or `decrypt()` call starts from the configured initial
/// rotor positions, matching the reset-per-call convention used by the other
/// stateful machine adapters in this crate.  Stateful/contact-by-contact work
/// remains implemented by `FialkaMachine` internally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fialka {
    config: FialkaConfig,
}

impl Fialka {
    /// Create a reusable Fialka adapter from a validated machine key.
    #[must_use]
    pub const fn new(config: FialkaConfig) -> Self {
        Self { config }
    }

    /// Return the validated configuration used to initialise each operation.
    #[must_use]
    pub const fn config(&self) -> &FialkaConfig {
        &self.config
    }

    /// Encode Russian letters through the 30-contact machine.
    ///
    /// Lower-case input is accepted and normalized to upper-case. The historical
    /// 30-letter Fialka alphabet omits Ё, Ъ and Э; any unsupported character
    /// returns an error instead of being silently discarded or remapped.
    pub fn encrypt_russian_letters(
        &self,
        src: &str,
    ) -> Result<String, UnsupportedRussianLetter> {
        self.process_russian_letters(src, CipherDirection::Encode)
    }

    /// Decode Russian letters through the 30-contact machine.
    ///
    /// This is the text-layer counterpart of [`Block::decrypt`]. Each input
    /// letter is translated to its electrical contact, processed in decoding
    /// mode, and translated back to the canonical upper-case Russian alphabet.
    pub fn decrypt_russian_letters(
        &self,
        src: &str,
    ) -> Result<String, UnsupportedRussianLetter> {
        self.process_russian_letters(src, CipherDirection::Decode)
    }

    fn process_russian_letters(
        &self,
        src: &str,
        direction: CipherDirection,
    ) -> Result<String, UnsupportedRussianLetter> {
        let mut machine = self.config.build_machine();
        let mut output = String::with_capacity(src.len());

        for ch in src.chars() {
            let input = RussianAlphabet::encode(ch)?;
            let contact = machine.process_contact(input, direction);
            output.push(RussianAlphabet::decode(contact));
        }

        Ok(output)
    }

    /// Encrypt ASCII decimal digits through the M-125-3 `30 <-> 10`
    /// numbers-only reduction circuit.
    pub fn encrypt_numeric(&self, src: &str) -> Result<String, NumericModeError> {
        self.process_numeric_text(src, CipherDirection::Encode)
    }

    /// Decrypt ASCII decimal digits through the M-125-3 numbers-only circuit.
    pub fn decrypt_numeric(&self, src: &str) -> Result<String, NumericModeError> {
        self.process_numeric_text(src, CipherDirection::Decode)
    }

    fn process_numeric_text(
        &self,
        src: &str,
        direction: CipherDirection,
    ) -> Result<String, NumericModeError> {
        let mut machine = self.config.build_machine();
        let mut output = String::with_capacity(src.len());

        for ch in src.chars() {
            let input = NumericAlphabet::encode(ch)?;
            let contact = machine.process_numeric_contact(input, direction)?;
            output.push(NumericAlphabet::decode(contact)?);
        }

        Ok(output)
    }

    fn process_block(&self, dst: &mut [u8], src: &[u8], direction: CipherDirection) -> usize {
        let limit = dst.len().min(src.len());
        let mut machine = self.config.build_machine();

        for index in 0..limit {
            let Some(input) = Contact::new(src[index]) else {
                // Block has no error channel.  A short processed-count is the
                // only non-panicking way to report an invalid raw contact.
                return index;
            };

            let output = machine.process_contact(input, direction);
            dst[index] = output.get();
        }

        limit
    }
}

impl Block for Fialka {
    /// Fialka is a stateful stream machine with one electrical contact per step.
    fn block_size(&self) -> usize {
        1
    }

    /// Encode raw zero-based electrical contacts (`0..29`).
    ///
    /// Processing stops at the first invalid byte or when `dst` is full; the
    /// return value is the number of contacts written.
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.process_block(dst, src, CipherDirection::Encode)
    }

    /// Decode raw zero-based electrical contacts (`0..29`).
    ///
    /// Processing stops at the first invalid byte or when `dst` is full; the
    /// return value is the number of contacts written.
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        self.process_block(dst, src, CipherDirection::Decode)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fialka::{
        CONTACT_COUNT, CoreSetting, CoreSide, Proton2Rotor, RingSetting, RotorId, RotorPosition,
        RotorSeries, data::polish,
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
        let mut contact = core.keyboard.keyboard_to_card(input);
        contact = core.commutator.keyboard_to_drum(contact);
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

        let mut outward = core.keyboard.keyboard_to_card(input);
        outward = core.commutator.keyboard_to_drum(outward);
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
        returned = core.keyboard.card_to_keyboard(returned);

        assert_eq!(core.encode_contact(input), returned);
    }


    #[test]
    fn base_3k_frozen_mapping_is_stable_for_both_mode_directions() {
        // One-based output contacts for an identity card, overall-base 3K
        // rotor set A..K, all visible positions A, and the documented entry
        // disc/reflector.  This is a frozen component-composition fixture, not
        // yet the historical message vector required by Step 12.
        const ENCODE_ONE_BASED: [u8; CONTACT_COUNT] = [
            30, 28, 22, 23, 18, 21, 25, 15, 10, 9, 27, 26, 19, 14, 8, 11, 24, 5, 13, 29, 6, 3,
            4, 17, 7, 12, 16, 2, 20, 1,
        ];
        const DECODE_ONE_BASED: [u8; CONTACT_COUNT] = [
            30, 28, 22, 23, 18, 21, 25, 15, 10, 9, 16, 26, 19, 14, 8, 27, 24, 5, 13, 29, 6, 3,
            4, 17, 7, 12, 11, 2, 20, 1,
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


    #[test]
    fn block_adapter_matches_native_stateful_machine() {
        let config = FialkaConfig::overall_base(RotorSeries::Polish3K, Commutator::identity());
        let adapter = Fialka::new(config.clone());
        let src: Vec<u8> = (0..60).map(|i| (i % CONTACT_COUNT) as u8).collect();
        let mut via_block = vec![0_u8; src.len()];

        assert_eq!(adapter.encrypt(&mut via_block, &src), src.len());

        let mut native = config.build_machine();
        let expected: Vec<u8> = src
            .iter()
            .copied()
            .map(|value| native.encode_contact(Contact::new(value).unwrap()).get())
            .collect();

        assert_eq!(via_block, expected);
    }

    #[test]
    fn block_adapter_round_trips_and_resets_each_call() {
        let adapter = Fialka::new(FialkaConfig::overall_base(
            RotorSeries::Polish3K,
            non_reciprocal_card(),
        ));
        let plain: Vec<u8> = (0..90).map(|i| ((i * 11 + 7) % CONTACT_COUNT) as u8).collect();
        let mut cipher_a = vec![0_u8; plain.len()];
        let mut cipher_b = vec![0_u8; plain.len()];
        let mut recovered = vec![0_u8; plain.len()];

        assert_eq!(adapter.encrypt(&mut cipher_a, &plain), plain.len());
        // A second call must restart from the configured initial rotor state.
        assert_eq!(adapter.encrypt(&mut cipher_b, &plain), plain.len());
        assert_eq!(cipher_a, cipher_b);

        assert_eq!(adapter.decrypt(&mut recovered, &cipher_a), plain.len());
        assert_eq!(recovered, plain);
    }

    #[test]
    fn russian_letters_text_api_round_trips_and_normalizes_case() {
        let fialka = Fialka::new(FialkaConfig::overall_base(
            RotorSeries::Polish3K,
            Commutator::identity(),
        ));
        let plaintext = "секретноесообщение";

        let ciphertext = fialka.encrypt_russian_letters(plaintext).unwrap();
        let recovered = fialka.decrypt_russian_letters(&ciphertext).unwrap();

        assert_eq!(recovered, "СЕКРЕТНОЕСООБЩЕНИЕ");
        assert_eq!(ciphertext.chars().count(), plaintext.chars().count());
    }

    #[test]
    fn russian_letters_text_api_rejects_characters_outside_machine_alphabet() {
        let fialka = Fialka::new(FialkaConfig::overall_base(
            RotorSeries::Polish3K,
            Commutator::identity(),
        ));

        assert_eq!(
            fialka.encrypt_russian_letters("Ё"),
            Err(UnsupportedRussianLetter('Ё'))
        );
        assert_eq!(
            fialka.encrypt_russian_letters("А Б"),
            Err(UnsupportedRussianLetter(' '))
        );
    }

    #[test]
    fn block_adapter_stops_before_invalid_contact_without_masking_it() {
        let adapter = Fialka::new(FialkaConfig::overall_base(
            RotorSeries::Polish3K,
            Commutator::identity(),
        ));
        let src = [0_u8, 1, 29, 30, 2, 3];
        let mut dst = [0xAA_u8; 6];

        assert_eq!(adapter.encrypt(&mut dst, &src), 3);
        assert_eq!(dst[3..], [0xAA; 3]);
    }

    #[test]
    fn block_adapter_respects_short_destination() {
        let adapter = Fialka::new(FialkaConfig::overall_base(
            RotorSeries::Polish3K,
            Commutator::identity(),
        ));
        let src = [0_u8, 1, 2, 3, 4];
        let mut dst = [0_u8; 3];

        assert_eq!(adapter.encrypt(&mut dst, &src), dst.len());
    }

}
