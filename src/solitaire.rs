//! Implements the Solitaire cipher algorithm for encryption and decryption.
//!
//! The Solitaire cipher (also known as Pontifex) is a manual cryptographic algorithm
//! designed by Bruce Schneier for the novel "Cryptonomicon" by Neal Stephenson.
//! It uses a standard 54-card deck (52 playing cards plus 2 jokers) to generate
//! a keystream for encryption and decryption.
//!
//! # Algorithm Overview
//!
//! The cipher operates by repeatedly transforming the deck through a series of steps:
//! 1. Move Joker A (card 53) one position down
//! 2. Move Joker B (card 54) two positions down
//! 3. Perform a triple cut around the two jokers
//! 4. Perform a count cut based on the bottom card's value
//! 5. Output the card at the position indicated by the top card's value
//!
//! # Security Note
//!
//! This cipher is designed for educational purposes and manual computation.
//! It is **not recommended** for securing sensitive information in practice,
//! as it is vulnerable to various cryptanalytic attacks when used incorrectly.
//!
//! # Usage
//!
//! ```
//! use old_crypto_rs::solitaire::Solitaire;
//! use old_crypto_rs::Block;
//!
//! // Create cipher with unkeyed (sorted) deck
//! let cipher = Solitaire::new_unkeyed();
//!
//! // Or create with a passphrase
//! let cipher = Solitaire::new_with_passphrase("MYSECRET");
//!
//! // Encrypt plaintext
//! let plaintext = b"HELLO";
//! let mut ciphertext = vec![0u8; plaintext.len()];
//! cipher.encrypt(&mut ciphertext, plaintext);
//!
//! // Decrypt ciphertext
//! let mut decrypted = vec![0u8; ciphertext.len()];
//! cipher.decrypt(&mut decrypted, &ciphertext);
//! ```
//!
//! # References
//!
//! - Bruce Schneier's original specification: <https://www.schneier.com/academic/solitaire/>
//! - "Cryptonomicon" by Neal Stephenson
//! - Wikipedia article on Solitaire cipher
//! 
use crate::Block;
use std::cell::RefCell;

/// A Solitaire cipher implementation using a 54-card deck.
///
/// The `Solitaire` struct maintains the state of a deck of cards used for encryption
/// and decryption operations. It stores both the initial deck configuration (for
/// resetting between operations) and the current deck state (which is modified during
/// keystream generation).
///
/// # Structure
///
/// - `initial_deck`: The original deck configuration, preserved for resetting
/// - `deck`: The working deck state, wrapped in `RefCell` for interior mutability
///
/// # Thread Safety
///
/// This type is not thread-safe due to the use of `RefCell`. Each thread should
/// create its own instance if parallel encryption/decryption is needed.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::solitaire::Solitaire;
/// use old_crypto_rs::Block;
///
/// // Create with default unkeyed deck
/// let cipher = Solitaire::new_unkeyed();
///
/// // Create with a passphrase
/// let cipher = Solitaire::new_with_passphrase("SECRET");
///
/// // Create with custom deck
/// let custom_deck: Vec<u8> = (1..=54).collect();
/// let cipher = Solitaire::new(custom_deck);
/// ```
/// 
#[derive(Clone)]
pub struct Solitaire {
    initial_deck: Vec<u8>,
    deck: RefCell<Vec<u8>>,
}

impl Solitaire {
    /// Creates a new Solitaire cipher with a custom deck configuration.
    ///
    /// The deck must be a permutation of 54 cards:
    /// - Cards 1-52: Standard playing cards (1-13 = Clubs, 14-26 = Diamonds,
    ///   27-39 = Hearts, 40-52 = Spades)
    /// - Card 53: Joker A
    /// - Card 54: Joker B
    ///
    /// # Arguments
    ///
    /// * `deck` - A vector of exactly 54 unique bytes representing the deck order
    ///
    /// # Panics
    ///
    /// Panics if the deck length is not exactly 54 cards.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::solitaire::Solitaire;
    ///
    /// // Create with a custom deck order
    /// let mut custom_deck: Vec<u8> = (1..=54).collect();
    /// // Shuffle or reorder as needed
    /// let cipher = Solitaire::new(custom_deck);
    /// ```
    /// 
    pub fn new(deck: Vec<u8>) -> Self {
        assert_eq!(deck.len(), 54);
        Solitaire {
            initial_deck: deck.clone(),
            deck: RefCell::new(deck),
        }
    }

    /// Creates a Solitaire cipher with an unkeyed (sorted) deck.
    ///
    /// This initializes the deck in standard order (1, 2, 3, ..., 54).
    /// An unkeyed deck provides no security and is primarily used for testing
    /// and demonstrating the algorithm's operation.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::solitaire::Solitaire;
    /// use old_crypto_rs::Block;
    ///
    /// let cipher = Solitaire::new_unkeyed();
    /// let mut output = vec![0u8; 5];
    /// cipher.encrypt(&mut output, b"HELLO");
    /// ```
    ///
    /// # Security Warning
    ///
    /// Never use an unkeyed deck for actual encryption as it provides no security.
    /// 
    pub fn new_unkeyed() -> Self {
        let deck: Vec<u8> = (1..=54).collect();
        Self::new(deck)
    }

    /// Creates a Solitaire cipher with a deck keyed by a passphrase.
    ///
    /// The passphrase is used to shuffle the initially sorted deck through a series
    /// of deck transformations. Each alphabetic character in the passphrase (case-insensitive)
    /// contributes to the deck's final permutation. Non-alphabetic characters are ignored.
    ///
    /// # Arguments
    ///
    /// * `passphrase` - A string used to key the deck. Only ASCII alphabetic characters
    ///   are processed; all others are skipped.
    ///
    /// # Algorithm
    ///
    /// For each alphabetic character in the passphrase:
    /// 1. Convert to uppercase and get its position (A=1, B=2, ..., Z=26)
    /// 2. Advance the deck through one complete cycle (steps 1-4)
    /// 3. Perform a count cut using the character's numeric value
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::solitaire::Solitaire;
    /// use old_crypto_rs::Block;
    ///
    /// // Passphrase can contain spaces and punctuation (ignored)
    /// let cipher = Solitaire::new_with_passphrase("My Secret Key!");
    ///
    /// // Same as above (non-alpha characters ignored)
    /// let cipher2 = Solitaire::new_with_passphrase("MYSECRETKEY");
    /// ```
    /// 
    pub fn new_with_passphrase(passphrase: &str) -> Self {
        let mut deck: Vec<u8> = (1..=54).collect();
        for ch in passphrase.chars() {
            if !ch.is_ascii_alphabetic() {
                continue;
            }
            let val = (ch.to_ascii_uppercase() as u8 - b'A' + 1) as usize;
            Self::advance_deck(&mut deck);
            Self::count_cut(&mut deck, val);
        }
        Self::new(deck)
    }

    /// Generates the next keystream value from the deck.
    ///
    /// This method performs one complete cycle of the Solitaire algorithm to produce
    /// a single keystream byte. If a joker is generated as output, the process repeats
    /// until a valid card (1-52) is produced.
    ///
    /// # Arguments
    ///
    /// * `deck` - A mutable reference to the current deck state
    ///
    /// # Returns
    ///
    /// A value between 1 and 26 representing the keystream output for this step.
    /// Cards 1-26 map directly to 1-26, while cards 27-52 are reduced modulo 26
    /// (i.e., card 27 becomes 1, card 28 becomes 2, etc.).
    ///
    /// # Algorithm Steps
    ///
    /// 1. Advance the deck through all transformation steps
    /// 2. Look at the top card's value to determine a count position
    /// 3. Output the card at that position (treating jokers as value 53)
    /// 4. If output is a joker, repeat from step 1
    /// 5. Convert the output card to a value in range 1-26
    /// 
    fn step(deck: &mut Vec<u8>) -> u8 {
        loop {
            Self::advance_deck(deck);

            // Step 5: Generate output card
            // Use the top card's value to index into the deck
            let first_val = deck[0];
            let count = if first_val > 52 { 53 } else { first_val } as usize;
            let output_card = deck[count];

            if output_card <= 52 {
                // Convert card value (1-52) to keystream value (1-26)
                // Cards 1-26 stay as-is, cards 27-52 wrap around
                return if output_card > 26 { output_card - 26 } else { output_card };
            }
            // If output card is a joker, discard and repeat the entire process
        }
    }

    /// Advances the deck through one complete transformation cycle.
    ///
    /// This performs the four main steps of the Solitaire algorithm that transform
    /// the deck state. These steps must be executed in order:
    ///
    /// 1. **Move Joker A down**: Move card 53 one position toward the bottom
    /// 2. **Move Joker B down**: Move card 54 two positions toward the bottom
    /// 3. **Triple cut**: Swap the cards above the first joker with the cards below the second joker
    /// 4. **Count cut**: Cut the deck based on the bottom card's value
    ///
    /// # Arguments
    ///
    /// * `deck` - A mutable reference to the deck to be transformed
    ///
    /// # Details
    ///
    /// The triple cut treats the two jokers as boundaries, dividing the deck into
    /// three sections: top (before first joker), middle (between jokers, inclusive),
    /// and bottom (after second joker). The top and bottom sections are swapped.
    ///
    /// The count cut uses the value of the bottom card to determine how many cards
    /// to move from the top to just above the bottom card.
    /// 
    fn advance_deck(deck: &mut Vec<u8>) {
        // Step 1: Move Joker A (card 53) one position down
        // If at the bottom, it wraps to position 1 (not 0)
        Self::move_joker(deck, 53, 1);

        // Step 2: Move Joker B (card 54) two positions down
        // If at or near the bottom, it wraps around similarly
        Self::move_joker(deck, 54, 2);

        // Step 3: Triple cut
        // Find positions of both jokers
        let pos_a = deck.iter().position(|&x| x == 53).unwrap();
        let pos_b = deck.iter().position(|&x| x == 54).unwrap();

        // Determine which joker is closer to the top
        let (top_j, bot_j) = if pos_a < pos_b {
            (pos_a, pos_b)
        } else {
            (pos_b, pos_a)
        };

        // Rebuild deck: [bottom section] + [middle section with jokers] + [top section]
        let mut new_deck = Vec::with_capacity(54);
        new_deck.extend_from_slice(&deck[bot_j + 1..]); // Cards after bottom joker
        new_deck.extend_from_slice(&deck[top_j..bot_j + 1]); // Both jokers and cards between
        new_deck.extend_from_slice(&deck[..top_j]); // Cards before top joker
        *deck = new_deck;

        // Step 4: Count cut
        // Use the bottom card's value to determine cut position
        let last_val = deck[53];
        let count = if last_val > 52 { 53 } else { last_val } as usize;
        Self::count_cut(deck, count);
    }

    /// Performs a count cut on the deck.
    ///
    /// This operation moves the top `count` cards to just above the bottom card,
    /// which always remains at the bottom of the deck. If count is 53 or greater,
    /// no operation is performed (the deck remains unchanged).
    ///
    /// # Arguments
    ///
    /// * `deck` - A mutable reference to the deck to be cut
    /// * `count` - The number of cards to cut from the top (0-53)
    ///
    /// # Algorithm
    ///
    /// Given a deck like `[A B C D E F ... Y Z]` and count=3:
    /// - Before: `[A B C D E ... Y Z]`
    /// - After:  `[D E ... Y A B C Z]`
    ///
    /// The bottom card (Z) never moves.
    /// 
    fn count_cut(deck: &mut Vec<u8>, count: usize) {
        if count < 53 {
            let last_val = deck[53];
            let mut new_deck = Vec::with_capacity(54);
            new_deck.extend_from_slice(&deck[count..53]);
            new_deck.extend_from_slice(&deck[..count]);
            new_deck.push(last_val);
            *deck = new_deck;
        }
    }

    /// Moves a joker card down through the deck by a specified number of positions.
    ///
    /// The joker moves toward the bottom of the deck. When it reaches the bottom position
    /// (index 53), the next move wraps it around to position 1 (not position 0, which would
    /// make it the top card). This wrap-around behavior treats the deck as circular for
    /// joker movement purposes.
    ///
    /// # Arguments
    ///
    /// * `deck` - A mutable reference to the deck
    /// * `joker` - The value of the joker to move (either 53 or 54)
    /// * `n` - The number of positions to move down
    ///
    /// # Examples
    ///
    /// Moving Joker A one position: `[... A B ...]` becomes `[... B A ...]`
    /// Moving Joker at bottom: `[X Y ... Z A]` becomes `[X A Y ... Z]` (A wraps to position 1)
    /// 
    fn move_joker(deck: &mut Vec<u8>, joker: u8, n: usize) {
        for _ in 0..n {
            let pos = deck.iter().position(|&x| x == joker).unwrap();
            if pos == 53 {
                // Joker is at the bottom; wrap to position 1 (not 0)
                let card = deck.remove(53);
                deck.insert(1, card);
            } else {
                // Swap with the next card down
                deck.swap(pos, pos + 1);
            }
        }
    }

    /// Resets the deck to its initial state.
    ///
    /// This method restores the deck to the configuration it had when the cipher
    /// was first created. This is essential for ensuring that encryption and decryption
    /// use the same keystream, as both operations start from the same initial deck state.
    ///
    /// # Implementation Note
    ///
    /// The deck state is maintained in a `RefCell` to allow interior mutability
    /// while keeping the `encrypt` and `decrypt` methods with `&self` receivers
    /// (required by the `Block` trait).
    /// 
    fn reset(&self) {
        *self.deck.borrow_mut() = self.initial_deck.clone();
    }
}

impl Block for Solitaire {
    fn block_size(&self) -> usize {
        1
    }

    /// Encrypts plaintext using the Solitaire cipher algorithm.
    ///
    /// This method generates a keystream by advancing the deck state and combines it
    /// with the plaintext to produce ciphertext. The deck is reset to its initial state
    /// before encryption begins, ensuring consistent keystream generation.
    ///
    /// # Arguments
    ///
    /// * `dst` - A mutable byte slice where the encrypted output will be written.
    ///           Must be at least as long as `src`.
    /// * `src` - A byte slice containing the plaintext to encrypt.
    ///           Only ASCII alphabetic characters are encrypted; all others pass through unchanged.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst` (always equal to `src.len()`).
    ///
    /// # Algorithm
    ///
    /// For each character in the source:
    /// - If alphabetic: Convert to uppercase, generate keystream byte, add values (mod 26)
    /// - If non-alphabetic: Copy unchanged to destination
    ///
    /// The encryption formula is: `C = (P + K - 1) mod 26 + 1`, where:
    /// - P is the plaintext character value (A=1, B=2, ..., Z=26)
    /// - K is the keystream value (1-26)
    /// - C is the resulting ciphertext character value
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::solitaire::Solitaire;
    /// use old_crypto_rs::Block;
    ///
    /// let cipher = Solitaire::new_unkeyed();
    /// let plaintext = b"HELLO";
    /// let mut ciphertext = vec![0u8; plaintext.len()];
    /// cipher.encrypt(&mut ciphertext, plaintext);
    /// // ciphertext now contains the encrypted result
    /// ```
    ///
    /// # Notes
    ///
    /// - Input case is normalized to uppercase
    /// - Non-alphabetic characters (spaces, punctuation, digits) are preserved as-is
    /// - The deck is reset before encryption, so multiple calls produce the same output
    ///
    fn encrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // Reset deck to the initial state for consistent keystream generation
        self.reset();

        for (i, &ch) in src.iter().enumerate() {
            if ch.is_ascii_alphabetic() {
                // Convert plaintext character to number (A=1, B=2, ..., Z=26)
                let p = (ch.to_ascii_uppercase() - b'A' + 1) as u8;

                // Generate next keystream value (1-26)
                let k = Self::step(&mut self.deck.borrow_mut());

                // Add plaintext and keystream values (with modulo 26 wrap-around)
                // Formula: C = (P + K - 1) mod 26 + 1
                let c = (p + k - 1) % 26 + 1;

                // Convert back to ASCII uppercase letter
                dst[i] = c + b'A' - 1;
            } else {
                // Non-alphabetic characters pass through unchanged
                dst[i] = ch;
            }
        }
        src.len()
    }

    /// Decrypts ciphertext using the Solitaire cipher algorithm.
    ///
    /// This method generates the same keystream used during encryption and subtracts it
    /// from the ciphertext to recover the original plaintext. The deck is reset to its
    /// initial state before decryption begins, ensuring the keystream matches encryption.
    ///
    /// # Arguments
    ///
    /// * `dst` - A mutable byte slice where the decrypted output will be written.
    ///           Must be at least as long as `src`.
    /// * `src` - A byte slice containing the ciphertext to decrypt.
    ///           Only ASCII alphabetic characters are decrypted; all others pass through unchanged.
    ///
    /// # Returns
    ///
    /// The number of bytes written to `dst` (always equal to `src.len()`).
    ///
    /// # Algorithm
    ///
    /// For each character in the source:
    /// - If alphabetic: Convert to uppercase, generate keystream byte, subtract values (mod 26)
    /// - If non-alphabetic: Copy unchanged to destination
    ///
    /// The decryption formula is: `P = (C - K) mod 26`, where:
    /// - C is the ciphertext character value (A=1, B=2, ..., Z=26)
    /// - K is the keystream value (1-26)
    /// - P is the resulting plaintext character value
    ///
    /// Special handling ensures proper modulo arithmetic for negative results.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::solitaire::Solitaire;
    /// use old_crypto_rs::Block;
    ///
    /// let cipher = Solitaire::new_unkeyed();
    /// let ciphertext = b"EXKYI";
    /// let mut plaintext = vec![0u8; ciphertext.len()];
    /// cipher.decrypt(&mut plaintext, ciphertext);
    /// assert_eq!(&plaintext, b"AAAAA");
    /// ```
    ///
    /// # Notes
    ///
    /// - Must use the same deck configuration (initial state) as encryption
    /// - Input case is normalized to uppercase
    /// - Non-alphabetic characters are preserved unchanged
    /// - The deck is reset before decryption to generate the correct keystream
    ///
    fn decrypt(&self, dst: &mut [u8], src: &[u8]) -> usize {
        // Reset deck to initial state for consistent keystream generation
        self.reset();

        for (i, &ch) in src.iter().enumerate() {
            if ch.is_ascii_alphabetic() {
                // Convert ciphertext character to number (A=1, B=2, ..., Z=26)
                let c = (ch.to_ascii_uppercase() - b'A' + 1) as u8;

                // Generate next keystream value (1-26) - must match encryption
                let k = Self::step(&mut self.deck.borrow_mut());

                // Subtract keystream from ciphertext (with modulo 26 wrap-around)
                // Formula: P = (C - K) mod 26, handling negative results
                let p = if c > k { c - k } else { c + 26 - k };

                // Convert back to ASCII uppercase letter
                dst[i] = p + b'A' - 1;
            } else {
                // Non-alphabetic characters pass through unchanged
                dst[i] = ch;
            }
        }
        src.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_solitaire_keystream() {
        let s = Solitaire::new_unkeyed();
        let mut deck = s.initial_deck.clone();
        let mut actual = Vec::new();
        for _ in 0..10 {
            actual.push(Solitaire::step(&mut deck));
        }
        // Wikipedia says for unkeyed deck: 4, 49, 10, (skip 53), 24, 8, 51, 44, 6, 33, 10...
        // However, standard implementations (including this one) diverge slightly after 8 steps.
        // We match up to the 8th value.
        let expected = [4, 23, 10, 24, 8, 25, 18, 6, 4, 7];
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_solitaire_wikipedia_example_1() {
        // Example: Plaintext "AAAAA" with unkeyed deck -> "EXKYI"
        let s = Solitaire::new_unkeyed();
        let src = b"AAAAA";
        let mut dst = vec![0u8; src.len()];
        s.encrypt(&mut dst, src);
        assert_eq!(std::str::from_utf8(&dst).unwrap(), "EXKYI");
    }

    #[test]
    fn test_solitaire_wikipedia_example_2() {
        // Example: Plaintext "AAAAAAAAAA" with unkeyed deck -> "EXKYIZSGEH"
        // (Wikipedia says "EXKYIZSUIK", but that seems inconsistent with their own keystream)
        let s = Solitaire::new_unkeyed();
        let src = b"AAAAAAAAAA";
        let mut dst = vec![0u8; src.len()];
        s.encrypt(&mut dst, src);
        assert_eq!(std::str::from_utf8(&dst).unwrap(), "EXKYIZSGEH");
    }

    #[test]
    fn test_solitaire_wikipedia_example_3() {
        // Round trip test
        let s = Solitaire::new_unkeyed();
        let src = b"EXKYIZSGEH";
        let mut dst = vec![0u8; src.len()];
        s.decrypt(&mut dst, src);
        assert_eq!(std::str::from_utf8(&dst).unwrap(), "AAAAAAAAAA");
    }

    #[test]
    fn test_solitaire_wikipedia_example_4() {
        // Example: "CLEAN" with unkeyed deck -> "GIOYV"
        let s = Solitaire::new_unkeyed();
        let src = b"CLEAN";
        let mut dst = vec![0u8; src.len()];
        s.encrypt(&mut dst, src);
        assert_eq!(std::str::from_utf8(&dst).unwrap(), "GIOYV");
        
        let mut dec = vec![0u8; src.len()];
        s.decrypt(&mut dec, &dst);
        assert_eq!(std::str::from_utf8(&dec).unwrap(), "CLEAN");
    }

    #[test]
    fn test_solitaire_extra_examples() {
        let tests = [
            ("", "AAAAAAAAAAAAAAA", "EXKYIZSGEHUNTIQ"),
            ("f", "AAAAAAAAAAAAAAA", "XYIUQBMHKKJBEGY"),
            ("fo", "AAAAAAAAAAAAAAA", "TUJYMBERLGXNDIW"),
            ("foo", "AAAAAAAAAAAAAAA", "ITHZUJIWGRFARMW"),
            ("a", "AAAAAAAAAAAAAAA", "XODALGSCULIQNSC"),
            ("aa", "AAAAAAAAAAAAAAA", "OHGWMXXCAIMCIQP"),
            ("aaa", "AAAAAAAAAAAAAAA", "DCSQYHBQZNGDRUT"),
            ("b", "AAAAAAAAAAAAAAA", "XQEEMOITLZVDSQS"),
            ("bc", "AAAAAAAAAAAAAAA", "QNGRKQIHCLGWSCE"),
            ("bcd", "AAAAAAAAAAAAAAA", "FMUBYBMAXHNQXCJ"),
            ("cryptonomicon", "AAAAAAAAAAAAAAAAAAAAAAAAA", "SUGSRSXSWQRMXOHIPBFPXARYQ"),
            ("cryptonomicon", "SOLITAIRE", "KIRAKSFJA"),
        ];

        for (pass, pt, ct) in tests {
            let s = if pass.is_empty() {
                Solitaire::new_unkeyed()
            } else {
                Solitaire::new_with_passphrase(pass)
            };
            let mut dst = vec![0u8; pt.len()];
            s.encrypt(&mut dst, pt.as_bytes());
            assert_eq!(std::str::from_utf8(&dst).unwrap(), ct, "Failed for key '{}'", pass);
        }
    }
}
