//! This module defines two different "autoclave" variations of the Vigenere cipher.
//!
//! In the Vigenere cipher, the key is repeated across the whole plaintext, meaning it is also
//! vulnerable to frequency analysis attacks (The "Kasiski" method to determine the key length).
//!
//! [Kasiski Method](https://en.wikipedia.org/wiki/Kasiski_examination)
//!
//! The Autoclave (or Autokey) cipher addresses this issue by using a key that is generated either
//! from the plaintext or the ciphertext itself, ensuring that the key is different for each block.
//! In essence, this is the ancestor of the various Block Cipher modes of operation (CBC, etc.) and
//! the key K is known as the "primer" or, in modern language, the IV (Initialisation Vector).
//!
//! The original autoclave system invented by Vigenère was the Autokey one, and he was using a single
//! letter for the key [KAHN 96].
//!
//! [Autokey Cipher](https://en.wikipedia.org/wiki/Autokey_cipher)
//! [Block Cipher Modes of Operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
//! [KAHN 96]
//!
//! There are two different autoclave variants defined by Vinegere himself (although he was using
//! a one character key):
//!
//! - use the plaintext (autokey)
//!
//! C0 = P0 ⨁ K
//! C1 = P1 ⨁ P0
//! ...
//! Cn = Pn ⨁ Pn-1
//!
//! Autokey is akin to CFB mode of operation.  It is easier to implement than the other one, as it
//! can be see as
//!
//! CCCCCCCCCCCCC = PPPPPPPPPPPPP ⨁ KKKKKPPPPPPPPPPPP
//!
//! - use the ciphertext (autocrypt)
//!
//! C0 = P0 ⨁ K
//! C1 = P1 ⨁ C0
//! ...
//! Cn = Pn ⨁ Cn-1
//!
//! Autocrypt is akin to CBC mode of operation.
//!

mod autocrypt;
mod autokey;

pub use autocrypt::Autocrypt;
pub use autokey::Autokey;
