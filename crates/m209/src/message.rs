//! Derived-indicator M-209 message envelopes (twelve-letter profile).
//!
//! Encryption appends unenciphered `X` padding; receiving cannot determine
//! how much of a transmitted final group is padding. Do not strip it silently.

use crate::{
    KeyId, KeyStore, M209Config, MessageError,
    decrypt_text_raw, derive_internal_indicator, display_plaintext, encrypt_text,
    group_five, ungroup_ciphertext,
};

const INDICATOR_GROUP_LEN: usize = 5;
const ENVELOPE_INDICATOR_LEN: usize = 2 * INDICATOR_GROUP_LEN;

/// Parsed transmitted message. The body includes any ambiguous final Xs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEnvelope {
    system: char,
    external: String,
    key_id: KeyId,
    body: String,
}

impl MessageEnvelope {
    pub fn parse(transmitted: &str) -> Result<Self, MessageError> {
        let letters = ungroup_ciphertext(transmitted)?;

        if letters.len() < ENVELOPE_INDICATOR_LEN * 2 + INDICATOR_GROUP_LEN {
            return Err(MessageError::TooShort);
        }

        let bytes = letters.as_bytes();
        let closing_start = bytes.len() - ENVELOPE_INDICATOR_LEN;

        if bytes[..ENVELOPE_INDICATOR_LEN] != bytes[closing_start..] {
            return Err(MessageError::MismatchedIndicators);
        }

        let body = &letters[ENVELOPE_INDICATOR_LEN..closing_start];

        if body.is_empty() {
            return Err(MessageError::EmptyBody);
        }

        if !body.len().is_multiple_of(INDICATOR_GROUP_LEN) {
            return Err(MessageError::IncompleteBodyGroup);
        }

        if bytes[0] != bytes[1] {
            return Err(MessageError::InvalidSystemIndicator);
        }

        let external = format!("{}{}", &letters[2..5], &letters[5..8]);
        let key_id = KeyId::parse(&letters[8..10])?;

        Ok(Self {
            system: bytes[0] as char,
            external,
            key_id,
            body: body.to_owned(),
        })
    }

    pub const fn system(&self) -> char {
        self.system
    }

    pub fn external(&self) -> &str {
        &self.external
    }

    pub const fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Ciphertext including possibly unenciphered trailing X padding.
    pub fn body(&self) -> &str {
        &self.body
    }

    pub fn transmit(&self) -> String {
        let indicators = format!("{}{}{}{}", self.system, self.system, self.external, self.key_id);
        group_five(&format!("{indicators}{}{indicators}", self.body))
    }
}

/// Sender-side result, including a known count of *unenciphered* padding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncipheredMessage {
    envelope: MessageEnvelope,
    padding: usize,
}

impl EncipheredMessage {
    pub const fn envelope(&self) -> &MessageEnvelope {
        &self.envelope
    }

    pub const fn padding(&self) -> usize {
        self.padding
    }

    pub fn transmit(&self) -> String {
        self.envelope.transmit()
    }
}

/// Receiver-side result. Raw plaintext includes undecidable output from the
/// post-encryption X padding; no letters are silently discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecipheredMessage {
    envelope: MessageEnvelope,
    internal: String,
    raw: String,
}

impl DecipheredMessage {
    pub const fn envelope(&self) -> &MessageEnvelope {
        &self.envelope
    }

    pub fn internal(&self) -> &str {
        &self.internal
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// Lossy display convention: decoded Z appears as a space.
    pub fn display(&self) -> String {
        display_plaintext(&self.raw)
    }
}

fn internal_config(
    config: &M209Config,
    positions: &[crate::WheelPosition; crate::WHEEL_COUNT],
) -> M209Config {
    M209Config::new(*config.pins(), *positions, *config.bars())
        .expect("derived wheel identities and daily key were validated")
}

/// Encrypt a complete message with *explicit* indicators (no implicit RNG).
/// This operation does not modify the stored daily key.
pub fn encipher_message(
    keys: &KeyStore,
    key_id: KeyId,
    system: char,
    external: &str,
    plaintext: &str,
) -> Result<EncipheredMessage, MessageError> {
    let key = keys.get(key_id)?;
    let indicator = derive_internal_indicator(key, system, external)?;
    let config = internal_config(key.config(), indicator.positions());
    let mut body = encrypt_text(&config, plaintext, false)?;

    if body.is_empty() {
        return Err(MessageError::EmptyBody);
    }

    let padding = (INDICATOR_GROUP_LEN - body.len() % INDICATOR_GROUP_LEN) % INDICATOR_GROUP_LEN;
    body.extend(std::iter::repeat_n('X', padding));

    Ok(EncipheredMessage {
        envelope: MessageEnvelope {
            system,
            external: external.to_owned(),
            key_id,
            body,
        },
        padding,
    })
}

/// Parse a transmitted derived-indicator message and decipher all body letters.
/// The receiver cannot reliably remove post-encryption X padding.
pub fn decipher_message(
    keys: &KeyStore,
    transmitted: &str,
) -> Result<DecipheredMessage, MessageError> {
    let envelope = MessageEnvelope::parse(transmitted)?;
    let key = keys.get(envelope.key_id())?;
    let derived = derive_internal_indicator(key, envelope.system(), envelope.external())?;
    let config = internal_config(key.config(), derived.positions());
    let raw = decrypt_text_raw(&config, envelope.body())?;

    Ok(DecipheredMessage {
        envelope,
        internal: derived.letters(),
        raw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyList, fixtures::{MANUAL_1944_CHECK, MANUAL_1944_PINS, manual_1944_drum}};

    fn reference_keys() -> KeyStore {
        let mut store = KeyStore::new();
        let key = KeyList::new(
            KeyId::parse("XA").unwrap(),
            M209Config::from_letters(MANUAL_1944_PINS, "AAAAAA", manual_1944_drum()).unwrap(),
            MANUAL_1944_CHECK,
        ).unwrap();
        store.insert(key).unwrap();
        store
    }

    #[test]
    fn published_complete_message_matches_exactly() {
        let keys = reference_keys();
        let encrypted = encipher_message(
            &keys, KeyId::parse("XA").unwrap(), 'K', "DUFLJB",
            "OPERATION ZEBRA STARTS AT SUNSET",
        ).unwrap();

        assert_eq!(encrypted.padding(), 3);
        assert_eq!(encrypted.envelope().body(), "KBMUNODDDCYWLVMRBVUSQYRHTXNZUIHXXXX");
        assert_eq!(
            encrypted.transmit(),
            "KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA"
        );
    }

    #[test]
    fn decrypt_preserves_ambiguous_padding() {
        let keys = reference_keys();
        let encrypted = encipher_message(
            &keys, KeyId::parse("XA").unwrap(), 'K', "DUFLJB",
            "OPERATION ZEBRA STARTS AT SUNSET",
        ).unwrap();
        let decoded = decipher_message(&keys, &encrypted.transmit()).unwrap();

        assert_eq!(decoded.internal(), "PEQGBJ");
        assert_eq!(&decoded.raw()[..32], "OPERATIONZZEBRAZSTARTSZATZSUNSET");
        assert_eq!(decoded.raw().len(), 35);
        assert_eq!(&decoded.display()[..32], "OPERATION  EBRA STARTS AT SUNSET");
    }

    #[test]
    fn independent_published_envelope_parses_without_daily_key() {
        let parsed = MessageEnvelope::parse(
            "YYGBM ENNHT VBMTJ PEEFV JWLUU PAFTS VOHEA QEPEQ OKVUA XDAUX YYGBM ENNHT"
        ).unwrap();
        assert_eq!(parsed.system(), 'Y');
        assert_eq!(parsed.external(), "GBMENN");
        assert_eq!(parsed.key_id().to_string(), "HT");
        assert_eq!(parsed.body(), "VBMTJPEEFVJWLUUPAFTSVOHEAQEPEQOKVUAXDAUX");
    }

    #[test]
    fn bad_envelopes_are_rejected() {
        let valid = "KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA";
        assert!(matches!(MessageEnvelope::parse(&valid.replace("KKDUF LJBXA", "KLDUF LJBXA")), Err(MessageError::InvalidSystemIndicator)));
        let mut bad_tail = valid.to_owned();
        bad_tail.replace_range(bad_tail.len()-1.., "Y");
        assert!(matches!(MessageEnvelope::parse(&bad_tail), Err(MessageError::MismatchedIndicators)));
        assert!(matches!(MessageEnvelope::parse("AA"), Err(MessageError::TooShort)));
    }
}
