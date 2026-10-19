//! End-to-end public-API regressions for the derived-indicator message profile.

use m209::{
    KeyId, KeyListError, KeyStore, MessageEnvelope, MessageError,
    decipher_message, derive_internal_indicator, encipher_message,
};

const KEY_STORE: &str = include_str!("../config/key-list-reference.yaml");
const TRANSMITTED: &str =
    "KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA";

fn reference_keys() -> KeyStore {
    KeyStore::from_yaml(KEY_STORE).expect("reference key list is valid")
}

#[test]
fn complete_published_message_through_public_api() {
    let keys = reference_keys();
    let id = KeyId::parse("XA").unwrap();
    let derived = derive_internal_indicator(keys.get(id).unwrap(), 'K', "DUFLJB").unwrap();

    assert_eq!(derived.intermediate(), "PEQGBJGCDFUP");
    assert_eq!(derived.letters(), "PEQGBJ");

    let sent = encipher_message(
        &keys, id, 'K', "DUFLJB", "OPERATION ZEBRA STARTS AT SUNSET",
    ).unwrap();

    assert_eq!(sent.padding(), 3);
    assert_eq!(sent.transmit(), TRANSMITTED);

    let received = decipher_message(&keys, TRANSMITTED).unwrap();
    assert_eq!(received.envelope().key_id(), id);
    assert_eq!(received.internal(), "PEQGBJ");
    assert_eq!(&received.raw()[..32], "OPERATIONZZEBRAZSTARTSZATZSUNSET");
    assert_eq!(received.raw().len(), 35);
}

#[test]
fn grouped_and_ungrouped_envelopes_are_equivalent() {
    let keys = reference_keys();
    let compact = TRANSMITTED.replace(' ', "");

    let grouped = MessageEnvelope::parse(TRANSMITTED).unwrap();
    let ungrouped = MessageEnvelope::parse(&compact).unwrap();

    assert_eq!(grouped, ungrouped);
    assert_eq!(grouped.transmit(), TRANSMITTED);
    assert_eq!(decipher_message(&keys, TRANSMITTED).unwrap().raw(),
               decipher_message(&keys, &compact).unwrap().raw());
}

#[test]
fn unknown_key_id_is_not_replaced_with_default_key() {
    let keys = reference_keys();
    let unknown = TRANSMITTED.replace("LJBXA", "LJBZZ");
    let parsed = MessageEnvelope::parse(&unknown).unwrap();

    assert_eq!(parsed.key_id(), KeyId::parse("ZZ").unwrap());
    assert!(matches!(
        decipher_message(&keys, &unknown),
        Err(MessageError::Key(KeyListError::UnknownIdentifier(_)))
    ));
}

#[test]
fn malformed_envelopes_and_ciphertext_are_rejected() {
    let compact = TRANSMITTED.replace(' ', "");
    let truncated_body = format!("{}{}{}", &compact[..10], &compact[10..44], &compact[45..]);

    assert!(matches!(
        MessageEnvelope::parse(&truncated_body),
        Err(MessageError::IncompleteBodyGroup)
    ));

    let changed_trailer = format!("{}{}", &compact[..compact.len()-1], "Y");
    assert!(matches!(
        MessageEnvelope::parse(&changed_trailer),
        Err(MessageError::MismatchedIndicators)
    ));

    assert!(matches!(
        MessageEnvelope::parse(&compact.replacen('K', "?", 1)),
        Err(MessageError::Text(_))
    ));
}
