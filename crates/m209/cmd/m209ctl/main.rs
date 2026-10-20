mod cli;
mod config;

use std::{fs, io, path::Path};

use clap::Parser;
use cli::{Cli, Command, OutputMode};
use m209::{
    Contact, KeyId, KeyStore, M209Config, decipher_message, decrypt_text,
    decrypt_text_raw, encipher_message, encrypt_text,
};
use old_crypto_rs::helpers::read_input_optional;

fn raw_convert(config: &M209Config, input: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut machine = config.build_machine();
    let mut output = String::with_capacity(input.len());

    for c in input.chars() {
        if !c.is_ascii_alphabetic() {
            return Err(format!("raw mode accepts A-Z only; found {c:?}").into());
        }

        let contact = Contact::new(c.to_ascii_uppercase() as u8 - b'A')
            .expect("validated ASCII letter");
        output.push(machine.convert_contact(contact).letter());
    }

    Ok(output)
}

fn input_text(text: Option<String>) -> io::Result<String> {
    let text = read_input_optional(text)?;
    Ok(text.trim_end_matches(['\n', '\r']).to_owned())
}

fn load_key_store(path: &Path) -> Result<KeyStore, Box<dyn std::error::Error>> {
    Ok(KeyStore::from_yaml(&fs::read_to_string(path)?)?)
}

fn run(cli: Cli) -> Result<String, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Encrypt { text, grouped } => {
            let path = cli.config.ok_or("--config is required for body-only commands")?;
            let key = config::load_key(&path)?;
            let text = input_text(text)?;

            match cli.mode {
                OutputMode::Raw => {
                    if grouped {
                        return Err("--grouped requires --mode text".into());
                    }
                    raw_convert(&key, &text)
                }
                OutputMode::Text => Ok(encrypt_text(&key, &text, grouped)?),
            }
        }
        Command::Decrypt { text, raw_output } => {
            let path = cli.config.ok_or("--config is required for body-only commands")?;
            let key = config::load_key(&path)?;
            let text = input_text(text)?;

            match cli.mode {
                OutputMode::Raw => raw_convert(&key, &text),
                OutputMode::Text if raw_output => Ok(decrypt_text_raw(&key, &text)?),
                OutputMode::Text => Ok(decrypt_text(&key, &text)?),
            }
        }
        Command::MessageEncrypt { key_store, key_id, system, external, text } => {
            let keys = load_key_store(&key_store)?;
            let id = KeyId::parse(&key_id)?;
            let text = input_text(text)?;
            Ok(encipher_message(&keys, id, system, &external, &text)?.transmit())
        }
        Command::MessageDecrypt { key_store, raw_output, text } => {
            let keys = load_key_store(&key_store)?;
            let text = input_text(text)?;
            let message = decipher_message(&keys, &text)?;

            if raw_output {
                Ok(message.raw().to_owned())
            } else {
                Ok(message.display())
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", run(Cli::parse())?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn key_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/key-list-reference.yaml")
    }

    #[test]
    fn complete_message_matches_published_vector() {
        let cli = Cli::try_parse_from([
            "m209ctl", "message-encrypt", "--key-store", key_path().to_str().unwrap(),
            "--key-id", "XA", "--system", "K", "--external", "DUFLJB",
            "OPERATION ZEBRA STARTS AT SUNSET",
        ]).unwrap();

        let transmitted = run(cli).unwrap();
        assert_eq!(
            transmitted,
            "KKDUF LJBXA KBMUN ODDDC YWLVM RBVUS QYRHT XNZUI HXXXX KKDUF LJBXA"
        );

        let cli = Cli::try_parse_from([
            "m209ctl", "message-decrypt", "--key-store", key_path().to_str().unwrap(),
            "--raw-output", &transmitted,
        ]).unwrap();
        let plain = run(cli).unwrap();
        assert_eq!(&plain[..32], "OPERATIONZZEBRAZSTARTSZATZSUNSET");
        assert_eq!(plain.len(), 35); // Post-encryption X padding remains ambiguous.
    }

    #[test]
    fn missing_key_store_is_not_silently_replaced_with_single_key() {
        let cli = Cli::try_parse_from([
            "m209ctl", "message-decrypt", "--key-store", "does-not-exist.yaml", "ABCD",
        ]).unwrap();
        assert!(run(cli).is_err());
    }
}
