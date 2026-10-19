mod cli;
mod config;

use std::io::{self, Read};

use clap::Parser;
use cli::{Cli, Command, OutputMode};
use m209::{Contact, M209Config, decrypt_text, decrypt_text_raw, encrypt_text};

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
    match text {
        Some(text) => Ok(text),
        None => {
            let mut text = String::new();
            io::stdin().read_to_string(&mut text)?;
            Ok(text.trim_end_matches(['\n', '\r']).to_owned())
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let path = cli.config.ok_or("a --config YAML key file is required")?;
    let key = config::load_key(&path)?;

    let result = match cli.command {
        Command::Encrypt { text, grouped } => {
            let text = input_text(text)?;
            match cli.mode {
                OutputMode::Raw => {
                    if grouped { return Err("--grouped requires --mode text".into()); }
                    raw_convert(&key, &text)?
                }
                OutputMode::Text => encrypt_text(&key, &text, grouped)?,
            }
        }
        Command::Decrypt { text, raw_output } => {
            let text = input_text(text)?;
            match cli.mode {
                OutputMode::Raw => raw_convert(&key, &text)?,
                OutputMode::Text if raw_output => decrypt_text_raw(&key, &text)?,
                OutputMode::Text => decrypt_text(&key, &text)?,
            }
        }
    };

    println!("{result}");
    Ok(())
}
