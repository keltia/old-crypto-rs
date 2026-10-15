//! CLI tool for the PURPLE cipher simulator (`purplectl`).
mod cli;
mod config;

use std::{error::Error, io::{self, Read}};
use clap::Parser;
use purple::Purple;
use cli::{Command, Opts};
use config::load_config;

fn main() {
    if let Err(error) = run(Opts::parse()) {
        eprintln!("purplectl: {error}");
        std::process::exit(1);
    }
}

fn run(opts: Opts) -> Result<(), Box<dyn Error>> {
    let machine = Purple::new(load_config(opts.config.as_deref())?);
    let (encrypt, words) = match opts.command {
        Command::Encrypt { text } => (true, text),
        Command::Decrypt { text } => (false, text),
    };
    let input = read_input(&words)?;
    let input = input.trim_end_matches(['\r', '\n']);
    let output = if encrypt {
        machine.encrypt_text(input)?
    } else {
        machine.decrypt_text(input)?
    };
    println!("{output}");
    Ok(())
}

fn read_input(words: &[String]) -> io::Result<String> {
    if words.is_empty() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input)
    } else {
        Ok(words.join(" "))
    }
}
