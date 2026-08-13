//! CLI tool for the SIGABA simulator
//!
mod cli;
mod config;

use std::{
    error::Error,
    io::{self, Read},
};

use clap::Parser;

use sigaba::Sigaba;

use cli::{Command, Opts};
use config::load_config;

fn main() {
    if let Err(error) = run(Opts::parse()) {
        eprintln!("sigabactl: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Opts) -> Result<(), Box<dyn Error>> {
    let machine = Sigaba::new(load_config(&cli.config)?);
    let (encrypt, words) = match cli.command {
        Command::Encrypt { text } => (true, text),
        Command::Decrypt { text } => (false, text),
    };
    let input = read_input(words)?;
    let input = input.trim_end_matches(['\r', '\n']);

    let output = if encrypt {
        machine.encrypt_text(input)?
    } else {
        machine.decrypt_text(input)?
    };
    println!("{output}");
    Ok(())
}

fn read_input(words: Vec<String>) -> io::Result<String> {
    if words.is_empty() {
        let mut input = String::new();
        io::stdin().read_to_string(&mut input)?;
        Ok(input)
    } else {
        Ok(words.join(" "))
    }
}

