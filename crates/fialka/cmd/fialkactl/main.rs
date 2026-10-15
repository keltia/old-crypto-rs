//! CLI for the Fialka M-125-3 simulator.
mod cli;
mod config;

use std::{error::Error, io::{self, Read}};
use clap::Parser;
use fialka::Fialka;
use cli::{Command, Mode, Opts};
use config::load_config;

fn main() {
    if let Err(error) = run(Opts::parse()) {
        eprintln!("fialkactl: {error}");
        std::process::exit(1);
    }
}

fn run(opts: Opts) -> Result<(), Box<dyn Error>> {
    let machine = Fialka::new(load_config(opts.config.as_deref())?);
    let (encrypt, words) = match opts.command {
        Command::Encrypt { text } => (true, text),
        Command::Decrypt { text } => (false, text),
    };
    let input = read_input(&words)?;
    let input = input.trim_end_matches(['\r', '\n']);
    let output = match (opts.mode, encrypt) {
        (Mode::Russian, true) => machine.encrypt_russian_letters(input)?,
        (Mode::Russian, false) => machine.decrypt_russian_letters(input)?,
        (Mode::Numeric, true) => machine.encrypt_numeric(input)?,
        (Mode::Numeric, false) => machine.decrypt_numeric(input)?,
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
