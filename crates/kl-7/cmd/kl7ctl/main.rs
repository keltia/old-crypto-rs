//! CLI tool for the TSEC/KL-7 simulator (`kl7ctl`).

mod cli;
mod config;

use std::{
    error::Error,
    io::{self, Read},
};

use clap::Parser;
use kl_7::{Contact26, Kl7, Position36};

use cli::{Command, Opts};
use config::load_config;

fn main() {
    if let Err(error) = run(Opts::parse()) {
        eprintln!("kl7ctl: {error}");
        std::process::exit(1);
    }
}

fn run(cli: Opts) -> Result<(), Box<dyn Error>> {
    let config = load_config(cli.config.as_deref())?;

    match cli.command {
        Command::Encrypt { text } => {
            let machine = Kl7::new(config);
            let input = read_input(&text)?;
            let input = input.trim_end_matches(['\r', '\n']);
            let output = machine.encrypt_text(input)?;
            println!("{output}");
        }
        Command::Decrypt { text } => {
            let machine = Kl7::new(config);
            let input = read_input(&text)?;
            let input = input.trim_end_matches(['\r', '\n']);
            let output = machine.decrypt_text(input)?;
            println!("{output}");
        }
        Command::Trace { text } => {
            let mut core = config.build_core();
            let input = read_input(&text)?;
            let input = input.trim_end_matches(['\r', '\n']);

            println!("Cycle | In  | Out | Drum Positions (Rotors 1..8)             | Stepped");
            println!("------+-----+-----+------------------------------------------+--------");

            for (idx, ch) in input.chars().enumerate() {
                if let Some(contact) = Contact26::from_ascii_letter(ch) {
                    let before_pos: Vec<Position36> = core.rotors().iter().map(|r| r.win_pos()).collect();
                    let enc = core.encipher_contact(contact)?;
                    let pos_str = before_pos
                        .iter()
                        .map(|p| format!("{:>2}", p.to_string()))
                        .collect::<Vec<_>>()
                        .join(" ");

                    println!(
                        "{:>5} |  {}  |  {}  | [{}] | cnt={}",
                        idx + 1,
                        contact.to_ascii_char(),
                        enc.to_ascii_char(),
                        pos_str,
                        core.counter()
                    );
                }
            }
        }
        Command::VerifyKey => {
            println!("Valid TSEC/KL-7 Key Sheet:");
            println!("  Rotors:          {:?}", config.rotors().map(|r| r.to_string()));
            println!("  Alpha Rings:     {:?}", config.alpha_ring_sets().map(|p| p.to_one_based()));
            println!("  Notch Rings:     {:?}", config.notch_rings().map(|r| r.to_number()));
            println!("  Notch Ring Sets: {:?}", config.notch_ring_sets().map(|p| p.to_string()));
            println!("  Initial Drum:    {:?}", config.initial_positions().map(|p| p.to_string()));
            println!("  Operation Mode:  {:?}", config.mode());
        }
    }

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
