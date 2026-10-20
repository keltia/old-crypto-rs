mod cli;
mod config;

use clap::Parser;
use old_crypto_rs::{Block, helpers::read_input_optional};
use sg_41::{
    SG41, Sg41Config, display_plaintext, format_ciphertext, parse_ciphertext, prepare_plaintext,
};

use cli::{Cli, Command, Mode};

fn convert(config: &Sg41Config, input: &str, encrypt: bool) -> Result<String, Box<dyn std::error::Error>> {
    let machine = SG41::new(config.clone());
    let mut buffer = vec![0; input.len()];

    let size = if encrypt {
        machine.encrypt(&mut buffer, input.as_bytes())
    } else {
        machine.decrypt(&mut buffer, input.as_bytes())
    };

    buffer.truncate(size);

    Ok(String::from_utf8(buffer)?)
}

fn raw_input(text: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !text.chars().all(|ch| ch.is_ascii_alphabetic()) {
        return Err("raw mode requires letters A-Z only".into());
    }

    Ok(text.to_ascii_uppercase())
}

fn run_with_config(cli: Cli, config: &Sg41Config, input: &str) -> Result<String, Box<dyn std::error::Error>> {
    match cli.command {
        Command::Encrypt { grouped, .. } => {
            if grouped && cli.mode == Mode::Raw {
                return Err("--grouped requires --mode text".into());
            }

            let plaintext = match cli.mode {
                Mode::Raw => raw_input(input)?,
                Mode::Text => prepare_plaintext(input).map_err(|(index, ch)| {
                    format!("unsupported plaintext character {ch:?} at index {index}")
                })?,
            };

            let ciphertext = convert(config, &plaintext, true)?;

            Ok(if grouped {
                format_ciphertext(&ciphertext)
            } else {
                ciphertext
            })
        }
        Command::Decrypt { raw_output, .. } => {
            if raw_output && cli.mode == Mode::Raw {
                return Err("--raw-output requires --mode text".into());
            }

            let ciphertext = match cli.mode {
                Mode::Raw => raw_input(input)?,
                Mode::Text => parse_ciphertext(input).map_err(|(index, ch)| {
                    format!("invalid ciphertext character {ch:?} at index {index}")
                })?,
            };

            let plaintext = convert(config, &ciphertext, false)?;

            Ok(if cli.mode == Mode::Text && !raw_output {
                display_plaintext(&plaintext)
            } else {
                plaintext
            })
        }
    }
}

fn run(cli: Cli) -> Result<String, Box<dyn std::error::Error>> {
    let config_path = cli
        .config
        .as_deref()
        .ok_or("missing required --config argument")?;
    let config = config::load_key(config_path)?;

    let argument = match &cli.command {
        Command::Encrypt { text, .. } | Command::Decrypt { text, .. } => text.clone(),
    };

    let input = read_input_optional(argument)?;
    let input = input.trim_end_matches(['\n', '\r']);

    run_with_config(cli, &config, input)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", run(Cli::parse())?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Sg41Config {
        config::parse_key(include_str!("../../config/reference.yaml")).unwrap()
    }

    #[test]
    fn cli_reference_vector_in_raw_mode() {
        let cli = Cli::try_parse_from([
            "sg41ctl", "--config", "unused.yaml", "--mode", "raw",
            "encrypt", "SCHLUESSELGERAETVIEREINSWANDERER",
        ]).unwrap();

        assert_eq!(
            run_with_config(cli, &config(), "SCHLUESSELGERAETVIEREINSWANDERER").unwrap(),
            "IHEPLRETQSDSNDCWHPIVVGLYMHOWSJQS"
        );
    }

    #[test]
    fn text_mode_roundtrips_spaces() {
        let cli = Cli::try_parse_from([
            "sg41ctl", "--config", "unused.yaml", "encrypt", "--grouped",
            "HALLO WELT",
        ]).unwrap();

        let ciphertext = run_with_config(cli, &config(), "HALLO WELT").unwrap();
        assert!(ciphertext.contains(' '));

        let cli = Cli::try_parse_from([
            "sg41ctl", "--config", "unused.yaml", "decrypt", "ignored",
        ]).unwrap();
        assert_eq!(run_with_config(cli, &config(), &ciphertext).unwrap(), "HALLO WELT");
    }

    #[test]
    fn invalid_input_is_not_silently_accepted() {
        let cli = Cli::try_parse_from([
            "sg41ctl", "--config", "unused.yaml", "encrypt", "ignored",
        ]).unwrap();
        assert!(run_with_config(cli, &config(), "A!").is_err());
    }
}
