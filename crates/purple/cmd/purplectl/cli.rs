//! Clap command-line definitions for purplectl.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(name = "purplectl", version, about = "Encrypt and decrypt text with PURPLE")]
pub struct Opts {
    /// YAML key sheet. Uses the December 1941 reference configuration if omitted.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt uppercase text. Reads standard input when TEXT is omitted.
    Encrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
    /// Decrypt uppercase text. Reads standard input when TEXT is omitted.
    Decrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_subcommand_and_text() {
        let opts = Opts::try_parse_from(["purplectl", "encrypt", "HELLO"]).unwrap();
        assert!(opts.config.is_none());
        assert!(matches!(opts.command, Command::Encrypt { text } if text == ["HELLO"]));
    }
    #[test]
    fn parses_key_sheet() {
        let opts = Opts::try_parse_from(["purplectl", "--config", "key.yaml", "decrypt", "ABC"]).unwrap();
        assert_eq!(opts.config, Some(PathBuf::from("key.yaml")));
    }
    #[test]
    fn old_flags_are_not_valid() {
        assert!(Opts::try_parse_from(["purplectl", "--encrypt", "--text", "ABC"]).is_err());
    }
}
