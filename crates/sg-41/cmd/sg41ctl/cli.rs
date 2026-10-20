//! Command-line options for the SG-41 simulator.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Mode {
    /// Encrypt/decrypt ASCII letters without historical text substitution.
    Raw,
    /// Apply historical SG-41 German plaintext conventions.
    Text,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt the input text, or read from standard input.
    Encrypt {
        text: Option<String>,

        /// Group ciphertext into five-letter groups (text mode only).
        #[arg(long)]
        grouped: bool,
    },
    /// Decrypt input ciphertext, or read from standard input.
    Decrypt {
        text: Option<String>,

        /// Preserve the electrical J instead of displaying spaces (text mode only).
        #[arg(long)]
        raw_output: bool,
    },
}

#[derive(Debug, Parser)]
#[command(name = "sg41ctl", about = "Schlüsselgerät 41 cipher simulator")]
pub struct Cli {
    /// YAML file containing all six wheel windows and pin patterns.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[arg(long, value_enum, default_value_t = Mode::Text, global = true)]
    pub mode: Mode,

    #[command(subcommand)]
    pub command: Command,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_global_options_before_and_after_subcommand() {
        let cli = Cli::try_parse_from([
            "sg41ctl", "--config", "reference.yaml", "encrypt", "ABC",
        ])
        .unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("reference.yaml")));
        assert!(matches!(cli.command, Command::Encrypt { .. }));

        let cli = Cli::try_parse_from([
            "sg41ctl", "decrypt", "--mode", "raw", "--config", "reference.yaml", "ABC",
        ])
        .unwrap();
        assert_eq!(cli.mode, Mode::Raw);
        assert!(matches!(cli.command, Command::Decrypt { .. }));
    }

    #[test]
    fn config_is_checked_by_runtime_not_clap() {
        let cli = Cli::try_parse_from(["sg41ctl", "encrypt", "ABC"]).unwrap();
        assert!(cli.config.is_none());
    }
}
