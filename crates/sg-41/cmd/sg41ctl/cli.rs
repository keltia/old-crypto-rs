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
    /// Encrypt and frame a complete historical message using YAML key material.
    MessageEncrypt {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        indicator: String,
        #[arg(long, default_value = "")]
        padding: String,
        #[arg(long)]
        filler: String,
        text: Option<String>,
    },
    /// Recover a historical message from its transmitted header and ciphertext.
    MessageDecrypt {
        #[arg(long)]
        key: PathBuf,
        #[arg(long)]
        raw_output: bool,
        text: Option<String>,
    },
}

#[derive(Debug, Parser)]
#[command(name = "sg41ctl", about = "Schlüsselgerät 41 cipher simulator")]
pub struct Opts {
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
        let cli = Opts::try_parse_from([
            "sg41ctl", "--config", "reference.yaml", "encrypt", "ABC",
        ])
        .unwrap();
        assert_eq!(cli.config, Some(PathBuf::from("reference.yaml")));
        assert!(matches!(cli.command, Command::Encrypt { .. }));

        let cli = Opts::try_parse_from([
            "sg41ctl", "decrypt", "--mode", "raw", "--config", "reference.yaml", "ABC",
        ])
        .unwrap();
        assert_eq!(cli.mode, Mode::Raw);
        assert!(matches!(cli.command, Command::Decrypt { .. }));
    }

    #[test]
    fn historical_commands_parse_without_old_config() {
        let opts = Opts::try_parse_from([
            "sg41ctl", "message-encrypt", "--key", "message.yaml",
            "--indicator", "KNVP", "--filler", "WT", "TEST",
        ]).unwrap();
        assert!(matches!(opts.command, Command::MessageEncrypt { .. }));
    }

    #[test]
    fn config_is_checked_by_runtime_not_clap() {
        let cli = Opts::try_parse_from(["sg41ctl", "encrypt", "ABC"]).unwrap();
        assert!(cli.config.is_none());
    }
}
