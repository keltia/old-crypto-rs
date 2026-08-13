//! CLI configuration structs
//!
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "sigabactl",
    version,
    about = "Encrypt and decrypt text with SIGABA"
)]
pub struct Opts {
    /// YAML file containing the complete initial rotor configuration.
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,

    /// YAML rotor wiring dataset. Uses the embedded reference set when omitted.
    #[arg(short, long, value_name = "FILE")]
    pub rotors: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotor_file_is_optional() {
        let opts = Opts::try_parse_from([
            "sigabactl",
            "--config",
            "key.yaml",
            "encrypt",
            "HELLO",
        ])
        .unwrap();

        assert_eq!(opts.config, PathBuf::from("key.yaml"));
        assert_eq!(opts.rotors, None);
    }

    #[test]
    fn rotor_file_can_be_selected_independently_from_key_config() {
        let opts = Opts::try_parse_from([
            "sigabactl",
            "--config",
            "key.yaml",
            "--rotors",
            "custom-rotors.yaml",
            "decrypt",
            "ABCDE",
        ])
        .unwrap();

        assert_eq!(opts.rotors, Some(PathBuf::from("custom-rotors.yaml")));
    }
}
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt plaintext. Reads standard input when TEXT is omitted.
    Encrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
    /// Decrypt ciphertext. Reads standard input when TEXT is omitted.
    Decrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
}
