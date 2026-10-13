//! CLI option definitions for kl7ctl.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "kl7ctl",
    version,
    about = "Encrypt, decrypt, and inspect TSEC/KL-7 cipher operations"
)]
pub struct Opts {
    /// YAML key sheet configuration file. Uses default reference setup if omitted.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt plaintext into 5-letter cipher groups. Reads standard input when TEXT is omitted.
    Encrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
    /// Decrypt ciphertext. Reads standard input when TEXT is omitted.
    Decrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
    /// Print cycle-by-cycle stepping and rotor positions trace.
    Trace {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
    /// Validate and display a YAML key sheet configuration.
    VerifyKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_is_optional_in_cli() {
        let opts = Opts::try_parse_from(["kl7ctl", "encrypt", "HELLO"]).unwrap();
        assert_eq!(opts.config, None);
        assert!(matches!(opts.command, Command::Encrypt { .. }));
    }

    #[test]
    fn config_with_flag() {
        let opts = Opts::try_parse_from([
            "kl7ctl",
            "--config",
            "reference.yaml",
            "decrypt",
            "ABCDE",
        ])
        .unwrap();
        assert_eq!(opts.config, Some(PathBuf::from("reference.yaml")));
    }
}
