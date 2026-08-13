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

    #[command(subcommand)]
    pub command: Command,
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
