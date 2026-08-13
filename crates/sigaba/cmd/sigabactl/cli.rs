//! CLI configuration structs
//!
use std::path::PathBuf;
use clap::{Parser, Subcommand};
use serde::Deserialize;
use crate::config::{IndexRotor, LargeRotor, RotorSet};

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub rotor_set: RotorSet,
    pub cipher: [LargeRotor; 5],
    pub control: [LargeRotor; 5],
    pub index: [IndexRotor; 5],
}

