use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputMode {
    /// Convert letters only; reject unsupported input.
    Raw,

    /// Use historical word-space and grouping conventions.
    Text,
}

#[derive(Debug, Parser)]
#[command(name = "m209ctl", about = "Hagelin M-209 cipher-machine simulator")]
pub struct Cli {
    /// YAML key file containing pins, wheel indicators, and 27 drum lug pairs.
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Select raw A-Z contacts or historical text conventions.
    #[arg(long, value_enum, default_value_t = OutputMode::Text, global = true)]
    pub mode: OutputMode,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encipher from the key's initial wheel positions.
    Encrypt {
        /// Input text; reads standard input when omitted.
        text: Option<String>,

        /// Emit five-letter ciphertext groups (text mode only).
        #[arg(long)]
        grouped: bool,
    },

    /// Decipher from the key's initial wheel positions.
    Decrypt {
        /// Ciphertext; reads standard input when omitted.
        text: Option<String>,

        /// Preserve raw Z letters instead of displaying them as spaces.
        #[arg(long)]
        raw_output: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn accepts_commands_and_modes() {
        let cli = Cli::try_parse_from(["m209ctl", "--mode", "raw", "encrypt", "ABC"])
            .unwrap();
        assert_eq!(cli.mode, OutputMode::Raw);
        assert!(matches!(cli.command, Command::Encrypt { .. }));

        let cli = Cli::try_parse_from(["m209ctl", "decrypt", "--raw-output"]).unwrap();
        assert!(matches!(cli.command, Command::Decrypt { raw_output: true, .. }));
    }
}
