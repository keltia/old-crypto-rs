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
    /// Single mechanical key YAML for the legacy body-only commands.
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    /// Select raw A-Z contacts or historical text conventions for body-only commands.
    #[arg(long, value_enum, default_value_t = OutputMode::Text, global = true)]
    pub mode: OutputMode,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encipher a message body using the single mechanical key.
    Encrypt {
        /// Input text; reads standard input when omitted.
        text: Option<String>,

        /// Emit five-letter ciphertext groups (text mode only).
        #[arg(long)]
        grouped: bool,
    },

    /// Decipher a message body using the single mechanical key.
    Decrypt {
        /// Ciphertext; reads standard input when omitted.
        text: Option<String>,

        /// Preserve raw Z letters instead of displaying them as spaces.
        #[arg(long)]
        raw_output: bool,
    },

    /// Encipher a complete twelve-contact derived-indicator message.
    MessageEncrypt {
        /// YAML collection of named, checked daily keys.
        #[arg(long)]
        key_store: PathBuf,

        /// Two-letter daily key identifier.
        #[arg(long)]
        key_id: String,

        /// One uppercase system-indicator letter.
        #[arg(long)]
        system: char,

        /// Six-letter external wheel indicator.
        #[arg(long)]
        external: String,

        /// Plaintext; reads standard input when omitted.
        text: Option<String>,
    },

    /// Decipher a complete transmitted message using its embedded indicators.
    MessageDecrypt {
        /// YAML collection of named, checked daily keys.
        #[arg(long)]
        key_store: PathBuf,

        /// Preserve raw Z letters rather than displaying them as spaces.
        #[arg(long)]
        raw_output: bool,

        /// Grouped transmitted message; reads standard input when omitted.
        text: Option<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_commands_and_modes() {
        let cli = Cli::try_parse_from(["m209ctl", "--mode", "raw", "encrypt", "ABC"])
            .unwrap();
        assert_eq!(cli.mode, OutputMode::Raw);
        assert!(matches!(cli.command, Command::Encrypt { .. }));

        let cli = Cli::try_parse_from(["m209ctl", "decrypt", "--raw-output"]).unwrap();
        assert!(matches!(cli.command, Command::Decrypt { raw_output: true, .. }));
    }

    #[test]
    fn parses_complete_message_commands() {
        let cli = Cli::try_parse_from([
            "m209ctl", "message-encrypt", "--key-store", "keys.yaml",
            "--key-id", "XA", "--system", "K", "--external", "DUFLJB",
            "OPERATION ZEBRA STARTS AT SUNSET",
        ]).unwrap();
        assert!(matches!(cli.command, Command::MessageEncrypt { .. }));

        let cli = Cli::try_parse_from([
            "m209ctl", "message-decrypt", "--key-store", "keys.yaml", "--raw-output",
        ]).unwrap();
        assert!(matches!(cli.command, Command::MessageDecrypt { raw_output: true, .. }));
    }

    #[test]
    fn indicator_arguments_are_required() {
        assert!(Cli::try_parse_from([
            "m209ctl", "message-encrypt", "--key-store", "keys.yaml", "--key-id", "XA",
        ]).is_err());
    }
}
