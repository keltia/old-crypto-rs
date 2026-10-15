use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum Mode {
    /// Russian letters (30-letter Fialka alphabet).
    Russian,
    /// Decimal digits via the numbers-only reduction circuit.
    Numeric,
}

#[derive(Debug, Parser)]
#[command(name = "fialkactl", version, about = "Encrypt and decrypt with the Fialka M-125-3")]
pub struct Opts {
    /// YAML key sheet. Defaults to Polish 3K with the overall/base settings.
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Text mode (Russian letters or decimal digits).
    #[arg(short, long, value_enum, default_value = "russian")]
    pub mode: Mode,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Encrypt text; read stdin if TEXT is omitted.
    Encrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
    /// Decrypt text; read stdin if TEXT is omitted.
    Decrypt {
        #[arg(value_name = "TEXT", trailing_var_arg = true)]
        text: Vec<String>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_modes_and_subcommands() {
        let opts = Opts::try_parse_from(["fialkactl", "--mode", "numeric", "encrypt", "123"]).unwrap();
        assert_eq!(opts.mode, Mode::Numeric);
        assert!(matches!(opts.command, Command::Encrypt { text } if text == ["123"]));
        let opts = Opts::try_parse_from(["fialkactl", "decrypt", "АБВ"]).unwrap();
        assert_eq!(opts.mode, Mode::Russian);
    }
}
