# sigabactl CLI tool

`sigabactl` encrypts and decrypts text with the SIGABA simulator using a complete initial configuration from YAML.

```sh
cargo run -p sigaba --bin sigabactl -- \
  --config crates/sigaba/config/reference.yaml encrypt "HELLO WORLD"
# FLQGFQUEQCH

cargo run -p sigaba --bin sigabactl -- \
  --config crates/sigaba/config/reference.yaml decrypt "FLQGF QUEQC H"
# HELLO WORLD
```

If text is omitted, the command reads it from standard input:

```sh
printf 'HELLO WORLD\n' | cargo run -p sigaba --bin sigabactl -- \
  --config crates/sigaba/config/reference.yaml encrypt
```

## Usage

```text
Encrypt and decrypt text with SIGABA

Usage: sigabactl --config <FILE> <COMMAND>

Commands:
  encrypt  Encrypt plaintext. Reads standard input when TEXT is omitted
  decrypt  Decrypt ciphertext. Reads standard input when TEXT is omitted
  help     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <FILE>  YAML file containing the complete initial rotor configuration
  -h, --help           Print help
  -V, --version        Print version
```

## Configuration

The YAML file contains one named rotor set, five cipher rotors, five control rotors, and five index rotors. 

Large rotors use the standard ECM designation: `N0` through `N9` for normal orientation and `R0` through `R9` for 
reversed orientation. Large-rotor positions use `A` through `Z`, while index positions use `0` through `9`. 
Rotor arrays are ordered by physical slot from left to right. IDs must be unique across the two large-rotor banks 
and within the index bank.

The reference settings from the Pekelney/Dunn paper in 1999 is also included as `config/reference.yaml`.


