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

The embedded Pekelney/Dunn rotor wiring is used by default. Select another
validated wiring dataset independently with `--rotors`:

```sh
cargo run -p sigaba --bin sigabactl -- \
  --config key.yaml \
  --rotors custom-rotors.yaml encrypt "HELLO WORLD"
```

If text is omitted, the command reads it from standard input:

```sh
printf 'HELLO WORLD\n' | cargo run -p sigaba --bin sigabactl -- \
  --config crates/sigaba/config/reference.yaml encrypt
```

## Usage

```text
Encrypt and decrypt text with SIGABA

Usage: sigabactl [OPTIONS] --config <FILE> <COMMAND>

Commands:
  encrypt  Encrypt plaintext. Reads standard input when TEXT is omitted
  decrypt  Decrypt ciphertext. Reads standard input when TEXT is omitted
  help     Print this message or the help of the given subcommand(s)

Options:
  -c, --config <FILE>  YAML file containing the complete initial rotor configuration
  -r, --rotors <FILE>  YAML rotor wiring dataset. Uses the embedded reference set when omitted
  -h, --help           Print help
  -V, --version        Print version
```

## Configuration

The key YAML contains five cipher rotors, five control rotors, and five index
rotors. It may also contain `rotor_set`, an optional dataset-name guard. If
present, its value must match the selected rotor dataset's `name`.

Large rotors use the standard ECM designation: `N0` through `N9` for normal orientation and `R0` through `R9` for 
reversed orientation. Large-rotor positions use `A` through `Z`, while index positions use `0` through `9`. 
Rotor arrays are ordered by physical slot from left to right. IDs must be unique across the two large-rotor banks 
and within the index bank.

Rotor wiring YAML uses the versioned schema demonstrated by
`config/rotors/pekelney-reference.yaml`: ten large rotors with 26-letter
permutations and five index rotors with quoted ten-digit permutations. The
reference settings from the Pekelney/Dunn paper in 1999 are included as
`config/reference.yaml`.

