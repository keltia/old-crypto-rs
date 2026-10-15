# Fialka M-125-3

A typed Rust simulation of the **Fialka M-125-3** cipher machine, maintained as the `fialka` crate in the [`old-crypto-rs`](https://github.com/keltia/old-crypto-rs) workspace.

## Implementation

The simulator models the 30-contact electrical machine, its ten-rotor drum and stepping mechanism, and the configuration of removable rotor cores. It includes:

- **Polish 3K** and **Czechoslovak 6K** adjustable rotor series, including their electrical and mechanical data.
- Ten physical rotor slots, with independently configurable wheel bodies and electrical cores (PROTON-2 core mixing), core side, core/ring settings, and rotor positions.
- Configurable punched-card commutator, entry disc, reflector, and distinct coding/decoding signal paths.
- Russian-letter text conversion and the M-125-3 numbers-only reduction circuit.
- A reset-per-call public `Fialka` adapter and a `Block` compatibility interface.

The implementation operates on **30 electrical contacts**. Its public byte-oriented `Block` interface accepts values `0..=29`, *not* ASCII-encoded letters. Text processing is available through separate methods.

## Using the library

A base configuration is convenient for tests and demonstrations. It is **not an operational historical daily key**.

```rust
use fialka::{Commutator, Fialka, FialkaConfig, RotorSeries};

let config = FialkaConfig::overall_base(
    RotorSeries::Polish3K,
    Commutator::identity(),
);
let machine = Fialka::new(config);

// Russian text (lowercase input is accepted).
let plaintext = "ПРИВЕТ";
let ciphertext = machine.encrypt_russian_letters(plaintext)?;
let recovered = machine.decrypt_russian_letters(&ciphertext)?;
assert_eq!(recovered, plaintext);

// Numbers-only mode has a separate interface.
let ciphertext = machine.encrypt_numeric("12345")?;
let recovered = machine.decrypt_numeric(&ciphertext)?;
assert_eq!(recovered, "12345");
# Ok::<(), Box<dyn std::error::Error>>(())
```

To use the raw-contact `Block` interface:

```rust
use fialka::{Block, Commutator, Fialka, FialkaConfig, RotorSeries};

let machine = Fialka::new(FialkaConfig::overall_base(
    RotorSeries::Czechoslovak6K,
    Commutator::identity(),
));
let input = [0_u8, 1, 2, 3, 4];
let mut encrypted = [0_u8; 5];
let len = machine.encrypt(&mut encrypted, &input);
let mut recovered = [0_u8; 5];
assert_eq!(machine.decrypt(&mut recovered, &encrypted[..len]), len);
assert_eq!(&recovered[..len], &input[..len]);
```

Each public `encrypt`/`decrypt` operation begins at the configured initial rotor positions. The `Block` methods process at most the destination length, and stop at the first invalid contact. The more detailed `FialkaConfig::new` constructor accepts an array of ten `RotorConfig` values and validates distinct wheel-body and wiring-core identities.

The Russian-letter alphabet has 30 supported letters; **Ё, Ъ, and Э are unsupported** and produce an error rather than being silently transformed. The text APIs are not general punctuation or whitespace normalizers.

## Testing

From the workspace root:

```sh
cargo test -p fialka
cargo clippy -p fialka --all-targets -- -D warnings
```

For the complete workspace:

```sh
cargo test --workspace
```

## References and further reading

- [Crypto Museum — Fialka](https://www.cryptomuseum.com/crypto/fialka/index.htm)
- [Cipher Machines and Cryptology — Fialka](https://www.ciphermachinesandcryptology.com/en/fialka.htm)
- [Project source and tests](https://github.com/keltia/old-crypto-rs/tree/develop/crates/fialka/src)

This crate reproduces the supported machine model for historical study. It is not intended for modern secure communications.
