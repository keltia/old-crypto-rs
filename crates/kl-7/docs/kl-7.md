# TSEC/KL-7 (ADONIS / POLLUX) Documentation

## Overview

The **TSEC/KL-7** (initially developed as AFSAM-7 in 1952 by AFSA/NSA) was the primary tactical and strategic off-line cipher machine used by the United States armed forces, CIA, FBI, and NATO allies throughout the Cold War until its retirement in 1983.

## Mechanical & Electrical Architecture

### 1. 8-Rotor Drum (`KLK-7`)
- **36 Contacts**: Each rotor possesses 36 flat-face contacts on the left and 36 spring-loaded pins on the right, providing complex substitution permutations.
- **Rotor 4 Stationary**: The rotor in drum position 4 (index 3) is fitted with a wide metal ring and remains permanently stationary during operation.
- **Rotors 1, 2, 3, 5, 6, 7, 8 Dynamic**: The remaining 7 rotors step dynamically in irregular motion.

### 2. Stepping Unit & Actuator Switches (`KLA-7`)
- **7 Sensing Switches ($S_a / S_b$)**: Each movable rotor slot is equipped with a two-level sensing switch that reads the outer plastic notch rings.
- **11 Exchangeable Notch Rings**: Labeled 1 through 11, each with a distinct pattern of cams (raised lugs) and notches (gaps).
- **Relay Stepping Logic**:
  - Rotor 1 steps if: `!s_7 && (!s_2 || !s_3)`
  - Rotor 2 steps if: `!s_5 || !s_6`
  - Rotor 3 steps if: `s_2 || s_6`
  - Rotor 4: Stationary
  - Rotor 5 steps if: `!s_2 || !s_3`
  - Rotor 6 steps if: `!s_1 || s_3`
  - Rotor 7 steps if: `s_1 || s_5`
  - Rotor 8 steps if: `!s_4 && (!s_2 || !s_3)`
- **Anti-Stall Guarantee**: The circuit logic guarantees that at least two rotors step on every cycle.

### 3. Re-Entry (Re-Flexing) Maze
- The left and right cipher unit endplates contain **26 alphabet contacts** and **10 loop-back contacts** (wires 0 through 9).
- When a signal exits the 8-rotor drum on a re-entry contact, it is routed via the external stepping harness back to the corresponding loop contact on the entry side for another pass through the drum.
- Signals typically perform between 1 and 11 passes before terminating on an alphabet contact.

### 4. Permutor Board & Direction Switching
- A sliding permutor contact board reverses the electrical signal direction through the rotor drum between **Encipher** (left-to-right) and **Decipher** (right-to-left) modes.

## Operational Procedures

### POLLUX Procedure (Tactical)
1. Set daily key parameters (rotors, alphabet ring settings, notch rings, and notch ring settings).
2. Set the drum to the message key alignment indicated in clear in the message header.
3. Encipher or decipher the message body directly.

### ADONIS Procedure (Strategic)
1. Set daily key parameters and set the drum to the **Basic Rotor Alignment**.
2. Encipher the random spelled-out message key to produce the encrypted indicator (e.g. 36-45 letter check).
3. Reset the drum to the message key alignment to encipher or decipher the text.

## Usage in Rust

```rust
use kl_7::{Kl7, Kl7Config};

// Load reference configuration (e.g., USS Beagle test setup)
let config = Kl7Config::uss_beagle();
let kl7 = Kl7::new(config);

// Encipher plaintext into 5-letter cipher groups
let ciphertext = kl7.encrypt_text("ATTACK AT DAWN")?;
println!("Ciphertext: {}", ciphertext);

// Decipher ciphertext back to plaintext
let plaintext = kl7.decrypt_text(&ciphertext)?;
assert_eq!(plaintext, "ATTACK AT DAWN");
```

## CLI Usage (`kl7ctl`)

```bash
# Encrypt message into 5-letter cipher groups
kl7ctl --config config/reference.yaml encrypt "TOP SECRET DISPATCH"

# Decrypt ciphertext
kl7ctl --config config/reference.yaml decrypt "TMRDV VCGMD BL"

# Trace cycle-by-cycle stepping and rotor window positions
kl7ctl trace "HELLO"

# Verify a YAML key sheet
kl7ctl --config config/reference.yaml verify-key
```
