# Step 21 — Historical message commands in `sg41ctl`

The existing `encrypt` and `decrypt` commands remain unchanged. New
`message-encrypt` and `message-decrypt` commands use the Step 20 transmission
functions and a YAML file containing historical key material.

## Key YAML schema

```yaml
monthly_rows: # exactly 26 rows, alphabetical A-Z order
  - '0000000000000000000000000' # A: example only, not historical data
  # ... 25 further 25-bit rows
daily_key: ACHUKW
sending_station:
  wheel_5: 18
  wheel_6: 37
disguise_alphabet: SYIZBJEHOCKUGPDRVFTXLNMWAQ
disguise_digits: '96585138157834794289563262'
```

The schematic monthly row above is **not** the historical March 1945 monthly
pin table. Do not use zero rows when claiming historical interoperability.
The historical disguise alphabet and digits are independently established by
Figure 12 of the 1945 key table.

## Usage

```sh
sg41ctl message-encrypt --key message-key.yaml --indicator KNVP --padding ABCD --filler WT 'HALLO WELTS'
sg41ctl message-decrypt --key message-key.yaml 'HEADERANDCIPHERTEXT'
sg41ctl message-decrypt --key message-key.yaml --raw-output < received.txt
```

`--indicator`, `--padding`, and `--filler` are supplied explicitly; the CLI
never generates randomness. Padding must be exactly the number of plaintext
letters needed to complete a five-character group (0–4). Decryption retains
padding because the original plaintext length is not transmitted. `--raw-output`
keeps the machine's J characters instead of converting them to spaces.

The new commands use `read_input_optional` for text from arguments or stdin,
`noyalib` for parsing, and the validated transmission layer for framing.
The historical `--mode` and `--config` options apply to the old raw/text
commands only; message commands require `--key` instead.
