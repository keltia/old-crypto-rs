# Fialka Step 19 - M-125-3 30<->10 numerical mode

This step implements the M-125-3 NumLock reduction circuit.

## Re-entry wiring

Reference Manual section 4.8, circuit diagram p.112:

    reflector -> card reader input
     1 -> 10    2 -> 29    3 ->  9    4 ->  3    5 -> 28
     6 -> 21    7 -> 22    8 -> 16   12 -> 13   14 ->  1
    15 -> 20   17 ->  5   19 -> 30   20 -> 26   21 ->  6
    23 -> 19   25 -> 15   27 -> 12   28 -> 27   29 -> 11

The connector Ш5 table on p.122 independently confirms:
29->11, 15->20, 28->27, 7->22, and 12->13.

The ten terminal reflector contacts are therefore:

    9, 10, 11, 13, 16, 18, 22, 24, 26, 30

These are the four Magic-Circuit contacts plus fixed reflector loops
9<->22, 10<->11 and 26<->30.

## Numeric keys

The official Russian M-125-3M NumLock keyboard drawing identifies:

    digit:    0  1  2  3  4  5  6  7  8  9
    key:      Х  Ш  У  Г  Н  А  Т  Р  Б  П
    contact: 21 24 19  4 13  1 18 16  2 15  (one-based)

## Electrical processing

One physical keypress may traverse the rotor drum multiple times. Rotors are
stationary throughout all internal re-entry passes and step exactly once after
a terminal numerical result is produced.

A cycle detector is included for malformed configurations.

## Sources

- Paul Reuvers & Marc Simons, *The Fialka M-125 Reference Manual*, v2.0,
  section 4.8 (pp.110-112) and connector Ш5 table (p.122):
  https://www.cryptomuseum.com/pub/files/Fialka_200.pdf
- Crypto Museum, Russian M-125-3M:
  https://www.cryptomuseum.com/crypto/fialka/m125_3/rus.htm
- Crypto Museum, M-125-3 overview:
  https://www.cryptomuseum.com/crypto/fialka/m125_3/
