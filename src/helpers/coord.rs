//! Trait representing the coordinate symbols used in 5x5 and 6x6 square ciphers.
//! 

/// Marker type representing the ADFGX coordinate system for 5×5 Polybius square ciphers.
///
/// This marker type implements the [`Coordinates`] trait with the coordinate symbols set to
/// "ADFGX". These five letters were chosen for use in the ADFGX cipher during World War I
/// because they sound very different in Morse code, reducing transmission errors.
///
/// # Coordinate System
///
/// The ADFGX system uses a 5×5 grid where each cell is identified by a pair of coordinates:
/// - First coordinate (row): A, D, F, G, or X
/// - Second coordinate (column): A, D, F, G, or X
///
/// This creates 25 possible positions (5×5), perfect for the 25-letter alphabet used in
/// classical ciphers (typically I/J are combined).
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::Coordinates;
/// # use old_crypto_rs::helpers::ADFGX;
///
/// // Access the coordinate symbols
/// assert_eq!(ADFGX::SYMBOLS, b"ADFGX");
/// assert_eq!(ADFGX::SYMBOLS.len(), 5);
///
/// // Example grid coordinates:
/// // Position (0,0) = "AA"
/// // Position (2,3) = "FG"
/// // Position (4,4) = "XX"
/// ```
///
/// # Historical Context
///
/// The ADFGX cipher was invented by Colonel Fritz Nebel in March 1918 for the German Army.
/// The specific letters A, D, F, G, X were selected because their Morse code representations
/// are maximally distinct:
/// - A: ·−
/// - D: −··
/// - F: ··−·
/// - G: −−·
/// - X: −··−
///
/// This design minimized transcription errors during radio transmission in battlefield
/// conditions.
///
/// # Grid Size
///
/// This coordinate system supports a 5×5 = 25 character grid, suitable for:
/// - Standard 25-letter alphabets (I/J combined)
/// - Modified alphabets with one character removed
///
/// For larger character sets including digits, see [`ADFGVX`].
///
/// # See Also
///
/// * [`ADFGVX`] - Extended 6×6 version for 36 characters
/// * [`Numeric5`] - Numeric coordinate system for 5×5 grids
/// * [`Coordinates`] - The trait definition
///
#[derive(Debug)]
pub struct ADFGX;

/// Marker type representing the ADFGVX coordinate system for 6×6 Polybius square ciphers.
///
/// This marker type implements the [`Coordinates`] trait with the coordinate symbols set to
/// "ADFGVX". This is an extension of the ADFGX system, adding the letter 'V' to support
/// larger character sets including digits.
///
/// # Coordinate System
///
/// The ADFGVX system uses a 6×6 grid where each cell is identified by a pair of coordinates:
/// - First coordinate (row): A, D, F, G, V, or X
/// - Second coordinate (column): A, D, F, G, V, or X
///
/// This creates 36 possible positions (6×6), enough for the complete alphabet (26 letters)
/// plus digits (10 numbers).
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::Coordinates;
/// # use old_crypto_rs::helpers::ADFGVX;
///
/// // Access the coordinate symbols
/// assert_eq!(ADFGVX::SYMBOLS, b"ADFGVX");
/// assert_eq!(ADFGVX::SYMBOLS.len(), 6);
///
/// // Example grid coordinates:
/// // Position (0,0) = "AA"
/// // Position (3,5) = "GX"
/// // Position (5,5) = "XX"
/// ```
///
/// # Historical Context
///
/// The ADFGVX cipher was introduced by the German Army in June 1918 as an enhancement of
/// the ADFGX cipher. The addition of 'V' expanded the grid from 5×5 to 6×6, allowing
/// inclusion of all 26 letters of the alphabet plus the 10 digits (0-9), making the cipher
/// more versatile for military communications that included map coordinates and numeric data.
///
/// The letter 'V' was chosen because its Morse code representation (···−) is also quite
/// distinct from the other letters, maintaining the error-resistance properties of the
/// original ADFGX system.
///
/// # Grid Size
///
/// This coordinate system supports a 6×6 = 36 character grid, suitable for:
/// - Complete alphabet (26 letters)
/// - All digits (0-9)
/// - Total: 36 characters
///
/// For smaller alphabets (25 characters), see [`ADFGX`].
///
/// # See Also
///
/// * [`ADFGX`] - Original 5×5 version for 25 characters
/// * [`Numeric6`] - Numeric coordinate system for 6×6 grids
/// * [`Coordinates`] - The trait definition
///
#[derive(Debug)]
pub struct ADFGVX;

/// Marker type representing a numeric coordinate system for 5×5 Polybius square ciphers.
///
/// This marker type implements the [`Coordinates`] trait with the coordinate symbols set to
/// "12345". This provides a simple numeric alternative to the letter-based ADFGX system,
/// using consecutive digits for grid coordinates.
///
/// # Coordinate System
///
/// The Numeric5 system uses a 5×5 grid where each cell is identified by a pair of digit
/// coordinates:
/// - First coordinate (row): 1, 2, 3, 4, or 5
/// - Second coordinate (column): 1, 2, 3, 4, or 5
///
/// This creates 25 possible positions (5×5), suitable for 25-letter alphabets commonly
/// used in classical ciphers.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::Coordinates;
/// # use old_crypto_rs::helpers::Numeric5;
///
/// // Access the coordinate symbols
/// assert_eq!(Numeric5::SYMBOLS, b"12345");
/// assert_eq!(Numeric5::SYMBOLS.len(), 5);
///
/// // Example grid coordinates:
/// // Position (0,0) = "11"
/// // Position (2,3) = "34"
/// // Position (4,4) = "55"
/// ```
///
/// # Use Cases
///
/// Numeric coordinates may be preferred when:
/// - Simplicity is desired over historical accuracy
/// - The implementation needs to avoid letter confusion
/// - Working with audiences more familiar with numeric systems
/// - Educational contexts where numbers are easier to understand
///
/// # Grid Size
///
/// This coordinate system supports a 5×5 = 25 character grid, suitable for:
/// - Standard 25-letter alphabets (typically I/J combined)
/// - Any modified 25-character alphabet
///
/// For 36-character grids, see [`Numeric6`].
///
/// # See Also
///
/// * [`ADFGX`] - Letter-based coordinate system for 5×5 grids
/// * [`Numeric6`] - Numeric coordinate system for 6×6 grids
/// * [`Coordinates`] - The trait definition
///
#[derive(Debug)]
pub struct Numeric5;

/// Marker type representing a numeric coordinate system for 6×6 Polybius square ciphers.
///
/// This marker type implements the [`Coordinates`] trait with the coordinate symbols set to
/// "012345". This provides a simple numeric alternative to the letter-based ADFGVX system,
/// using consecutive digits starting from zero for grid coordinates.
///
/// # Coordinate System
///
/// The Numeric6 system uses a 6×6 grid where each cell is identified by a pair of digit
/// coordinates:
/// - First coordinate (row): 0, 1, 2, 3, 4, or 5
/// - Second coordinate (column): 0, 1, 2, 3, 4, or 5
///
/// This creates 36 possible positions (6×6), enough for the complete alphabet plus digits.
///
/// # Zero-Based Indexing
///
/// Unlike [`Numeric5`] which uses 1-based indexing (1-5), this system uses 0-based
/// indexing (0-5). This aligns with common programming conventions and array indexing,
/// potentially simplifying implementation code.
///
/// # Use Cases
///
/// Numeric coordinates may be preferred when:
/// - Zero-based indexing simplifies implementation
/// - Working with programmers familiar with 0-based arrays
/// - The historical letter-based system is not required
/// - Educational contexts demonstrating grid-based ciphers
///
/// # Grid Size
///
/// This coordinate system supports a 6×6 = 36 character grid, suitable for:
/// - Complete alphabet (26 letters)
/// - All digits (0-9)
/// - Total: 36 characters
///
/// For smaller 25-character grids, see [`Numeric5`].
///
/// # Comparison with ADFGVX
///
/// While functionally equivalent to [`ADFGVX`] for grid addressing, this system uses
/// consecutive digits (0-5) instead of the Morse-optimized letters (A, D, F, G, V, X).
/// The numeric system is more intuitive for modern users but lacks the historical
/// significance and error-resistance properties of the ADFGVX system.
///
/// # See Also
///
/// * [`ADFGVX`] - Letter-based coordinate system for 6×6 grids
/// * [`Numeric5`] - Numeric coordinate system for 5×5 grids
/// * [`Coordinates`] - The trait definition
///
#[derive(Debug)]
pub struct Numeric6;

/// Trait defining a coordinate symbol set for Polybius square-based ciphers.
///
/// This trait provides a compile-time constant array of symbols used to identify positions
/// in grid-based classical ciphers. Each position in a Polybius square is identified by a
/// pair of coordinates (row, column), where each coordinate is represented by one of the
/// symbols defined by this trait.
///
/// # Design Pattern
///
/// This trait uses zero-cost marker types to provide compile-time selection of coordinate
/// systems without runtime overhead. The coordinate symbols are specified as a compile-time
/// constant (`SYMBOLS`), allowing the compiler to optimize away any abstraction cost.
///
/// # Polybius Square Coordinates
///
/// A Polybius square is a grid-based substitution cipher where each letter is replaced by
/// its coordinates in the grid. For example, in a 5×5 grid with ADFGX coordinates:
///
/// ```text
///     A  D  F  G  X
///   ┌──┬──┬──┬──┬──┐
/// A │ P│ H│ Q│ G│ M│
///   ├──┼──┼──┼──┼──┤
/// D │ E│ A│ Y│ N│ O│
///   ├──┼──┼──┼──┼──┤
/// F │ F│ D│ X│ K│ R│
///   ├──┼──┼──┼──┼──┤
/// G │ C│ V│ S│ Z│ W│
///   ├──┼──┼──┼──┼──┤
/// X │ B│ U│ T│ I│ L│
///   └──┴──┴──┴──┴──┘
/// ```
///
/// The letter 'P' at position (0,0) would be encoded as "AA", 'E' at (1,0) as "DA", etc.
///
/// # Common Implementations
///
/// - [`ADFGX`] - Uses letters A, D, F, G, X for 5×5 grids (25 positions)
/// - [`ADFGVX`] - Uses letters A, D, F, G, V, X for 6×6 grids (36 positions)
/// - [`Numeric5`] - Uses digits 1-5 for 5×5 grids
/// - [`Numeric6`] - Uses digits 0-5 for 6×6 grids
///
/// # Examples
///
/// Using with generic code:
///
/// ```
/// use old_crypto_rs::helpers::Coordinates;
/// # use old_crypto_rs::helpers::ADFGX;
///
/// fn encode_position<C: Coordinates>(row: usize, col: usize) -> String {
///     let symbols = C::SYMBOLS;
///     format!("{}{}", symbols[row] as char, symbols[col] as char)
/// }
///
/// // Works with different coordinate systems
/// assert_eq!(encode_position::<ADFGX>(0, 0), "AA");
/// assert_eq!(encode_position::<ADFGX>(2, 3), "FG");
/// ```
///
/// Accessing symbols directly:
///
/// ```
/// use old_crypto_rs::helpers::{Coordinates, ADFGX, ADFGVX};
///
/// // 5×5 grid coordinates
/// assert_eq!(ADFGX::SYMBOLS, b"ADFGX");
/// assert_eq!(ADFGX::SYMBOLS.len(), 5);
///
/// // 6×6 grid coordinates
/// assert_eq!(ADFGVX::SYMBOLS, b"ADFGVX");
/// assert_eq!(ADFGVX::SYMBOLS.len(), 6);
/// ```
///
/// # Grid Size Requirements
///
/// The number of symbols determines the grid size:
/// - 5 symbols → 5×5 grid → 25 positions (suitable for 25-letter alphabets)
/// - 6 symbols → 6×6 grid → 36 positions (suitable for 26 letters + 10 digits)
///
/// # Use Cases
///
/// This trait is primarily used in:
/// - ADFGX/ADFGVX ciphers
/// - Polybius square ciphers
/// - Bifid cipher
/// - Trifid cipher
/// - Other grid-based substitution ciphers
///
/// # See Also
///
/// * [`ADFGX`] - 5×5 letter-based coordinate system
/// * [`ADFGVX`] - 6×6 letter-based coordinate system
/// * [`Numeric5`] - 5×5 numeric coordinate system
/// * [`Numeric6`] - 6×6 numeric coordinate system
///
pub trait Coordinates {
    /// The array of ASCII byte values representing coordinate symbols.
    ///
    /// This constant defines the symbols used to identify positions in a Polybius square.
    /// Each symbol represents one coordinate value (row or column), and the length of this
    /// array determines the grid size.
    ///
    /// # Requirements
    ///
    /// - Symbols should be ASCII characters for simplicity
    /// - Symbols must be distinct to avoid ambiguity
    /// - The number of symbols determines grid dimensions (5 for 5×5, 6 for 6×6, etc.)
    ///
    const SYMBOLS: &'static [u8];
}

/// Implementation of the `Coordinates` trait for the ADFGX coordinate system.
///
/// This implementation defines the five coordinate symbols (A, D, F, G, X) used in the
/// ADFGX cipher's 5×5 Polybius square. These specific letters were historically chosen
/// for their distinct Morse code representations to minimize radio transmission errors.
///
/// # Grid Structure
///
/// With these 5 symbols, this creates a coordinate system where:
/// - Row coordinates: A (0), D (1), F (2), G (3), X (4)
/// - Column coordinates: A (0), D (1), F (2), G (3), X (4)
/// - Total positions: 5 × 5 = 25
///
/// # See Also
///
/// * [`ADFGX`] - The marker type documentation
/// * [`Coordinates`] - The trait definition
///
impl Coordinates for ADFGX {
    const SYMBOLS: &'static [u8] = b"ADFGX";
}

/// Implementation of the `Coordinates` trait for the ADFGVX coordinate system.
///
/// This implementation defines the six coordinate symbols (A, D, F, G, V, X) used in the
/// ADFGVX cipher's 6×6 Polybius square. This extends the original ADFGX system by adding
/// 'V', allowing the grid to accommodate both the complete alphabet and numeric digits.
///
/// # Grid Structure
///
/// With these 6 symbols, this creates a coordinate system where:
/// - Row coordinates: A (0), D (1), F (2), G (3), V (4), X (5)
/// - Column coordinates: A (0), D (1), F (2), G (3), V (4), X (5)
/// - Total positions: 6 × 6 = 36
///
/// # See Also
///
/// * [`ADFGVX`] - The marker type documentation
/// * [`Coordinates`] - The trait definition
///
impl Coordinates for ADFGVX {
    const SYMBOLS: &'static [u8] = b"ADFGVX";
}

/// Implementation of the `Coordinates` trait for the Numeric5 coordinate system.
///
/// This implementation defines five numeric coordinate symbols (1, 2, 3, 4, 5) for use
/// in 5×5 Polybius squares. This provides a simple, intuitive alternative to letter-based
/// coordinate systems using consecutive digits starting from 1.
///
/// # Grid Structure
///
/// With these 5 symbols, this creates a coordinate system where:
/// - Row coordinates: 1 (0), 2 (1), 3 (2), 4 (3), 5 (4)
/// - Column coordinates: 1 (0), 2 (1), 3 (2), 4 (3), 5 (4)
/// - Total positions: 5 × 5 = 25
///
/// # See Also
///
/// * [`Numeric5`] - The marker type documentation
/// * [`Coordinates`] - The trait definition
///
impl Coordinates for Numeric5 {
    const SYMBOLS: &'static [u8] = b"12345";
}

/// Implementation of the `Coordinates` trait for the Numeric6 coordinate system.
///
/// This implementation defines six numeric coordinate symbols (0, 1, 2, 3, 4, 5) for use
/// in 6×6 Polybius squares. This provides a simple, zero-indexed alternative to letter-based
/// coordinate systems, aligning with common programming array indexing conventions.
///
/// # Grid Structure
///
/// With these 6 symbols, this creates a coordinate system where:
/// - Row coordinates: 0 (0), 1 (1), 2 (2), 3 (3), 4 (4), 5 (5)
/// - Column coordinates: 0 (0), 1 (1), 2 (2), 3 (3), 4 (4), 5 (5)
/// - Total positions: 6 × 6 = 36
///
/// # See Also
///
/// * [`Numeric6`] - The marker type documentation
/// * [`Coordinates`] - The trait definition
///
impl Coordinates for Numeric6 {
    const SYMBOLS: &'static [u8] = b"012345";
}

