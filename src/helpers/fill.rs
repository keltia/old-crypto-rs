
/// Trait defining a filler character policy for handling duplicate letters in digrams.
///
/// This trait is used to specify which character should be inserted between consecutive
/// identical letters in classical ciphers that process text in pairs (digrams), such as
/// the Playfair cipher. When two identical letters would appear in the same digram,
/// a filler character must be inserted to separate them.
///
/// # Design Pattern
///
/// This trait uses zero-cost marker types to provide compile-time selection of filler
/// characters without runtime overhead. The filler character is specified as a compile-time
/// constant (`FILL`), allowing the compiler to optimize away any abstraction cost.
///
/// # Common Implementations
///
/// - [`FillX`] - Uses 'X' as the filler character (most common in English)
/// - [`FillQ`] - Uses 'Q' as the filler character (alternative choice)
///
/// # Examples
///
/// Using with generic code:
///
/// ```
/// use old_crypto_rs::helpers::FillWith;
/// # use old_crypto_rs::helpers::FillX;
///
/// fn insert_filler<F: FillWith>(text: &str) -> String {
///     // Use F::FILL to access the filler character
///     let filler = F::FILL as char;
///     // ... implementation ...
/// # text.to_string()
/// }
///
/// // Works with different filler policies
/// let result = insert_filler::<FillX>("HELLO");
/// ```
///
/// # Use Cases
///
/// This trait is primarily used in:
/// - Playfair cipher encryption/decryption
/// - Two-square cipher
/// - Four-square cipher
/// - Other bi-grammatic classical ciphers
///
/// # See Also
///
/// * [`FillX`] - Standard 'X' filler implementation
/// * [`FillQ`] - Alternative 'Q' filler implementation
/// * [`fix_double_aligned`] - Function that uses filler characters
///
pub trait FillWith {
    /// The ASCII byte value of the filler character.
    ///
    /// This constant defines which character will be inserted between duplicate
    /// letters in a digram. It should typically be a letter that appears less
    /// frequently in the target language to minimize confusion.
    ///
    /// # Examples
    ///
    /// ```
    /// use old_crypto_rs::helpers::{FillWith, FillX, FillQ, NoFill};
    ///
    /// assert_eq!(FillX::FILL, b'X');
    /// assert_eq!(FillQ::FILL, b'Q');
    /// assert_eq!(NoFill::FILL, b'-');
    /// ```
    const FILL: u8;
}

/// Marker type representing the 'X' filler character policy for digram handling.
///
/// This marker type implements the [`FillWith`] trait with the filler character set to 'X'.
/// It's the most commonly used filler in English-language classical ciphers because 'X'
/// appears relatively infrequently in normal English text, making it less likely to cause
/// confusion during decryption.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{FillWith, FillX};
///
/// // Access the filler character
/// assert_eq!(FillX::FILL, b'X');
/// assert_eq!(FillX::FILL as char, 'X');
/// ```
///
/// # Usage in Ciphers
///
/// ```
/// use old_crypto_rs::helpers::{FillWith, FillX};
///
/// fn process_digrams<F: FillWith>(text: &str) -> String {
///     // When we encounter duplicate letters like "LL",
///     // we insert F::FILL between them: "LXL"
///     let filler = F::FILL as char;
///     // ... cipher logic ...
/// # text.to_string()
/// }
///
/// // Using the 'X' filler policy
/// let result = process_digrams::<FillX>("HELLO");
/// // Would transform "LL" to "LXL"
/// ```
///
/// # Historical Context
///
/// The use of 'X' as a filler character dates back to the original Playfair cipher
/// invented by Charles Wheatstone in 1854. The choice of 'X' was practical because:
/// - It's relatively uncommon in English (frequency ~0.15%)
/// - It's visually distinct from other letters
/// - It doesn't typically appear doubled in English words
///
/// # See Also
///
/// * [`FillQ`] - Alternative filler using 'Q'
/// * [`FillWith`] - The trait definition
/// * [`fix_double_aligned`] - Function that handles duplicate letters
///
pub struct FillX;

/// Marker type representing the 'Q' filler character policy for digram handling.
///
/// This marker type implements the [`FillWith`] trait with the filler character set to 'Q'.
/// It's an alternative to the more common 'X' filler and may be preferred in certain
/// contexts where 'Q' appears less frequently or when 'X' itself needs to be preserved
/// in the plaintext.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{FillWith, FillQ};
///
/// // Access the filler character
/// assert_eq!(FillQ::FILL, b'Q');
/// assert_eq!(FillQ::FILL as char, 'Q');
/// ```
///
/// # Usage in Ciphers
///
/// ```
/// use old_crypto_rs::helpers::{FillWith, FillQ};
///
/// fn process_digrams<F: FillWith>(text: &str) -> String {
///     // When we encounter duplicate letters like "LL",
///     // we insert F::FILL between them: "LQL"
///     let filler = F::FILL as char;
///     // ... cipher logic ...
/// # text.to_string()
/// }
///
/// // Using the 'Q' filler policy
/// let result = process_digrams::<FillQ>("HELLO");
/// // Would transform "LL" to "LQL"
/// ```
///
/// # When to Use 'Q' Instead of 'X'
///
/// Consider using `FillQ` when:
/// - Your plaintext contains many 'X' characters that must be preserved
/// - You're working with languages where 'Q' is extremely rare
/// - The message context makes 'Q' less ambiguous than 'X'
/// - You need to distinguish between different encryption passes
///
/// Note that in English, 'Q' is actually rarer than 'X' (frequency ~0.095% vs ~0.15%),
/// making it a viable alternative in many cases.
///
/// # See Also
///
/// * [`FillX`] - Standard filler using 'X'
/// * [`FillWith`] - The trait definition
/// * [`fix_double_aligned`] - Function that handles duplicate letters
///
pub struct FillQ;

/// Marker type representing the NO filler character policy for digram handling.
///
/// This marker type implements the [`FillWith`] trait with the filler character set to '-'.
///
/// # See Also
///
/// * [`FillQ`] - Standard filler using 'Q'
/// * [`FillX`] - Standard filler using 'X'
/// * [`FillWith`] - The trait definition
/// * [`fix_double_aligned`] - Function that handles duplicate letters
///
pub struct NoFill;

/// Implementation of the `FillWith` trait for the 'X' filler character policy.
///
/// This implementation sets the filler character to 'X' (ASCII byte value 88),
/// making it the default choice for handling duplicate letters in digrams.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{FillWith, FillX};
///
/// // Access the filler character at compile time
/// const FILLER: u8 = FillX::FILL;
/// assert_eq!(FILLER, b'X');
///
/// // Use in generic functions
/// fn get_filler<F: FillWith>() -> char {
///     F::FILL as char
/// }
/// assert_eq!(get_filler::<FillX>(), 'X');
/// ```
///
/// # See Also
///
/// * [`FillX`] - The marker type documentation
/// * [`FillWith`] - The trait definition
///
impl FillWith for FillX {
    const FILL: u8 = b'X';
}

/// Implementation of the `FillWith` trait for the 'Q' filler character policy.
///
/// This implementation sets the filler character to 'Q' (ASCII byte value 81),
/// providing an alternative to the more common 'X' filler for handling duplicate
/// letters in digrams.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{FillWith, FillQ};
///
/// // Access the filler character at compile time
/// const FILLER: u8 = FillQ::FILL;
/// assert_eq!(FILLER, b'Q');
///
/// // Use in generic functions
/// fn get_filler<F: FillWith>() -> char {
///     F::FILL as char
/// }
/// assert_eq!(get_filler::<FillQ>(), 'Q');
/// ```
///
/// # See Also
///
/// * [`FillQ`] - The marker type documentation
/// * [`FillWith`] - The trait definition
///
impl FillWith for FillQ {
    const FILL: u8 = b'Q';
}

/// Implementation of the `FillWith` trait for the '-' filler character policy, aka No filling
///
/// This implementation sets the filler character to '-' to signify that there will be no filler
/// for duplicated letters in digrams.  These will be encrypted and decrypted as they are.
///
/// This variation is mentioned in [KAHN 96] when describing the messages exchanged when President-to-be
/// John F. Kennedy's torpedo boat got destroyed by Japânese troops, and he and his crew had to hide
/// for days before being recovered.
///
/// # Examples
///
/// ```
/// use old_crypto_rs::helpers::{FillWith, NoFill};
///
/// // Access the filler character at compile time
/// const FILLER: u8 = NoFill::FILL;
/// assert_eq!(FILLER, b'-');
///
/// // Use in generic functions
/// fn get_filler<F: FillWith>() -> char {
///     F::FILL as char
/// }
/// assert_eq!(get_filler::<NoFill>(), '-');
/// ```
///
/// # See Also
///
/// * [`FillQ`] - The marker type documentation
/// * [`FillX`] - The marker type documentation
/// * [`FillWith`] - The trait definition
///
impl FillWith for NoFill {
    const FILL: u8 = b'-';
}
