//! Common types for the project.
//! 

/// Compact encoding entry for a single plaintext byte.
///
/// `len` is 0 for unmapped bytes, or 1/2 for the number of output digits.
/// `bytes` stores the digit bytes for the code.
#[derive(Copy, Clone, Default)]
pub struct EncEntry {
    /// Number of digits used for encoding (1 or 2).
    len: u8,
    /// The digit bytes (ASCII characters '0'-'9').
    bytes: [u8; 2],
}

impl EncEntry {
    #[inline]
    pub fn new(len: u8, bytes: [u8; 2]) -> Self {
        Self { len, bytes }
    }

    #[inline]
    pub fn len(&self) -> u8 {
        self.len
    }

    #[inline]
    pub fn bytes(&self, idx: u8) -> u8 {
        self.bytes[idx as usize]
    }
}

impl std::fmt::Debug for EncEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let b0 = if self.bytes[0] == 0 {
            b'.'
        } else {
            self.bytes[0]
        };
        let b1 = if self.bytes[1] == 0 {
            b'.'
        } else {
            self.bytes[1]
        };
        let code = [b0, b1];
        f.write_str(std::str::from_utf8(&code).unwrap_or(".."))
    }
}
