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
    pub fn is_empty(&self) -> bool {
        self.len == 0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enc_entry_new() {
        let entry = EncEntry::new(2, [b'1', b'5']);
        assert_eq!(entry.len(), 2);
        assert_eq!(entry.bytes(0), b'1');
        assert_eq!(entry.bytes(1), b'5');
    }

    #[test]
    fn test_enc_entry_len() {
        let entry1 = EncEntry::new(1, [b'3', 0]);
        assert_eq!(entry1.len(), 1);

        let entry2 = EncEntry::new(2, [b'4', b'7']);
        assert_eq!(entry2.len(), 2);

        let entry0 = EncEntry::new(0, [0, 0]);
        assert_eq!(entry0.len(), 0);
    }

    #[test]
    fn test_enc_entry_bytes() {
        let entry = EncEntry::new(2, [b'9', b'2']);
        assert_eq!(entry.bytes(0), b'9');
        assert_eq!(entry.bytes(1), b'2');
    }

    #[test]
    fn test_enc_entry_default() {
        let entry = EncEntry::default();
        assert_eq!(entry.len(), 0);
        assert_eq!(entry.bytes(0), 0);
        assert_eq!(entry.bytes(1), 0);
    }

    #[test]
    fn test_enc_entry_debug_full() {
        let entry = EncEntry::new(2, [b'4', b'8']);
        assert_eq!(format!("{:?}", entry), "48");
    }

    #[test]
    fn test_enc_entry_debug_single() {
        let entry = EncEntry::new(1, [b'7', 0]);
        assert_eq!(format!("{:?}", entry), "7.");
    }

    #[test]
    fn test_enc_entry_debug_empty() {
        let entry = EncEntry::new(0, [0, 0]);
        assert_eq!(format!("{:?}", entry), "..");
    }

    #[test]
    fn test_enc_entry_debug_partial() {
        let entry = EncEntry::new(1, [0, b'3']);
        assert_eq!(format!("{:?}", entry), ".3");
    }
}

