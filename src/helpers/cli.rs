//! Command-line input ingestion helpers.
//!
//! Provides standardized utilities for reading input text from command-line arguments
//! or standard input across cipher CLI tools.

use std::io::{self, Read};

/// Read input text from a slice of positional argument words, or from standard input if empty.
///
/// When `words` is not empty, the words are joined with a single space.
/// When `words` is empty, standard input is read to completion.
///
/// # Errors
/// Returns an [`io::Error`] if reading from standard input fails.
pub fn read_input<T: AsRef<str>>(words: &[T]) -> io::Result<String> {
    read_input_from_reader(io::stdin(), words)
}

/// Read input text from a reader or positional argument words.
///
/// When `words` is not empty, the words are joined with a single space.
/// When `words` is empty, the reader is read to completion.
///
/// # Errors
/// Returns an [`io::Error`] if reading from `reader` fails.
pub fn read_input_from_reader<R: Read, T: AsRef<str>>(
    mut reader: R,
    words: &[T],
) -> io::Result<String> {
    if words.is_empty() {
        let mut input = String::new();
        reader.read_to_string(&mut input)?;
        Ok(input)
    } else {
        let words: Vec<&str> = words.iter().map(AsRef::as_ref).collect();
        Ok(words.join(" "))
    }
}

/// Read input text from an optional argument string, or from standard input if `None`.
///
/// If `text` is `Some`, the string value is returned.
/// If `text` is `None`, standard input is read to completion.
///
/// # Errors
/// Returns an [`io::Error`] if reading from standard input fails.
pub fn read_input_optional(text: Option<impl Into<String>>) -> io::Result<String> {
    read_input_optional_from_reader(io::stdin(), text)
}

/// Read input text from a reader or an optional argument string.
///
/// If `text` is `Some`, the string value is returned.
/// If `text` is `None`, the reader is read to completion.
///
/// # Errors
/// Returns an [`io::Error`] if reading from `reader` fails.
pub fn read_input_optional_from_reader<R: Read>(
    mut reader: R,
    text: Option<impl Into<String>>,
) -> io::Result<String> {
    match text {
        Some(text) => Ok(text.into()),
        None => {
            let mut input = String::new();
            reader.read_to_string(&mut input)?;
            Ok(input)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_input_from_words() {
        let words = vec!["HELLO".to_string(), "WORLD".to_string()];
        let cursor = io::Cursor::new(b"UNUSED STDIN");
        let result = read_input_from_reader(cursor, &words).unwrap();
        assert_eq!(result, "HELLO WORLD");
    }

    #[test]
    fn test_read_input_from_reader_when_words_empty() {
        let words: Vec<String> = vec![];
        let cursor = io::Cursor::new(b"MESSAGE FROM STDIN\n");
        let result = read_input_from_reader(cursor, &words).unwrap();
        assert_eq!(result, "MESSAGE FROM STDIN\n");
    }

    #[test]
    fn test_read_input_optional_some() {
        let cursor = io::Cursor::new(b"UNUSED STDIN");
        let result = read_input_optional_from_reader(cursor, Some("DIRECT INPUT")).unwrap();
        assert_eq!(result, "DIRECT INPUT");
    }

    #[test]
    fn test_read_input_optional_none() {
        let cursor = io::Cursor::new(b"STDIN OPTIONAL INPUT");
        let result = read_input_optional_from_reader(cursor, None::<String>).unwrap();
        assert_eq!(result, "STDIN OPTIONAL INPUT");
    }
}
