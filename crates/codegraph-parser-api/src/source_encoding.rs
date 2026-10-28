// Copyright 2024-2026 Andrey Vasilevsky <anvanster@gmail.com>
// SPDX-License-Identifier: Apache-2.0

//! Conservative decoding for source files read by parsers.
//!
//! UTF-8 is preferred. The only fallback is unambiguous ISO-8859-1 text:
//! C1 controls, NUL, and other non-whitespace ASCII controls are rejected so
//! unknown encodings and binary data produce an explicit error.

use std::io;

/// Decode UTF-8 source, or printable ISO-8859-1 text when UTF-8 is invalid.
///
/// ISO-8859-1 conversion is in-memory only. ASCII newline bytes are preserved,
/// so parser row-based source locations continue to refer to the original
/// file. The current CodeGraph parser interfaces expose line locations, not
/// byte offsets or columns.
pub fn decode_source_bytes(bytes: &[u8]) -> io::Result<String> {
    if bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported source encoding: NUL byte in source text",
        ));
    }
    if let Ok(source) = std::str::from_utf8(bytes) {
        return Ok(source.to_owned());
    }

    let is_unambiguous_latin1 = bytes.iter().all(|byte| match byte {
        b'\t' | b'\n' | 0x0c | b'\r' => true,
        0x00..=0x08 | 0x0b | 0x0e..=0x1f | 0x7f | 0x80..=0x9f => false,
        _ => true,
    });
    if !is_unambiguous_latin1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported source encoding: expected UTF-8 or unambiguous ISO-8859-1 text",
        ));
    }

    Ok(bytes.iter().map(|byte| char::from(*byte)).collect())
}

#[cfg(test)]
mod tests {
    use super::decode_source_bytes;

    #[test]
    fn decodes_latin1_without_changing_line_breaks() {
        let bytes = b"/* caf\xe9 */\nint f();\n";
        let decoded = decode_source_bytes(bytes).unwrap();
        assert_eq!(decoded, "/* café */\nint f();\n");
        assert_eq!(decoded.bytes().filter(|byte| *byte == b'\n').count(), 2);
        assert_eq!(bytes, b"/* caf\xe9 */\nint f();\n");
    }

    #[test]
    fn preserves_valid_utf8_and_rejects_ambiguous_or_binary_bytes() {
        assert_eq!(decode_source_bytes("café\n".as_bytes()).unwrap(), "café\n");
        assert!(decode_source_bytes(b"text\x93\n").is_err());
        assert!(decode_source_bytes(b"text\0\n").is_err());
    }
}
