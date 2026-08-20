/// Percent-encode a string for safe inclusion in URLs.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push('%');
                push_hex_byte(&mut out, b);
            }
        }
    }
    out
}

#[inline]
fn push_hex_byte(s: &mut String, b: u8) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    s.push(HEX[(b >> 4) as usize] as char);
    s.push(HEX[(b & 0xF) as usize] as char);
}

/// Format a 16-byte UUID into the standard format with dashes.
pub fn format_uuid(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    const HEX: &[u8] = b"0123456789abcdef";
    for (i, &byte) in b.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            s.push('-');
        }
        s.push(HEX[(byte >> 4) as usize] as char);
        s.push(HEX[(byte & 0xF) as usize] as char);
    }
    s
}
